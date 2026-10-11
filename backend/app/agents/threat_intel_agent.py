import os
import json
import time
import logging
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from app.agents.agent_schemas import (
    DetectionOutput,
    ThreatIntelOutput,
    MitreAttackItem,
    CveItem,
    CisaAdvisoryItem
)
from app.rag.retriever import get_retriever
from app.rag.vector_store import get_vector_store
from app.rag.guardrails import validate_and_sanitize_threat_intel
from app.llm.client import get_llm_client
from app.llm.prompts.threat_intel_prompts import (
    QUERY_EXPANSION_SYSTEM_PROMPT,
    THREAT_INTEL_SYNTHESIS_SYSTEM_PROMPT,
    format_query_expansion_prompt,
    format_threat_intel_synthesis_prompt
)

logger = logging.getLogger(__name__)


class LLMSynthesizedIntel(BaseModel):
    selected_mitre_ids: List[str] = Field(default_factory=list)
    selected_cve_ids: List[str] = Field(default_factory=list)
    selected_cisa_ids: List[str] = Field(default_factory=list)
    iot_threat_context: str


class ThreatIntelAgent:
    """
    Threat Intelligence Agent implementing real RAG over authentic cybersecurity knowledge bases:
    - MITRE ATT&CK (Enterprise & ICS)
    - NVD CVE Database (IoT vulnerabilities)
    - CISA Known Exploited Vulnerabilities (KEV) & Advisories
    - NIST SP 800-213 & OWASP IoT Top 10 Guidelines

    Enforces strict anti-hallucination guardrails and graceful deterministic fallback.
    """

    def __init__(self):
        self.retriever = get_retriever()
        self.vector_store = get_vector_store()

    def retrieve_intelligence(self, detection: DetectionOutput) -> ThreatIntelOutput:
        from app.core.config import load_platform_settings
        platform_cfg = load_platform_settings()
        ti_settings = platform_cfg.get("threat_intelligence", {})
        llm_cfg = platform_cfg.get("llm", {})
        rag_cfg = platform_cfg.get("rag", {})

        enable_mitre = ti_settings.get("enable_mitre", True)
        enable_cve = ti_settings.get("enable_nvd_cve", True)
        enable_cisa = ti_settings.get("enable_cisa", True)
        rag_top_k = ti_settings.get("rag_top_k", 3)
        min_relevance = float(rag_cfg.get("min_relevance_score", 0.35))

        attack = detection.attack_type.strip()
        attack_lower = attack.lower()
        is_benign = attack_lower in ["benign", "normal"]

        # -------------------------------------------------------------
        # 1. Benign-Traffic Shortcut (No RAG needed for Benign)
        # -------------------------------------------------------------
        if is_benign:
            sources = [
                "https://csrc.nist.gov/publications/detail/sp/800-213/final",
                "https://attack.mitre.org"
            ]
            context = (
                "Traffic exhibits normal baseline behavioral patterns consistent with authorized IoT telemetry. "
                "No active MITRE ATT&CK exploitation techniques or CISA KEV alerts correlate with this flow. "
                "Adherence to NIST SP 800-213 IoT device cybersecurity baseline monitoring is recommended."
            )
            return ThreatIntelOutput(
                mitre_attack=[],
                cve_list=[],
                cisa_advisories=[],
                iot_threat_context=context,
                retrieval_confidence=1.0,
                sources=sources,
                generated_by="rule_based"
            )

        # -------------------------------------------------------------
        # 2. Query Construction & LLM Query Expansion
        # -------------------------------------------------------------
        net_ctx = detection.network_context
        top_feats = [f.model_dump() for f in detection.top_contributing_features]
        base_query = f"{attack} port {net_ctx.destination_port} {net_ctx.protocol}"

        expanded_queries = [base_query]
        llm_enabled = bool(llm_cfg.get("enabled", True))
        llm_client = get_llm_client()

        if llm_enabled and llm_cfg.get("agent_toggles", {}).get("threat_intel", True) and llm_client.is_available():
            try:
                prompt = format_query_expansion_prompt(
                    attack_type=attack,
                    top_features=top_feats,
                    network_context=net_ctx.model_dump()
                )
                raw_exp = llm_client.generate(QUERY_EXPANSION_SYSTEM_PROMPT, prompt, agent_name="Threat Intel Agent")
                # Parse JSON queries
                cleaned = raw_exp.strip()
                if cleaned.startswith("```"):
                    import re
                    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
                    cleaned = re.sub(r"\s*```$", "", cleaned)
                data = json.loads(cleaned)
                for q in data.get("queries", []):
                    if isinstance(q, str) and q.strip():
                        expanded_queries.append(q.strip())
            except Exception as qe:
                logger.debug(f"Query expansion fallback to rule queries: {qe}")
                # Rule-based expanded queries
                expanded_queries.extend([
                    f"{attack} IoT vulnerability {net_ctx.protocol}",
                    f"{attack} botnet command injection router"
                ])
        else:
            expanded_queries.extend([
                f"{attack} IoT vulnerability {net_ctx.protocol}",
                f"{attack} botnet router"
            ])

        # -------------------------------------------------------------
        # 3. Hybrid RAG Retrieval (Dense + BM25 + Exact ID + RRF)
        # -------------------------------------------------------------
        retrieved_doc_map = {}
        for query_str in expanded_queries[:3]:
            results = self.retriever.retrieve(
                query=query_str,
                top_k=rag_top_k * 2,
                min_relevance=min_relevance
            )
            for res in results:
                doc = res.document
                # Store highest score
                if doc.id not in retrieved_doc_map or res.score > retrieved_doc_map[doc.id][1]:
                    retrieved_doc_map[doc.id] = (doc, res.score)

        # Sort combined results by score
        sorted_retrieved = sorted(retrieved_doc_map.values(), key=lambda x: x[1], reverse=True)
        retrieved_docs = [item[0] for item in sorted_retrieved]

        # Filter by doc_type toggles
        filtered_mitre = []
        filtered_cve = []
        filtered_cisa = []

        for doc, score in sorted_retrieved:
            dt = doc.metadata.get("doc_type")
            if dt == "mitre_attack" and enable_mitre and len(filtered_mitre) < rag_top_k:
                filtered_mitre.append(MitreAttackItem(
                    id=doc.id,
                    name=doc.metadata.get("name", doc.id),
                    tactic=doc.metadata.get("tactic", "Impact"),
                    description=doc.content[:300],
                    url=doc.metadata.get("url", f"https://attack.mitre.org/techniques/{doc.id}/"),
                    similarity_score=score
                ))
            elif dt == "cve" and enable_cve and len(filtered_cve) < rag_top_k:
                filtered_cve.append(CveItem(
                    cve_id=doc.id,
                    affected_systems=doc.metadata.get("affected", "IoT Network Devices"),
                    cvss_score=float(doc.metadata.get("cvss", 7.5)),
                    severity=doc.metadata.get("severity", "HIGH"),
                    description=doc.content[:300],
                    url=doc.metadata.get("url", f"https://nvd.nist.gov/vuln/detail/{doc.id}"),
                    similarity_score=score
                ))
            elif dt == "cisa_advisory" and enable_cisa and len(filtered_cisa) < rag_top_k:
                filtered_cisa.append(CisaAdvisoryItem(
                    id=doc.id,
                    title=doc.metadata.get("title", doc.id),
                    release_date=doc.metadata.get("date", "Recent"),
                    summary=doc.content[:300],
                    url=doc.metadata.get("url", "https://www.cisa.gov"),
                    similarity_score=score
                ))

        # -------------------------------------------------------------
        # 4. Grounded Threat Context Synthesis & Guardrails
        # -------------------------------------------------------------
        used_llm = False
        llm_model_name = None
        latency_ms = None
        synthesized_context = ""

        if llm_enabled and llm_cfg.get("agent_toggles", {}).get("threat_intel", True) and llm_client.is_available() and retrieved_docs:
            t0 = time.time()
            try:
                retrieved_payload = [
                    {
                        "id": d.id,
                        "source": d.metadata.get("source", "CTI"),
                        "title": d.metadata.get("name") or d.metadata.get("title") or d.id,
                        "content": d.content,
                        "url": d.metadata.get("url", "")
                    }
                    for d in retrieved_docs[:8]
                ]

                synth_prompt = format_threat_intel_synthesis_prompt(
                    attack_type=attack,
                    network_context=net_ctx.model_dump(),
                    retrieved_docs=retrieved_payload
                )

                structured_res = llm_client.generate_structured(
                    system=THREAT_INTEL_SYNTHESIS_SYSTEM_PROMPT,
                    prompt=synth_prompt,
                    schema=LLMSynthesizedIntel,
                    agent_name="Threat Intel Agent"
                )

                latency_ms = round((time.time() - t0) * 1000, 2)
                used_llm = True
                llm_model_name = llm_client.model
                synthesized_context = structured_res.iot_threat_context

            except Exception as se:
                logger.warning(f"LLM Threat Intel synthesis failed (using deterministic fallback): {se}")
                used_llm = False

        # Deterministic context fallback if LLM was not used or failed
        if not used_llm or not synthesized_context:
            context_parts = []
            if filtered_mitre:
                names = ", ".join(f"{m.id} ({m.name})" for m in filtered_mitre)
                context_parts.append(f"Associated with MITRE ATT&CK technique(s): {names}.")
            if filtered_cve:
                cves = ", ".join(f"{c.cve_id} (CVSS {c.cvss_score})" for c in filtered_cve)
                context_parts.append(f"Correlates with verified IoT vulnerabilities: {cves}.")
            if filtered_cisa:
                cisa_names = ", ".join(f"{ci.id}" for ci in filtered_cisa)
                context_parts.append(f"Referenced in CISA advisories: {cisa_names}.")

            if not context_parts:
                context_parts.append(
                    f"Signature matches '{attack}' behaviors. No high-confidence verified CVE or CISA KEV alert correlates with this flow."
                )

            synthesized_context = " ".join(context_parts)

        # -------------------------------------------------------------
        # 5. Programmatic Anti-Hallucination Guardrail Execution
        # -------------------------------------------------------------
        candidate_output = ThreatIntelOutput(
            mitre_attack=filtered_mitre,
            cve_list=filtered_cve,
            cisa_advisories=filtered_cisa,
            iot_threat_context=synthesized_context,
            retrieval_confidence=0.85,
            sources=[],
            generated_by="llm" if used_llm else "rule_based_fallback",
            llm_model=llm_model_name,
            latency_ms=latency_ms
        )

        final_output = validate_and_sanitize_threat_intel(
            raw_output=candidate_output,
            retrieved_docs=retrieved_docs,
            vector_store=self.vector_store
        )

        return final_output


threat_intel_agent = ThreatIntelAgent()
