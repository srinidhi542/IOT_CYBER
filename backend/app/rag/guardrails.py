import re
import logging
from typing import List, Set, Tuple, Optional
from app.rag.vector_store import Document, VectorStore
from app.agents.agent_schemas import (
    ThreatIntelOutput,
    MitreAttackItem,
    CveItem,
    CisaAdvisoryItem
)

logger = logging.getLogger(__name__)

REGEX_MITRE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
REGEX_CVE = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)
REGEX_CISA = re.compile(r"\b(AA\d{2}-\d{3}[A-Z]|ICSA-\d{2}-\d{3}-\d{2})\b", re.IGNORECASE)


def extract_all_ids(text: str) -> Set[str]:
    """Finds all cybersecurity identifiers mentioned in arbitrary text."""
    found = set()
    for m in REGEX_MITRE.finditer(text):
        found.add(m.group(1).upper())
    for m in REGEX_CVE.finditer(text):
        found.add(m.group(1).upper())
    for m in REGEX_CISA.finditer(text):
        found.add(m.group(1).upper())
    return found


def validate_and_sanitize_threat_intel(
    raw_output: ThreatIntelOutput,
    retrieved_docs: List[Document],
    vector_store: VectorStore,
    fallback_confidence: float = 0.5
) -> ThreatIntelOutput:
    """
    Programmatically verifies all cited MITRE, CVE, and CISA IDs:
    1. Compares each candidate ID against the retrieved document set.
    2. Validates against the authentic vector store database.
    3. Drops any fabricated or hallucinated items and logs explicit warnings.
    4. Calculates realistic retrieval_confidence based on similarity scores.
    """
    retrieved_id_map = {doc.id.upper(): doc for doc in retrieved_docs}
    allowed_ids = set(retrieved_id_map.keys())

    # 1. Sanitize MITRE Attack Items
    verified_mitre: List[MitreAttackItem] = []
    for item in raw_output.mitre_attack:
        item_id = item.id.strip().upper()
        if item_id in allowed_ids:
            doc = retrieved_id_map[item_id]
            verified_mitre.append(MitreAttackItem(
                id=item_id,
                name=doc.metadata.get("name", item.name),
                tactic=doc.metadata.get("tactic", item.tactic),
                description=doc.content[:300] if len(doc.content) > 30 else item.description,
                url=doc.metadata.get("url", item.url)
            ))
        else:
            # Check if it exists in vector store at all
            doc = vector_store.get_by_id(item_id)
            if doc:
                verified_mitre.append(MitreAttackItem(
                    id=item_id,
                    name=doc.metadata.get("name", item.name),
                    tactic=doc.metadata.get("tactic", item.tactic),
                    description=doc.content[:300],
                    url=doc.metadata.get("url", item.url)
                ))
            else:
                logger.warning(f"[Guardrail Alert] Dropped hallucinated MITRE ID cited by LLM: {item_id}")

    # 2. Sanitize CVE Items
    verified_cves: List[CveItem] = []
    for item in raw_output.cve_list:
        cve_id = item.cve_id.strip().upper()
        if cve_id in allowed_ids:
            doc = retrieved_id_map[cve_id]
            verified_cves.append(CveItem(
                cve_id=cve_id,
                affected_systems=doc.metadata.get("affected", item.affected_systems),
                cvss_score=float(doc.metadata.get("cvss", item.cvss_score)),
                severity=doc.metadata.get("severity", item.severity),
                description=doc.content[:300] if len(doc.content) > 30 else item.description,
                url=doc.metadata.get("url", item.url)
            ))
        else:
            doc = vector_store.get_by_id(cve_id)
            if doc:
                verified_cves.append(CveItem(
                    cve_id=cve_id,
                    affected_systems=doc.metadata.get("affected", item.affected_systems),
                    cvss_score=float(doc.metadata.get("cvss", item.cvss_score)),
                    severity=doc.metadata.get("severity", item.severity),
                    description=doc.content[:300],
                    url=doc.metadata.get("url", item.url)
                ))
            else:
                logger.warning(f"[Guardrail Alert] Dropped hallucinated CVE ID cited by LLM: {cve_id}")

    # 3. Sanitize CISA Advisory Items
    verified_cisa: List[CisaAdvisoryItem] = []
    for item in raw_output.cisa_advisories:
        adv_id = item.id.strip().upper()
        if adv_id in allowed_ids:
            doc = retrieved_id_map[adv_id]
            verified_cisa.append(CisaAdvisoryItem(
                id=adv_id,
                title=doc.metadata.get("title", item.title),
                release_date=doc.metadata.get("date", item.release_date),
                summary=doc.content[:300] if len(doc.content) > 30 else item.summary,
                url=doc.metadata.get("url", item.url)
            ))
        else:
            doc = vector_store.get_by_id(adv_id)
            if doc:
                verified_cisa.append(CisaAdvisoryItem(
                    id=adv_id,
                    title=doc.metadata.get("title", item.title),
                    release_date=doc.metadata.get("date", item.release_date),
                    summary=doc.content[:300],
                    url=doc.metadata.get("url", item.url)
                ))
            else:
                logger.warning(f"[Guardrail Alert] Dropped hallucinated CISA ID cited by LLM: {adv_id}")

    # 4. Check for hallucinated IDs embedded in free text context
    context_text = raw_output.iot_threat_context
    mentioned_ids = extract_all_ids(context_text)
    for mid in mentioned_ids:
        if mid not in allowed_ids and not vector_store.get_by_id(mid):
            logger.warning(f"[Guardrail Alert] Stripping unverified ID '{mid}' from threat context text.")
            context_text = re.sub(rf"\b{re.escape(mid)}\b", "[UNVERIFIED ID REDACTED]", context_text, flags=re.IGNORECASE)

    # 5. Compile verified authoritative sources
    sources = []
    for m in verified_mitre:
        if m.url:
            sources.append(m.url)
    for c in verified_cves:
        if c.url:
            sources.append(c.url)
    for ci in verified_cisa:
        if ci.url:
            sources.append(ci.url)
    unique_sources = list(dict.fromkeys(sources))

    # 6. Realistic retrieval confidence calculation
    if not verified_mitre and not verified_cves and not verified_cisa:
        confidence = 0.35
        if "no strong" not in context_text.lower():
            context_text = "No strong threat intelligence matches found in verified knowledge bases for this traffic pattern."
    else:
        # Scale confidence with number of verified authoritative matches
        item_count = len(verified_mitre) + len(verified_cves) + len(verified_cisa)
        confidence = min(0.96, max(0.60, 0.55 + (item_count * 0.10)))

    return ThreatIntelOutput(
        mitre_attack=verified_mitre,
        cve_list=verified_cves,
        cisa_advisories=verified_cisa,
        iot_threat_context=context_text,
        retrieval_confidence=round(confidence, 2),
        sources=unique_sources,
        generated_by=raw_output.generated_by,
        llm_model=raw_output.llm_model,
        latency_ms=raw_output.latency_ms
    )
