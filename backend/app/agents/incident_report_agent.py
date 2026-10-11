import time
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

from app.agents.agent_schemas import (
    DetectionOutput,
    ThreatIntelOutput,
    RiskAssessmentOutput,
    ResponseOutput,
    TimelineEvent,
    IncidentReportOutput
)
from app.llm.agent_helpers import call_llm
from app.llm.prompts.report_prompts import (
    REPORT_SYSTEM_PROMPT,
    format_report_prompt
)
from app.llm.prompts.incident_report_prompts import (
    INCIDENT_REPORT_SYSTEM_PROMPT,
    format_incident_report_prompt,
)

logger = logging.getLogger(__name__)


class IncidentReportAgent:
    """
    Incident Report Agent:
    Compiles structured cybersecurity incident reports uniting:
    - Incident Identification & Timestamp
    - Attack Classification & Confidence
    - Network 5-Tuple Telemetry
    - SHAP Explainability & Feature Attributions
    - Verified Threat Intelligence (MITRE ATT&CK, NVD CVEs, CISA Advisories)
    - Multi-Factor Risk Assessment (Score, Severity, Priority)
    - Response & Mitigation Playbook with Firewall Commands
    - Chronological Multi-Agent SOC Timeline
    - Explicit degradation callouts for any missing or fallback upstream agents
    """

    def generate_report(
        self,
        incident_id: str,
        detection: DetectionOutput,
        threat_intel: Optional[ThreatIntelOutput],
        risk: Optional[RiskAssessmentOutput],
        response: Optional[ResponseOutput],
        timeline: List[TimelineEvent],
        agent_statuses: Optional[Dict[str, str]] = None,
        user_id: str = "system",
    ) -> IncidentReportOutput:
        from app.core.config import load_platform_settings
        platform_cfg = load_platform_settings()
        llm_cfg = platform_cfg.get("llm", {})

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        attack = detection.attack_type
        conf_pct = detection.confidence * 100
        src = f"{detection.network_context.source_ip}:{detection.network_context.source_port}"
        dst = f"{detection.network_context.destination_ip}:{detection.network_context.destination_port}"
        proto = detection.network_context.protocol
        is_benign = attack.lower() in ["benign", "normal"]

        risk_score = risk.risk_score if risk else 0.0
        severity = risk.severity if risk else "Low"
        priority = risk.priority if risk else "P3 - Medium"

        statuses = agent_statuses or {}

        # ------------------------------------------------------------------
        # 1. Executive Summary – LLM preferred, deterministic fallback
        # ------------------------------------------------------------------
        llm_enabled = bool(llm_cfg.get("enabled", True))
        llm_agent_on = llm_cfg.get("agent_toggles", {}).get("incident_report", True)
        exec_summary = ""
        exec_used_llm = False
        exec_llm_model = None
        exec_latency_ms = None

        if not is_benign and llm_enabled and llm_agent_on:
            try:
                t0 = time.time()
                summary_prompt = format_incident_report_prompt(
                    incident_id=incident_id,
                    attack_type=attack,
                    confidence_pct=conf_pct,
                    src=src,
                    dst=dst,
                    proto=proto,
                    risk_score=risk_score,
                    severity=severity,
                    priority=priority,
                    threat_context=(
                        threat_intel.iot_threat_context
                        if threat_intel
                        else "Threat intelligence retrieval was unavailable."
                    ),
                    mitre_ids=[m.id for m in threat_intel.mitre_attack] if threat_intel else [],
                    cve_ids=[c.cve_id for c in threat_intel.cve_list] if threat_intel else [],
                    containment_actions=response.containment if response else [],
                    agent_statuses=statuses,
                )
                success, result = call_llm(
                    system=INCIDENT_REPORT_SYSTEM_PROMPT,
                    user_prompt=summary_prompt,
                    agent_name="incident_report_summary",
                    user_id=user_id,
                    schema=None,
                )
                if success and isinstance(result, str) and len(result.strip()) > 80:
                    exec_summary = result.strip()
                    exec_used_llm = True
                    exec_latency_ms = round((time.time() - t0) * 1000, 2)
                    try:
                        from app.llm.client import get_llm_client as _gc
                        exec_llm_model = _gc().model
                    except Exception:
                        exec_llm_model = None
            except Exception as exc:
                logger.warning(f"[IncidentReportAgent] LLM executive summary failed: {exc}")

        if not exec_summary:
            # Deterministic fallback
            if is_benign:
                exec_summary = (
                    f"Incident {incident_id} evaluated network traffic between {src} and {dst} ({proto}). "
                    f"The flow was classified as Benign baseline activity with {conf_pct:.1f}% confidence. "
                    f"Overall Risk Score is {risk_score}/100 ({severity}). "
                    f"No active malicious exploitation was identified."
                )
            else:
                threat_ctx = threat_intel.iot_threat_context if threat_intel else "Threat intelligence retrieval was unavailable."
                exec_summary = (
                    f"SECURITY INCIDENT ALERT: High-priority security incident {incident_id} detected. "
                    f"Network telemetry exhibits active '{attack}' threat patterns from {src} targeting {dst} ({proto}) "
                    f"with {conf_pct:.1f}% classification certainty. "
                    f"Assessed Risk Score is {risk_score}/100 ({severity} Severity, {priority}). "
                    f"{threat_ctx} Mitigation actions have been formulated and require SOC Analyst approval."
                )

        # ------------------------------------------------------------------
        # 2. LLM-Assisted Full Report Prose Synthesis
        # ------------------------------------------------------------------
        used_llm = False
        llm_model = None
        latency_ms = None
        markdown_doc = ""

        if llm_enabled and llm_agent_on:
            try:
                t0 = time.time()
                prompt = format_report_prompt(
                    incident_id=incident_id,
                    detection_data=detection.model_dump(),
                    threat_intel_data=threat_intel.model_dump() if threat_intel else {},
                    risk_data=risk.model_dump() if risk else {},
                    response_data=response.model_dump() if response else {},
                    agent_statuses=statuses,
                )
                success, result = call_llm(
                    system=REPORT_SYSTEM_PROMPT,
                    user_prompt=prompt,
                    agent_name="incident_report",
                    user_id=user_id,
                    schema=None,
                )
                if success and isinstance(result, str) and len(result.strip()) > 200:
                    markdown_doc = result.strip()
                    latency_ms = round((time.time() - t0) * 1000, 2)
                    used_llm = True
                    try:
                        from app.llm.client import get_llm_client as _gc
                        llm_model = _gc().model
                    except Exception:
                        llm_model = None
            except Exception as le:
                logger.warning(f"[IncidentReportAgent] LLM report prose generation failed: {le}")

        # ------------------------------------------------------------------
        # 3. Deterministic Markdown Fallback
        # ------------------------------------------------------------------
        if not markdown_doc:
            md_lines = [
                f"# SOC INCIDENT ASSESSMENT REPORT: {incident_id}",
                f"**Generated:** {now_str}  |  **Classification:** RESTRICTED / SOC-OPERATIONAL",
                "",
            ]

            degraded_agents = [name for name, st in statuses.items() if st in ["DEGRADED", "FAILED"]]
            if degraded_agents:
                md_lines.extend([
                    "> [!WARNING]",
                    f"> **PARTIAL PIPELINE NOTICE**: The following agents experienced errors or ran in fallback mode: {', '.join(degraded_agents)}.",
                    "",
                ])

            md_lines.extend([
                "## 1. Executive Summary",
                exec_summary,
                "",
                "---",
                "",
                "## 2. Threat Classification & Network Telemetry",
                f"- **Attack Family:** `{attack}`",
                f"- **Classification Confidence:** `{conf_pct:.2f}%`",
                f"- **Source Endpoint:** `{src}`",
                f"- **Destination Endpoint:** `{dst}`",
                f"- **Transport Protocol:** `{proto}`",
                f"- **Detection Timestamp:** `{detection.network_context.timestamp or now_str}`",
                "",
            ])

            if detection.analyst_explanation:
                md_lines.extend([
                    f"**Analyst Technical Narrative:** {detection.analyst_explanation}",
                    "",
                ])

            md_lines.extend([
                "### Class Probability Breakdown",
                "| Class Label | Probability |",
                "| :--- | :--- |",
            ])
            for lbl, prob in detection.probabilities.items():
                bar = "█" * int(prob * 20)
                md_lines.append(f"| {lbl} | {prob * 100:.2f}% `{bar}` |")

            md_lines.extend([
                "",
                "---",
                "",
                "## 3. Machine Learning Explainability (SHAP Attribution)",
                "The following top network flow features drove the XGBoost classification model:",
                "",
                "| Rank | Feature Indicator | Measured Value | SHAP Attribution | Directional Impact |",
                "| :---: | :--- | :---: | :---: | :--- |",
            ])
            for idx, shap_item in enumerate(detection.top_contributing_features, 1):
                md_lines.append(
                    f"| {idx} | `{shap_item.feature}` | {shap_item.value:.3f} "
                    f"| {shap_item.shap_value:+.4f} | {shap_item.direction.upper()} |"
                )

            md_lines.extend([
                "",
                "---",
                "",
                "## 4. Verified Threat Intelligence & RAG Findings",
            ])

            if threat_intel:
                md_lines.append(f"**Retrieval Confidence:** {threat_intel.retrieval_confidence * 100:.0f}%\n")
                md_lines.append("### MITRE ATT&CK Mapping")
                if threat_intel.mitre_attack:
                    for m in threat_intel.mitre_attack:
                        md_lines.extend([
                            f"- **[{m.id}: {m.name}]({m.url})** (Tactic: *{m.tactic}*)",
                            f"  {m.description}",
                        ])
                else:
                    md_lines.append("- *No active MITRE ATT&CK techniques associated with baseline traffic.*")

                md_lines.extend(["", "### Correlated NVD / CVE Records"])
                if threat_intel.cve_list:
                    for c in threat_intel.cve_list:
                        md_lines.extend([
                            f"- **[{c.cve_id}]({c.url})** - CVSS `{c.cvss_score}` ({c.severity})",
                            f"  *Affected:* {c.affected_systems}",
                            f"  {c.description}",
                        ])
                else:
                    md_lines.append("- *No matching high-risk CVE vulnerabilities found in verified database.*")

                if threat_intel.cisa_advisories:
                    md_lines.extend(["", "### CISA Security Advisories"])
                    for ci in threat_intel.cisa_advisories:
                        md_lines.append(f"- **[{ci.id}: {ci.title}]({ci.url})** (Released {ci.release_date})")

                md_lines.extend([
                    "",
                    "### Authoritative Sources",
                    *[f"- <{s}>" for s in threat_intel.sources],
                ])
            else:
                md_lines.extend([
                    "> [!NOTE]",
                    "> Threat Intelligence unavailable: Knowledge retriever was offline or unconfigured.",
                ])

            md_lines.extend([
                "",
                "---",
                "",
                "## 5. Risk Assessment Profile",
                f"- **Assessed Risk Score:** `{risk_score} / 100.0`",
                f"- **Assigned Severity:** `{severity.upper()}`",
                f"- **Operational Priority:** `{priority}`",
            ])
            if risk:
                md_lines.extend([
                    f"- **Potential Impact:** {risk.impact}",
                    f"- **Threat Likelihood:** {risk.likelihood}",
                    "",
                    "### Analytical Justification",
                    *[f"- {r}" for r in risk.reasoning],
                ])
            else:
                md_lines.append("> [!NOTE]\n> Detailed risk reasoning unavailable.")

            md_lines.extend([
                "",
                "---",
                "",
                "## 6. Recommended Response & Containment Playbook",
            ])

            if response:
                md_lines.extend([
                    "",
                    "### Immediate Containment Steps",
                    *[f"1. {c}" for c in response.containment],
                    "",
                    "### Recovery Procedures",
                    *[f"1. {r}" for r in response.recovery],
                    "",
                    "### Long-Term Prevention & Hardening",
                    *[f"- {p}" for p in response.prevention],
                    "",
                    "### Firewall & Access Control Rules",
                    "> [!CAUTION]",
                    "> **ANALYST APPROVAL REQUIRED**: Automated execution is strictly disabled. Verify host parameters before executing.",
                    "",
                ])
                if response.firewall_commands:
                    for cmd in response.firewall_commands:
                        md_lines.extend([
                            f"#### {cmd.firewall_type.upper()}: {cmd.description}",
                            "```bash",
                            cmd.command,
                            "```",
                            "",
                        ])
                else:
                    md_lines.append("*No active firewall blocks recommended for benign traffic.*")
            else:
                md_lines.extend([
                    "> [!NOTE]",
                    "> Response plan unavailable: response agent did not execute.",
                ])

            md_lines.extend([
                "---",
                "",
                "## 7. Chronological Incident Timeline",
                "| Timestamp | Agent | Action / Decision | Telemetry Details |",
                "| :--- | :--- | :--- | :--- |",
            ])
            for ev in timeline:
                md_lines.append(f"| {ev.timestamp} | `{ev.agent}` | {ev.action} | {ev.details} |")

            markdown_doc = "\n".join(md_lines)

        # Use the best latency/model available (full report LLM preferred over summary-only LLM)
        final_generated_by = "llm" if (used_llm or exec_used_llm) else "rule_based_fallback"
        final_llm_model = llm_model or exec_llm_model
        final_latency_ms = latency_ms or exec_latency_ms

        return IncidentReportOutput(
            incident_id=incident_id,
            generated_at=now_str,
            title=f"SOC Incident Assessment: {incident_id} [{attack}]",
            executive_summary=exec_summary,
            attack_type=attack,
            severity=severity,
            priority=priority,
            risk_score=risk_score,
            timeline=timeline,
            markdown_content=markdown_doc,
            generated_by=final_generated_by,
            llm_model=final_llm_model,
            latency_ms=final_latency_ms,
        )


incident_report_agent = IncidentReportAgent()
