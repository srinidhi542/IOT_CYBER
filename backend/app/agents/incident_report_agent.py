import logging
from datetime import datetime
from typing import List, Dict, Any
from app.agents.agent_schemas import (
    DetectionOutput,
    ThreatIntelOutput,
    RiskAssessmentOutput,
    ResponseOutput,
    TimelineEvent,
    IncidentReportOutput
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
    """

    def generate_report(
        self,
        incident_id: str,
        detection: DetectionOutput,
        threat_intel: ThreatIntelOutput,
        risk: RiskAssessmentOutput,
        response: ResponseOutput,
        timeline: List[TimelineEvent]
    ) -> IncidentReportOutput:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        attack = detection.attack_type
        conf_pct = detection.confidence * 100
        src = f"{detection.network_context.source_ip}:{detection.network_context.source_port}"
        dst = f"{detection.network_context.destination_ip}:{detection.network_context.destination_port}"
        proto = detection.network_context.protocol

        # 1. Executive Summary
        is_benign = attack.lower() in ["benign", "normal"]
        if is_benign:
            exec_summary = (
                f"Incident {incident_id} evaluated network traffic between {src} and {dst} ({proto}). "
                f"The flow was classified as Benign baseline activity with {conf_pct:.1f}% confidence. "
                f"Overall Risk Score is {risk.risk_score}/100 ({risk.severity}). No active malicious exploitation was identified."
            )
        else:
            exec_summary = (
                f"SECURITY INCIDENT ALERT: High-priority security incident {incident_id} detected. "
                f"Network telemetry exhibits active '{attack}' threat patterns from {src} targeting {dst} ({proto}) "
                f"with {conf_pct:.1f}% classification certainty. "
                f"Assessed Risk Score is {risk.risk_score}/100 ({risk.severity} Severity, {risk.priority}). "
                f"{threat_intel.iot_threat_context} Containment actions have been formulated and require SOC Analyst approval."
            )

        # 2. Build Markdown Document
        md_lines = [
            f"# SOC INCIDENTIAL ASSESSMENT REPORT: {incident_id}",
            f"**Generated:** {now_str}  |  **Classification:** RESTRICTED / SOC-OPERATIONAL",
            "",
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
            "### Class Probability Breakdown",
            "| Class Label | Probability |",
            "| :--- | :--- |"
        ]

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
            "| :---: | :--- | :---: | :---: | :--- |"
        ])

        for idx, shap_item in enumerate(detection.top_contributing_features, 1):
            md_lines.append(
                f"| {idx} | `{shap_item.feature}` | {shap_item.value:.3f} | {shap_item.shap_value:+.4f} | {shap_item.direction.upper()} |"
            )

        md_lines.extend([
            "",
            "---",
            "",
            "## 4. Verified Threat Intelligence & RAG Findings",
            f"**Retrieval Confidence:** {threat_intel.retrieval_confidence * 100:.0f}%",
            "",
            "### MITRE ATT&CK Mapping"
        ])

        if threat_intel.mitre_attack:
            for m in threat_intel.mitre_attack:
                md_lines.extend([
                    f"- **[{m.id}: {m.name}]({m.url})** (Tactic: *{m.tactic}*)",
                    f"  {m.description}"
                ])
        else:
            md_lines.append("- *No active MITRE ATT&CK techniques associated with baseline traffic.*")

        md_lines.extend([
            "",
            "### Correlated NVD / CVE Records"
        ])

        if threat_intel.cve_list:
            for c in threat_intel.cve_list:
                md_lines.extend([
                    f"- **[{c.cve_id}]({c.url})** - CVSS `{c.cvss_score}` ({c.severity})",
                    f"  *Affected:* {c.affected_systems}",
                    f"  {c.description}"
                ])
        else:
            md_lines.append("- *No matching high-risk CVE vulnerabilities found in verified database.*")

        if threat_intel.cisa_advisories:
            md_lines.extend([
                "",
                "### CISA Security Advisories"
            ])
            for ci in threat_intel.cisa_advisories:
                md_lines.append(f"- **[{ci.id}: {ci.title}]({ci.url})** (Released {ci.release_date})")

        md_lines.extend([
            "",
            "### Authoritative Sources",
            *[f"- <{s}>" for s in threat_intel.sources],
            "",
            "---",
            "",
            "## 5. Risk Assessment Profile",
            f"- **Assessed Risk Score:** `{risk.risk_score} / 100.0`",
            f"- **Assigned Severity:** `{risk.severity.upper()}`",
            f"- **Operational Priority:** `{risk.priority}`",
            f"- **Potential Impact:** {risk.impact}",
            f"- **Threat Likelihood:** {risk.likelihood}",
            "",
            "### Analytical Justification",
            *[f"- {r}" for r in risk.reasoning],
            "",
            "---",
            "",
            "## 6. Recommended Response & Containment Playbook",
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
            ""
        ])

        if response.firewall_commands:
            for cmd in response.firewall_commands:
                md_lines.extend([
                    f"#### {cmd.firewall_type.upper()}: {cmd.description}",
                    "```bash",
                    cmd.command,
                    "```",
                    ""
                ])
        else:
            md_lines.append("*No active firewall blocks recommended for benign traffic.*")

        md_lines.extend([
            "---",
            "",
            "## 7. Chronological Incident Timeline",
            "| Timestamp | Agent | Action / Decision | Telemetry Details |",
            "| :--- | :--- | :--- | :--- |"
        ])

        for ev in timeline:
            md_lines.append(f"| {ev.timestamp} | `{ev.agent}` | {ev.action} | {ev.details} |")

        markdown_doc = "\n".join(md_lines)

        return IncidentReportOutput(
            incident_id=incident_id,
            generated_at=now_str,
            title=f"SOC Incident Assessment: {incident_id} [{attack}]",
            executive_summary=exec_summary,
            attack_type=attack,
            severity=risk.severity,
            priority=risk.priority,
            risk_score=risk.risk_score,
            timeline=timeline,
            markdown_content=markdown_doc
        )


incident_report_agent = IncidentReportAgent()
