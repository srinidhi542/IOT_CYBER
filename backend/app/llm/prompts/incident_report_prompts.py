"""
Incident Report Agent Prompts (Version 1.0)
Professional SOC incident report synthesis from consolidated pipeline incident data.
"""

INCIDENT_REPORT_SYSTEM_PROMPT = """You are an Executive Cyber Incident Reporter AI in an enterprise IoT SOC.
Your task is to write a professional, authoritative executive summary for a security incident report
based on the consolidated incident data provided below.

REQUIREMENTS:
1. Write 2-3 concise paragraphs summarising:
   - What happened: the threat vector, attack family, and classification confidence.
   - Impact: severity, risk score, and effect on IoT devices/infrastructure.
   - Status: containment actions taken and whether analyst approval is still required.
2. Reference specific data values (risk score, severity, CVE IDs, MITRE technique IDs) provided
   in the incident data - do NOT invent identifiers.
3. If any upstream pipeline agent was DEGRADED or FAILED, explicitly acknowledge the gap and
   note that the analysis may be partial.
4. Use formal, precise language appropriate for a CISO-level audience.
5. Do NOT output JSON - output plain prose only.
"""


def format_incident_report_prompt(
    incident_id: str,
    attack_type: str,
    confidence_pct: float,
    src: str,
    dst: str,
    proto: str,
    risk_score: float,
    severity: str,
    priority: str,
    threat_context: str,
    mitre_ids: list,
    cve_ids: list,
    containment_actions: list,
    agent_statuses: dict,
) -> str:
    """Build the user-turn prompt for the incident report executive summary LLM call."""
    degraded = [name for name, st in agent_statuses.items() if st in ("DEGRADED", "FAILED")]
    degraded_note = (
        f"DEGRADED AGENTS (partial analysis): {', '.join(degraded)}"
        if degraded
        else "All pipeline agents completed successfully."
    )

    lines = [
        f"Incident ID: {incident_id}",
        f"Attack Family: {attack_type} (Classification Confidence: {confidence_pct:.1f}%)",
        f"Network Path: {src} -> {dst} ({proto})",
        f"Risk Score: {risk_score}/100 | Severity: {severity} | Priority: {priority}",
        f"Threat Intelligence Context: {threat_context}",
        f"MITRE ATT&CK Techniques: {mitre_ids}",
        f"Correlated CVEs: {cve_ids}",
        f"Immediate Containment Actions: {containment_actions[:4]}",
        f"Pipeline Status: {degraded_note}",
        "",
        "Write the executive summary for this incident report (plain prose, no JSON):",
    ]
    return "\n".join(lines)
