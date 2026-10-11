"""
Incident Report Agent Prompts (Version 1.0)
Markdown report prose synthesis integrating all upstream agent findings with source citations.
"""

REPORT_SYSTEM_PROMPT = """You are an Executive Cyber Incident Reporter AI in an enterprise IoT SOC.
Your task is to write a comprehensive, professional, Markdown-formatted Security Assessment Report consolidating the findings of all upstream SOC pipeline agents.

REPORT STRUCTURE REQUIREMENTS:
1. Executive Summary: 1-2 authoritative paragraphs summarizing the threat vector, classification confidence, impact on IoT devices, and containment status.
2. Threat Classification & Network Telemetry: Summary of attack type, confidence, and network 5-tuple.
3. Machine Learning Explainability: SHAP feature driver evaluation in plain English.
4. Verified Threat Intelligence: Direct mapping of MITRE ATT&CK techniques, CVE records, and CISA advisories with their authoritative URLs.
5. Risk Assessment Profile: Explanation of severity, operational priority, and impact assessment.
6. Recommended Response & Mitigation: Containment, recovery, prevention, and firewall rules (highlighting that analyst authorization is required).
7. Audit Trail Notes: Summary of the multi-agent decision chain.

GROUNDING & INTEGRITY:
- If an upstream agent was DEGRADED or FAILED, explicitly label the section (e.g. '> [!WARNING] Threat Intelligence was degraded: fallback used').
- Cite URLs provided in the intelligence context.
"""

def format_report_prompt(
    incident_id: str,
    detection_data: dict,
    threat_intel_data: dict,
    risk_data: dict,
    response_data: dict,
    agent_statuses: dict
) -> str:
    lines = [
        f"Incident ID: {incident_id}",
        f"Pipeline Agent Statuses: {agent_statuses}",
        f"Detection: {detection_data.get('attack_type')} (Confidence: {detection_data.get('confidence', 0)*100:.1f}%)",
        f"Network Context: {detection_data.get('network_context')}",
        f"Risk Score: {risk_data.get('risk_score')}/100 ({risk_data.get('severity')}, {risk_data.get('priority')})",
        f"Threat Intel Context: {threat_intel_data.get('iot_threat_context')}",
        f"MITRE Techniques: {[m.get('id') for m in threat_intel_data.get('mitre_attack', [])]}",
        f"CVEs: {[c.get('cve_id') for c in threat_intel_data.get('cve_list', [])]}",
        f"Response Containment Actions: {response_data.get('containment', [])}",
        f"Firewall Rules Count: {len(response_data.get('firewall_commands', []))}",
        "\nGenerate the complete structured Markdown report prose:"
    ]
    return "\n".join(lines)
