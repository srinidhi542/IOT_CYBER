"""
Risk Assessment Agent Prompts (Version 1.0)
Narrative justification for multi-factor calibrated risk score.
"""

RISK_SYSTEM_PROMPT = """You are a Cybersecurity Risk Assessor AI for an IoT Security Operations Center.
Your task is to write a structured analytical reasoning narrative justifying an algorithmic risk score.

RULES:
1. The numeric risk score, severity, and operational priority are DETERMINISTIC and FINAL. You MUST NOT alter or challenge the numeric risk score.
2. Formulate 3-5 concise, bullet-ready reasoning points detailing:
   - Model confidence and baseline threat severity
   - Physical or network impact on IoT devices (microcontrollers, gateways, sensors)
   - Influence of top SHAP feature deviations
   - Threat intelligence factors (correlating CVE severity, CISA advisories, or port sensitivity)
3. Return valid JSON: {"reasoning": ["point 1", "point 2", "point 3"]}
"""

def format_risk_prompt(
    risk_score: float,
    severity: str,
    priority: str,
    attack_type: str,
    confidence: float,
    top_features: list,
    threat_intel_summary: str,
    max_cve_cvss: float,
    cisa_count: int,
    port: int
) -> str:
    lines = [
        f"Determined Risk Score: {risk_score}/100.0",
        f"Assigned Severity: {severity}",
        f"Operational Priority: {priority}",
        f"Classified Attack: {attack_type} (Confidence: {confidence * 100:.1f}%)",
        f"Targeted Port: {port}",
        f"Highest Correlated CVE CVSS: {max_cve_cvss}",
        f"CISA Advisories Linked: {cisa_count}",
        f"Threat Intel Summary: {threat_intel_summary}",
        "Top SHAP Indicators:"
    ]
    for feat in top_features[:3]:
        lines.append(f"  - {feat.get('feature')}: SHAP {feat.get('shap_value'):+.4f} ({feat.get('direction')})")
    lines.append("\nGenerate 3-5 concise technical reasoning statements in JSON format:")
    return "\n".join(lines)
