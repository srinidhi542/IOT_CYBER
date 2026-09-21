import logging
from typing import List, Dict, Any
from app.agents.agent_schemas import (
    DetectionOutput,
    ThreatIntelOutput,
    RiskAssessmentOutput
)

logger = logging.getLogger(__name__)

ATTACK_BASE_SEVERITY = {
    "ddos": 95.0,
    "mirai": 95.0,
    "botnet": 95.0,
    "dos": 80.0,
    "web attack": 75.0,
    "brute force": 65.0,
    "recon": 45.0,
    "reconnaissance": 45.0,
    "spoofing": 45.0,
    "benign": 0.0,
    "normal": 0.0
}


class RiskAssessmentAgent:
    """
    Risk Assessment Agent:
    Evaluates multi-factor cybersecurity risk based on:
    - XGBoost classification & confidence
    - SHAP feature attributions and directional deviations
    - 5-tuple network exposure (ports, public/private IPs)
    - Threat Intelligence context (MITRE ATT&CK & CVE CVSS ratings)
    """

    def assess_risk(
        self,
        detection: DetectionOutput,
        threat_intel: ThreatIntelOutput
    ) -> RiskAssessmentOutput:
        attack = detection.attack_type.strip().lower()
        conf = max(0.0, min(1.0, detection.confidence))
        is_benign = attack in ["benign", "normal"]

        if is_benign:
            return RiskAssessmentOutput(
                risk_score=0.0,
                severity="Low",
                priority="P4 - Low / Informational",
                impact="Minimal - Routine Authorized IoT Operations",
                likelihood="Negligible",
                reasoning=[
                    "Network traffic behavior matches known benign telemetry baseline.",
                    "No anomalous feature spikes or unauthorized access vectors detected.",
                    f"Model confidence in benign classification is {conf * 100:.1f}%."
                ]
            )

        # 1. Base attack score
        base_score = 50.0
        for k, v in ATTACK_BASE_SEVERITY.items():
            if k in attack:
                base_score = v
                break

        # 2. Confidence scaling
        # High confidence reinforces score; low confidence discounts
        conf_factor = 0.7 + (conf * 0.3)
        calculated_risk = base_score * conf_factor

        # 3. SHAP Evidence modifier
        # Examine top SHAP features
        shap_reasons = []
        shap_boost = 0.0
        for item in detection.top_contributing_features[:3]:
            feat = item.feature
            val = item.value
            direction = item.direction
            shap_val = item.shap_value
            friendly_name = feat.replace('_', ' ').title()

            if abs(shap_val) > 0.05:
                shap_boost += 2.0
                shap_reasons.append(
                    f"Elevated SHAP attribution on '{friendly_name}' (value: {val:.2f}, SHAP: {shap_val:+.4f}), which strongly {direction} threat probability."
                )

        calculated_risk += min(shap_boost, 10.0)

        # 4. Threat Intel & Network Exposure modifier
        intel_reasons = []
        max_cve_cvss = max([c.cvss_score for c in threat_intel.cve_list], default=0.0)
        if max_cve_cvss >= 9.0:
            calculated_risk += 8.0
            intel_reasons.append(f"Correlated with Critical severity CVEs (CVSS score {max_cve_cvss}/10).")
        elif max_cve_cvss >= 7.0:
            calculated_risk += 4.0
            intel_reasons.append(f"Correlated with High severity CVEs (CVSS score {max_cve_cvss}/10).")

        if threat_intel.cisa_advisories:
            calculated_risk += 5.0
            intel_reasons.append(f"Referenced in active CISA cyber defense advisory ({threat_intel.cisa_advisories[0].id}).")

        dport = detection.network_context.destination_port or 0
        if dport in [22, 23, 80, 443, 1883, 8080]:
            calculated_risk += 3.0
            intel_reasons.append(f"Targeting critical IoT service port {dport} ({detection.network_context.protocol}).")

        # Clamp final risk score to [0.0, 100.0]
        final_risk = round(max(0.0, min(100.0, calculated_risk)), 1)

        # 5. Severity and Priority determination
        if final_risk >= 75.0:
            severity = "Critical"
            priority = "P1 - Critical Urgent"
            impact = "Catastrophic or severe degradation of IoT gateway and dependent network infrastructure."
            likelihood = "Active Exploitation in Progress"
        elif final_risk >= 50.0:
            severity = "High"
            priority = "P2 - High Priority"
            impact = "Potential device compromise, unauthorized credential access, or localized disruption."
            likelihood = "High Probability of Imminent Harm"
        elif final_risk >= 25.0:
            severity = "Medium"
            priority = "P3 - Medium Priority"
            impact = "Network reconnaissance or port probing without verified payload delivery."
            likelihood = "Suspicious Probing Activity"
        else:
            severity = "Low"
            priority = "P4 - Low / Informational"
            impact = "Negligible operational impact."
            likelihood = "Low"

        # 6. Synthesize comprehensive reasoning
        reasoning = [
            f"Classified as '{detection.attack_type}' with {conf * 100:.1f}% model confidence.",
            *shap_reasons,
            *intel_reasons,
            f"Network 5-tuple context: Source {detection.network_context.source_ip}:{detection.network_context.source_port} -> Destination {detection.network_context.destination_ip}:{detection.network_context.destination_port} ({detection.network_context.protocol})."
        ]

        return RiskAssessmentOutput(
            risk_score=final_risk,
            severity=severity,
            priority=priority,
            impact=impact,
            likelihood=likelihood,
            reasoning=reasoning
        )


risk_assessment_agent = RiskAssessmentAgent()
