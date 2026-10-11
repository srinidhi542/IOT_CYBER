import time
import logging
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from app.agents.agent_schemas import (
    DetectionOutput,
    ThreatIntelOutput,
    RiskAssessmentOutput
)
from app.llm.agent_helpers import call_llm
from app.llm.prompts.risk_prompts import (
    RISK_SYSTEM_PROMPT,
    format_risk_prompt
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
    "normal": 0.0,
}


class LLMRiskReasoning(BaseModel):
    reasoning: List[str] = Field(default_factory=list)


class RiskAssessmentAgent:
    """
    Risk Assessment Agent:
    Evaluates multi-factor cybersecurity risk based on:
    - XGBoost classification & confidence
    - SHAP feature attributions and directional deviations
    - 5-tuple network exposure (ports, public/private IPs)
    - Threat Intelligence context (MITRE ATT&CK & CVE CVSS ratings)

    STRICT GUARANTEE:
    - The numeric risk score and severity are strictly deterministic.
    - LLM is used exclusively for narrative reasoning and contextual explanation.
    """

    def assess_risk(
        self,
        detection: DetectionOutput,
        threat_intel: Optional[ThreatIntelOutput] = None,
        user_id: str = "system",
    ) -> RiskAssessmentOutput:
        from app.core.config import load_platform_settings
        platform_cfg = load_platform_settings()
        conf_threshold = platform_cfg.get("detection_engine", {}).get("confidence_threshold", 0.70)
        llm_cfg = platform_cfg.get("llm", {})

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
                    f"Model confidence in benign classification is {conf * 100:.1f}%.",
                ],
                generated_by="rule_based",
            )

        # ------------------------------------------------------------------
        # 1. Deterministic Numeric Risk Scoring (Authoritative – never changed by LLM)
        # ------------------------------------------------------------------
        base_score = 50.0
        for k, v in ATTACK_BASE_SEVERITY.items():
            if k in attack:
                base_score = v
                break

        conf_factor = 0.7 + (conf * 0.3)
        if conf < conf_threshold:
            conf_factor *= conf / conf_threshold

        calculated_risk = base_score * conf_factor

        # SHAP Evidence modifier
        shap_reasons: List[str] = []
        shap_boost = 0.0
        for item in detection.top_contributing_features[:3]:
            feat = item.feature
            val = item.value
            direction = item.direction
            shap_val = item.shap_value
            friendly_name = feat.replace("_", " ").title()
            if abs(shap_val) > 0.05:
                shap_boost += 2.0
                shap_reasons.append(
                    f"Elevated SHAP attribution on '{friendly_name}' "
                    f"(value: {val:.2f}, SHAP: {shap_val:+.4f}), "
                    f"which strongly {direction} threat probability."
                )
        calculated_risk += min(shap_boost, 10.0)

        # Threat Intel & Network Exposure modifier
        intel_reasons: List[str] = []
        max_cve_cvss = 0.0
        cisa_count = 0
        if threat_intel:
            max_cve_cvss = max([c.cvss_score for c in threat_intel.cve_list], default=0.0)
            if max_cve_cvss >= 9.0:
                calculated_risk += 8.0
                intel_reasons.append(f"Correlated with Critical severity CVEs (CVSS score {max_cve_cvss}/10).")
            elif max_cve_cvss >= 7.0:
                calculated_risk += 4.0
                intel_reasons.append(f"Correlated with High severity CVEs (CVSS score {max_cve_cvss}/10).")

            if threat_intel.cisa_advisories:
                cisa_count = len(threat_intel.cisa_advisories)
                calculated_risk += 5.0
                intel_reasons.append(
                    f"Referenced in active CISA cyber defense advisory ({threat_intel.cisa_advisories[0].id})."
                )
        else:
            intel_reasons.append("Threat intelligence was unavailable; risk calculated without CVE/CISA modifiers.")

        dport = detection.network_context.destination_port or 0
        if dport in [22, 23, 80, 443, 1883, 8080]:
            calculated_risk += 3.0
            intel_reasons.append(
                f"Targeting critical IoT service port {dport} ({detection.network_context.protocol})."
            )

        final_risk = round(max(0.0, min(100.0, calculated_risk)), 1)

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

        # ------------------------------------------------------------------
        # 2. Reasoning Formulation (LLM Narrative with Deterministic Fallback)
        # ------------------------------------------------------------------
        rule_reasoning: List[str] = [
            f"Classified as '{detection.attack_type}' with {conf * 100:.1f}% model confidence.",
            *shap_reasons,
            *intel_reasons,
            (
                f"Network 5-tuple context: Source {detection.network_context.source_ip}:"
                f"{detection.network_context.source_port} -> Destination "
                f"{detection.network_context.destination_ip}:{detection.network_context.destination_port} "
                f"({detection.network_context.protocol})."
            ),
        ]

        llm_enabled = bool(llm_cfg.get("enabled", True))
        llm_agent_on = llm_cfg.get("agent_toggles", {}).get("risk_assessment", True)
        used_llm = False
        llm_model = None
        latency_ms = None
        final_reasoning = rule_reasoning

        if llm_enabled and llm_agent_on:
            try:
                t0 = time.time()
                prompt = format_risk_prompt(
                    risk_score=final_risk,
                    severity=severity,
                    priority=priority,
                    attack_type=detection.attack_type,
                    confidence=conf,
                    top_features=[s.model_dump() for s in detection.top_contributing_features],
                    threat_intel_summary=(
                        threat_intel.iot_threat_context
                        if threat_intel
                        else "No threat intelligence available"
                    ),
                    max_cve_cvss=max_cve_cvss,
                    cisa_count=cisa_count,
                    port=dport,
                )
                success, result = call_llm(
                    system=RISK_SYSTEM_PROMPT,
                    user_prompt=prompt,
                    agent_name="risk_assessment",
                    user_id=user_id,
                    schema=LLMRiskReasoning,
                )
                if success and result.reasoning:
                    final_reasoning = result.reasoning
                    latency_ms = round((time.time() - t0) * 1000, 2)
                    used_llm = True
                    try:
                        from app.llm.client import get_llm_client as _gc
                        llm_model = _gc().model
                    except Exception:
                        llm_model = None
            except Exception as le:
                logger.warning(
                    f"[RiskAssessmentAgent] LLM narrative generation failed "
                    f"(using deterministic reasoning): {le}"
                )

        return RiskAssessmentOutput(
            risk_score=final_risk,
            severity=severity,
            priority=priority,
            impact=impact,
            likelihood=likelihood,
            reasoning=final_reasoning,
            generated_by="llm" if used_llm else "rule_based_fallback",
            llm_model=llm_model,
            latency_ms=latency_ms,
        )


risk_assessment_agent = RiskAssessmentAgent()
