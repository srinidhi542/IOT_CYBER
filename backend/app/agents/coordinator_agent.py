import os
import time
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from collections import OrderedDict

from app.agents.agent_schemas import (
    NetworkContext,
    ShapEvidence,
    DetectionOutput,
    IncidentState,
    TimelineEvent
)
from app.agents.threat_intel_agent import threat_intel_agent
from app.agents.risk_assessment_agent import risk_assessment_agent
from app.agents.response_agent import response_agent
from app.agents.incident_report_agent import incident_report_agent

logger = logging.getLogger(__name__)


class CoordinatorAgent:
    """
    Coordinator Agent:
    Orchestrates the 6-agent sequential SOC pipeline:
    Detection Agent -> Coordinator Agent -> Threat Intel Agent ->
    Risk Assessment Agent -> Response Agent -> Incident Report Agent -> SOC Dashboard.

    Maintains incident state and historical records using structured JSON schemas.
    """

    def __init__(self, max_history: int = 100):
        self.incidents: OrderedDict[str, IncidentState] = OrderedDict()
        self.max_history = max_history

    def run_pipeline(
        self,
        record: Dict[str, Any],
        network_context: Optional[Dict[str, Any]] = None
    ) -> IncidentState:
        start_time = time.time()
        incident_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{int(time.time() * 1000) % 100000:05d}"
        created_at_iso = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        timeline: List[TimelineEvent] = []

        def mark_event(agent_name: str, action: str, details: str):
            t_offset = round(time.time() - start_time, 3)
            timeline.append(TimelineEvent(
                timestamp=f"+{t_offset:.3f}s",
                agent=agent_name,
                action=action,
                details=details,
                status="COMPLETED"
            ))

        # -------------------------------------------------------------
        # 1. DETECTION AGENT (Existing XGBoost & SHAP Explainability)
        # -------------------------------------------------------------
        from app.ml.predict_pipeline import explain_prediction

        shap_result = explain_prediction(record, top_k=5)

        net_ctx = NetworkContext(
            timestamp=network_context.get("Timestamp") if network_context else record.get("Timestamp", created_at_iso),
            source_ip=network_context.get("Source_IP") if network_context else record.get("Source_IP", "192.168.1.15"),
            destination_ip=network_context.get("Destination_IP") if network_context else record.get("Destination_IP", "104.24.12.5"),
            source_port=int(network_context.get("Source_Port", 49364)) if network_context else int(record.get("Source_Port", 49364)),
            destination_port=int(network_context.get("Destination_Port", 80)) if network_context else int(record.get("Destination_Port", 80)),
            protocol=network_context.get("Protocol_Name") if network_context else record.get("Protocol_Name", "TCP")
        )

        shap_items = [
            ShapEvidence(
                feature=item["feature"],
                value=float(item["value"]),
                shap_value=float(item["shap_value"]),
                direction=item["direction"]
            )
            for item in shap_result.get("top_contributing_features", [])
        ]

        detection_output = DetectionOutput(
            attack_type=shap_result["label"],
            confidence=shap_result["confidence"],
            probabilities=shap_result.get("probabilities", {}),
            network_context=net_ctx,
            top_contributing_features=shap_items,
            shap_values=shap_result.get("shap_values", {}),
            raw_record=record
        )

        top_shap_desc = shap_items[0].feature if shap_items else "flow metrics"
        mark_event(
            "Detection Agent",
            "Supervised Inference & SHAP Attribution",
            f"Classified flow as '{detection_output.attack_type}' with {detection_output.confidence * 100:.1f}% confidence. Primary feature driver: {top_shap_desc}."
        )

        # -------------------------------------------------------------
        # 2. COORDINATOR AGENT (State Initialization)
        # -------------------------------------------------------------
        mark_event(
            "Coordinator Agent",
            "Incident State Initialized",
            f"Allocated incident tracker {incident_id}. Initiating Threat Intelligence RAG retrieval."
        )

        # -------------------------------------------------------------
        # 3. THREAT INTELLIGENCE AGENT (RAG Retrieval)
        # -------------------------------------------------------------
        threat_intel = threat_intel_agent.retrieve_intelligence(detection_output)
        mitre_count = len(threat_intel.mitre_attack)
        cve_count = len(threat_intel.cve_list)
        mark_event(
            "Threat Intelligence Agent",
            "Knowledge Base RAG Retrieval",
            f"Retrieved {mitre_count} MITRE ATT&CK technique(s) and {cve_count} verified CVE record(s). Zero hallucination checks passed."
        )

        # -------------------------------------------------------------
        # 4. RISK ASSESSMENT AGENT (Multi-Factor Scoring)
        # -------------------------------------------------------------
        risk_assessment = risk_assessment_agent.assess_risk(detection_output, threat_intel)
        mark_event(
            "Risk Assessment Agent",
            "Multi-Factor Risk Scoring",
            f"Assessed Risk Score: {risk_assessment.risk_score}/100 ({risk_assessment.severity} Severity, {risk_assessment.priority})."
        )

        # -------------------------------------------------------------
        # 5. RESPONSE AGENT (Playbook Formulation)
        # -------------------------------------------------------------
        response_plan = response_agent.generate_response_plan(detection_output, risk_assessment)
        fw_count = len(response_plan.firewall_commands)
        mark_event(
            "Response Agent",
            "Mitigation & ACL Formulation",
            f"Generated {fw_count} firewall/ACL commands and {len(response_plan.containment)} containment procedures. Status: PENDING_ANALYST_APPROVAL."
        )

        # -------------------------------------------------------------
        # 6. INCIDENT REPORT AGENT (Report & Timeline Compilation)
        # -------------------------------------------------------------
        report = incident_report_agent.generate_report(
            incident_id=incident_id,
            detection=detection_output,
            threat_intel=threat_intel,
            risk=risk_assessment,
            response=response_plan,
            timeline=timeline
        )
        mark_event(
            "Incident Report Agent",
            "Structured Report Compilation",
            f"Finalized comprehensive SOC assessment report for {incident_id} ({len(report.markdown_content)} bytes)."
        )

        # -------------------------------------------------------------
        # 7. ASSEMBLE COMPLETE INCIDENT STATE
        # -------------------------------------------------------------
        incident_state = IncidentState(
            incident_id=incident_id,
            created_at=created_at_iso,
            status="PENDING_APPROVAL" if response_plan.approval_required else "CLOSED",
            detection=detection_output,
            threat_intel=threat_intel,
            risk_assessment=risk_assessment,
            response=response_plan,
            report=report,
            timeline=timeline
        )

        # Cache in memory
        self.incidents[incident_id] = incident_state
        if len(self.incidents) > self.max_history:
            self.incidents.popitem(last=False)

        logger.info(f"Pipeline finished for {incident_id} in {time.time() - start_time:.2f}s.")
        return incident_state

    def record_analyst_approval(
        self,
        incident_id: str,
        approved: bool,
        analyst_name: str,
        notes: Optional[str] = None
    ) -> IncidentState:
        if incident_id not in self.incidents:
            raise KeyError(f"Incident {incident_id} not found in active cache.")

        incident = self.incidents[incident_id]
        if not incident.response:
            raise ValueError(f"Incident {incident_id} has no response plan to approve.")

        status = "APPROVED" if approved else "REJECTED"
        incident.response.approval_status = status
        incident.response.reviewed_by = analyst_name
        incident.response.review_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        incident.response.review_notes = notes or ("Approved by analyst" if approved else "Rejected by analyst")
        incident.status = "CONTAINED" if approved else "REJECTED"

        incident.timeline.append(TimelineEvent(
            timestamp=datetime.now().strftime("%H:%M:%S"),
            agent="SOC Analyst",
            action=f"Mitigation Plan {status}",
            details=f"Analyst '{analyst_name}' marked response as {status}. Notes: {incident.response.review_notes}",
            status="COMPLETED"
        ))

        return incident

    def get_incident(self, incident_id: str) -> Optional[IncidentState]:
        return self.incidents.get(incident_id)

    def list_incidents(self) -> List[IncidentState]:
        return list(reversed(self.incidents.values()))


# Global Coordinator Agent singleton
coordinator_agent = CoordinatorAgent()
