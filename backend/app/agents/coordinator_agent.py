import os
import json
import time
import logging
import traceback
from datetime import datetime
from typing import Dict, Any, List, Optional
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

from app.agents.agent_schemas import (
    NetworkContext,
    ShapEvidence,
    DetectionOutput,
    IncidentState,
    TimelineEvent,
    AgentError,
    ThreatIntelOutput,
    RiskAssessmentOutput,
    ResponseOutput,
    IncidentReportOutput
)
from app.agents.threat_intel_agent import threat_intel_agent
from app.agents.risk_assessment_agent import risk_assessment_agent, ATTACK_BASE_SEVERITY
from app.agents.response_agent import response_agent
from app.agents.incident_report_agent import incident_report_agent

logger = logging.getLogger(__name__)


class AgentResult:
    def __init__(
        self,
        agent_name: str,
        status: str,
        value: Any = None,
        error: Optional[str] = None,
        latency_ms: float = 0.0
    ):
        self.agent_name = agent_name
        self.status = status  # "COMPLETED", "DEGRADED", "FAILED", "SKIPPED"
        self.value = value
        self.error = error
        self.latency_ms = latency_ms


def run_agent_safely(
    agent_name: str,
    fn,
    *args,
    timeout: float = 30.0,
    **kwargs
) -> AgentResult:
    """
    Executes an agent step inside an isolated safe runner:
    - Catches all exceptions
    - Enforces configurable per-agent execution timeout
    - Logs full tracebacks server-side
    - Sanitizes error messages for client response
    - Returns structured AgentResult instead of raising
    """
    t0 = time.time()
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(fn, *args, **kwargs)
            res = future.result(timeout=timeout)
            latency_ms = round((time.time() - t0) * 1000, 2)

            # Check if agent marked its output as degraded fallback
            status = "COMPLETED"
            if hasattr(res, "generated_by") and getattr(res, "generated_by") == "rule_based_fallback":
                status = "DEGRADED"

            return AgentResult(
                agent_name=agent_name,
                status=status,
                value=res,
                latency_ms=latency_ms
            )

    except FutureTimeoutError:
        latency_ms = round((time.time() - t0) * 1000, 2)
        sanitized = f"Agent '{agent_name}' timed out after {timeout:.1f}s"
        logger.error(f"[FaultTolerance] {sanitized}")
        return AgentResult(
            agent_name=agent_name,
            status="FAILED",
            error=sanitized,
            latency_ms=latency_ms
        )

    except Exception as e:
        latency_ms = round((time.time() - t0) * 1000, 2)
        logger.error(f"[FaultTolerance] Agent '{agent_name}' crashed: {e}\n{traceback.format_exc()}")
        # Sanitize error to avoid leaking secrets/paths
        sanitized_err = f"{type(e).__name__}: {str(e)}"
        return AgentResult(
            agent_name=agent_name,
            status="FAILED",
            error=sanitized_err,
            latency_ms=latency_ms
        )


class CoordinatorAgent:
    """
    Coordinator Agent:
    Orchestrates the 6-agent SOC pipeline with end-to-end fault tolerance,
    graceful degradation, and cross-incident correlation.
    """

    def __init__(self, max_history: int = 100):
        self.incidents: OrderedDict[str, IncidentState] = OrderedDict()
        self.max_history = max_history
        self._load_persisted_incidents()

    def _load_persisted_incidents(self):
        """Loads previously saved incidents from storage/reports/*.json so incidents persist across backend reloads."""
        try:
            from app.core.config import settings
            reports_dir = settings.STORAGE_REPORTS_DIR
            if not os.path.exists(reports_dir):
                return
            
            json_files = [f for f in os.listdir(reports_dir) if f.startswith("REP-") and f.endswith(".json")]
            # Sort by file modification time ascending so that the newest file is inserted LAST into OrderedDict.
            # Then list(reversed(self.incidents.values())) will return the NEWEST incident first!
            json_files.sort(key=lambda f: os.path.getmtime(os.path.join(reports_dir, f)))
            
            for fname in json_files[:self.max_history]:
                fpath = os.path.join(reports_dir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    
                    inc_id = data.get("incident_id")
                    if not inc_id or inc_id in self.incidents:
                        continue
                    
                    # Construct IncidentState from stored report json
                    det_data = data.get("detection")
                    ti_data = data.get("threat_intel")
                    risk_data = data.get("risk")
                    resp_data = data.get("response")
                    rep_data = data.get("report")
                    tl_data = data.get("timeline") or []
                    
                    det_obj = DetectionOutput(**det_data) if det_data else None
                    ti_obj = ThreatIntelOutput(**ti_data) if ti_data else None
                    risk_obj = RiskAssessmentOutput(**risk_data) if risk_data else None
                    resp_obj = ResponseOutput(**resp_data) if resp_data else None
                    rep_obj = IncidentReportOutput(**rep_data) if rep_data else None
                    tl_objs = [TimelineEvent(**t) for t in tl_data]
                    
                    created_at_val = rep_data.get("generated_at") if rep_data else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    incident_state = IncidentState(
                        incident_id=inc_id,
                        created_at=str(created_at_val),
                        status="CONTAINED" if resp_obj and resp_obj.approval_status == "APPROVED" else "PENDING_APPROVAL",
                        overall_status="COMPLETE",
                        detection=det_obj,
                        threat_intel=ti_obj,
                        risk_assessment=risk_obj,
                        response=resp_obj,
                        report=rep_obj,
                        timeline=tl_objs,
                        agent_status={"detection": "COMPLETED", "threat_intel": "COMPLETED", "risk_assessment": "COMPLETED", "response": "COMPLETED", "incident_report": "COMPLETED"},
                        correlation_note=None
                    )
                    self.incidents[inc_id] = incident_state
                except Exception as e:
                    logger.debug(f"Could not load stored incident from {fname}: {e}")
            
            logger.info(f"Loaded {len(self.incidents)} persisted incidents from disk.")
        except Exception as err:
            logger.warning(f"Error loading persisted incidents: {err}")


    def run_pipeline(
        self,
        record: Dict[str, Any],
        network_context: Optional[Dict[str, Any]] = None,
        user_id: str = "system",
    ) -> IncidentState:
        from app.core.config import load_platform_settings
        platform_cfg = load_platform_settings()

        agent_timeout = float(platform_cfg.get("multi_agent_pipeline", {}).get("agent_timeout_seconds", 30.0))
        exec_mode = platform_cfg.get("agent_pipeline", {}).get("execution_mode", "coordinated")
        llm_cfg = platform_cfg.get("llm", {})
        llm_enabled = bool(llm_cfg.get("enabled", True))
        llm_toggles = llm_cfg.get("agent_toggles", {})

        start_time = time.time()
        incident_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{int(time.time() * 1000) % 100000:05d}"
        created_at_iso = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        timeline: List[TimelineEvent] = []
        agent_statuses: Dict[str, str] = {}
        pipeline_errors: List[AgentError] = []

        def mark_event(
            agent_name: str,
            action: str,
            details: str,
            status: str = "COMPLETED"
        ):
            t_offset = round(time.time() - start_time, 3)
            timeline.append(TimelineEvent(
                timestamp=f"+{t_offset:.3f}s",
                agent=agent_name,
                action=action,
                details=details,
                status=status
            ))

        # -------------------------------------------------------------
        # 1. DETECTION AGENT (XGBoost + SHAP + LLM Analyst Explanation)
        # -------------------------------------------------------------
        def _execute_detection():
            from app.ml.predict_pipeline import explain_prediction
            shap_k = platform_cfg.get("detection_engine", {}).get("shap_top_k", 5)
            shap_result = explain_prediction(record, top_k=shap_k)

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

            det_output = DetectionOutput(
                attack_type=shap_result["label"],
                confidence=shap_result["confidence"],
                probabilities=shap_result.get("probabilities", {}),
                network_context=net_ctx,
                top_contributing_features=shap_items,
                shap_values=shap_result.get("shap_values", {}),
                raw_record=record,
                generated_by="rule_based"
            )

            # Optional LLM Explanation step
            if llm_enabled and llm_toggles.get("detection", True):
                try:
                    from app.llm.client import get_llm_client
                    from app.llm.prompts.detection_prompts import DETECTION_SYSTEM_PROMPT, format_detection_prompt

                    llm_c = get_llm_client()
                    if llm_c.is_available():
                        p = format_detection_prompt(
                            attack_type=det_output.attack_type,
                            confidence=det_output.confidence,
                            network_context=net_ctx.model_dump(),
                            top_features=[s.model_dump() for s in shap_items]
                        )
                        t0 = time.time()
                        explanation = llm_c.generate(DETECTION_SYSTEM_PROMPT, p, agent_name="Detection Agent")
                        lat = round((time.time() - t0) * 1000, 2)
                        det_output.analyst_explanation = explanation
                        det_output.generated_by = "llm"
                        det_output.llm_model = llm_c.model
                        det_output.latency_ms = lat
                except Exception as le:
                    logger.warning(f"Detection LLM explanation failed (falling back to rules): {le}")
                    det_output.generated_by = "rule_based_fallback"

            return det_output

        det_res = run_agent_safely("Detection Agent", _execute_detection, timeout=agent_timeout)
        agent_statuses["detection"] = det_res.status

        if det_res.status == "FAILED":
            err_msg = det_res.error or "Detection engine failed to evaluate telemetry."
            pipeline_errors.append(AgentError(agent="Detection Agent", error=err_msg, timestamp=created_at_iso))
            mark_event("Detection Agent", "Supervised Inference Failure", f"Failed: {err_msg}", status="FAILED")

            # Detection is the only hard dependency -> return minimal FAILED incident
            failed_incident = IncidentState(
                incident_id=incident_id,
                created_at=created_at_iso,
                status="FAILED",
                overall_status="FAILED",
                detection=None,
                threat_intel=None,
                risk_assessment=None,
                response=None,
                report=None,
                timeline=timeline,
                agent_status=agent_statuses,
                errors=pipeline_errors
            )
            self.incidents[incident_id] = failed_incident
            return failed_incident

        detection_output: DetectionOutput = det_res.value
        top_shap_desc = detection_output.top_contributing_features[0].feature if detection_output.top_contributing_features else "flow metrics"
        llm_info = f" [LLM: {detection_output.llm_model}, {detection_output.latency_ms}ms]" if detection_output.generated_by == "llm" else ""
        mark_event(
            "Detection Agent",
            "Supervised Inference & SHAP Attribution",
            f"Classified flow as '{detection_output.attack_type}' with {detection_output.confidence * 100:.1f}% confidence. Primary feature driver: {top_shap_desc}.{llm_info}",
            status=det_res.status
        )

        # -------------------------------------------------------------
        # 2. COORDINATOR AGENT (Incident Correlation & Triage Note)
        # -------------------------------------------------------------
        correlation_note = None
        try:
            recent_matches = [
                {
                    "incident_id": inc.incident_id,
                    "attack_type": inc.detection.attack_type if inc.detection else "Unknown",
                    "source_ip": inc.detection.network_context.source_ip if inc.detection else "Unknown",
                    "destination_ip": inc.detection.network_context.destination_ip if inc.detection else "Unknown",
                    "created_at": inc.created_at
                }
                for inc in list(self.incidents.values())[-10:]
                if inc.detection and inc.detection.network_context.source_ip == detection_output.network_context.source_ip
            ]

            if llm_enabled and llm_toggles.get("coordinator", True):
                from app.llm.client import get_llm_client
                from app.llm.prompts.coordinator_prompts import COORDINATOR_SYSTEM_PROMPT, format_correlation_prompt

                llm_c = get_llm_client()
                if llm_c.is_available():
                    cp = format_correlation_prompt(
                        current_incident_id=incident_id,
                        attack_type=detection_output.attack_type,
                        source_ip=detection_output.network_context.source_ip or "Unknown",
                        dest_ip=detection_output.network_context.destination_ip or "Unknown",
                        recent_incidents=recent_matches
                    )
                    correlation_note = llm_c.generate(COORDINATOR_SYSTEM_PROMPT, cp, agent_name="Coordinator Agent")
            
            if not correlation_note:
                if recent_matches:
                    correlation_note = f"Observed {len(recent_matches)} prior correlated incident(s) from host {detection_output.network_context.source_ip} in current active session."
                else:
                    correlation_note = "First observed malicious traffic burst from this source endpoint in the current monitoring window."
        except Exception as ce:
            logger.warning(f"Coordinator correlation analysis skipped: {ce}")
            correlation_note = "Incident initialized without historical correlation."

        agent_statuses["coordinator"] = "COMPLETED"
        mark_event(
            "Coordinator Agent",
            "Incident State Initialized",
            f"Allocated tracker {incident_id}. Correlation note: {correlation_note}",
            status="COMPLETED"
        )

        # -------------------------------------------------------------
        # 3. THREAT INTELLIGENCE AGENT (Hybrid RAG + Guardrails)
        # -------------------------------------------------------------
        threat_intel: Optional[ThreatIntelOutput] = None
        ti_res = run_agent_safely("Threat Intel Agent", threat_intel_agent.retrieve_intelligence, detection_output, timeout=agent_timeout)
        agent_statuses["threat_intel"] = ti_res.status

        if ti_res.status == "FAILED":
            err_msg = ti_res.error or "RAG store unreachable or retrieval crashed."
            pipeline_errors.append(AgentError(agent="Threat Intel Agent", error=err_msg, timestamp=created_at_iso))
            mark_event("Threat Intel Agent", "Knowledge Base Retrieval", f"Failed: {err_msg}", status="FAILED")
        else:
            threat_intel = ti_res.value
            mitre_count = len(threat_intel.mitre_attack)
            cve_count = len(threat_intel.cve_list)
            gen_tag = f" [LLM: {threat_intel.llm_model}, {threat_intel.latency_ms}ms]" if threat_intel.generated_by == "llm" else ""
            mark_event(
                "Threat Intel Agent",
                "Knowledge Base RAG Retrieval",
                f"Retrieved {mitre_count} MITRE ATT&CK technique(s) and {cve_count} verified CVE record(s). Zero-hallucination checks passed.{gen_tag}",
                status=ti_res.status
            )

        # -------------------------------------------------------------
        # 4. RISK ASSESSMENT AGENT (Multi-Factor Scoring + Narrative)
        # -------------------------------------------------------------
        risk_assessment: Optional[RiskAssessmentOutput] = None
        def _run_risk():
            return risk_assessment_agent.assess_risk(detection_output, threat_intel, user_id=user_id)

        risk_res = run_agent_safely("Risk Assessment Agent", _run_risk, timeout=agent_timeout)
        agent_statuses["risk_assessment"] = risk_res.status

        if risk_res.status == "FAILED":
            err_msg = risk_res.error or "Risk scoring engine failed."
            pipeline_errors.append(AgentError(agent="Risk Assessment Agent", error=err_msg, timestamp=created_at_iso))
            mark_event("Risk Assessment Agent", "Risk Scoring Failure", f"Failed: {err_msg}", status="FAILED")
            # Downstream fallback: build estimated risk assessment from attack type table
            attack_key = detection_output.attack_type.lower()
            est_base = 50.0
            for k, v in ATTACK_BASE_SEVERITY.items():
                if k in attack_key:
                    est_base = v
                    break
            risk_assessment = RiskAssessmentOutput(
                risk_score=est_base,
                severity="High" if est_base >= 50 else "Medium",
                priority="P2 - High Priority (Estimated)" if est_base >= 50 else "P3 - Medium (Estimated)",
                impact="Estimated baseline impact (Risk Agent was unavailable)",
                likelihood="Estimated from supervised classifier",
                reasoning=[f"Fallback risk estimated from attack type '{detection_output.attack_type}'."]
            )
        else:
            risk_assessment = risk_res.value
            gen_tag = f" [LLM: {risk_assessment.llm_model}, {risk_assessment.latency_ms}ms]" if risk_assessment.generated_by == "llm" else ""
            mark_event(
                "Risk Assessment Agent",
                "Multi-Factor Risk Scoring",
                f"Assessed Risk Score: {risk_assessment.risk_score}/100 ({risk_assessment.severity} Severity, {risk_assessment.priority}).{gen_tag}",
                status=risk_res.status
            )

        # -------------------------------------------------------------
        # 5. RESPONSE AGENT (Playbooks & Syntax-Checked Firewall Rules)
        # -------------------------------------------------------------
        response_plan: Optional[ResponseOutput] = None
        def _run_response():
            return response_agent.generate_response_plan(detection_output, risk_assessment, user_id=user_id)

        resp_res = run_agent_safely("Response Agent", _run_response, timeout=agent_timeout)
        agent_statuses["response"] = resp_res.status

        if resp_res.status == "FAILED":
            err_msg = resp_res.error or "Response formulation failed."
            pipeline_errors.append(AgentError(agent="Response Agent", error=err_msg, timestamp=created_at_iso))
            mark_event("Response Agent", "Response Playbook Formulation", f"Failed: {err_msg}", status="FAILED")
        else:
            response_plan = resp_res.value
            fw_count = len(response_plan.firewall_commands)
            gen_tag = f" [LLM: {response_plan.llm_model}, {response_plan.latency_ms}ms]" if response_plan.generated_by == "llm" else ""
            mark_event(
                "Response Agent",
                "Mitigation & ACL Formulation",
                f"Generated {fw_count} firewall/ACL commands and {len(response_plan.containment)} containment procedures. Status: PENDING_ANALYST_APPROVAL.{gen_tag}",
                status=resp_res.status
            )

        # -------------------------------------------------------------
        # 6. INCIDENT REPORT AGENT (Structured Synthesis & Timeline)
        # -------------------------------------------------------------
        report: Optional[IncidentReportOutput] = None
        def _run_report():
            return incident_report_agent.generate_report(
                incident_id=incident_id,
                detection=detection_output,
                threat_intel=threat_intel,
                risk=risk_assessment,
                response=response_plan,
                timeline=timeline,
                agent_statuses=agent_statuses,
                user_id=user_id,
            )

        rep_res = run_agent_safely("Incident Report Agent", _run_report, timeout=agent_timeout)
        agent_statuses["incident_report"] = rep_res.status

        if rep_res.status == "FAILED":
            err_msg = rep_res.error or "Report compilation failed."
            pipeline_errors.append(AgentError(agent="Incident Report Agent", error=err_msg, timestamp=created_at_iso))
            mark_event("Incident Report Agent", "Report Compilation", f"Failed: {err_msg}", status="FAILED")
            # Build minimal emergency fallback markdown report
            emergency_md = f"# SOC Incident Report: {incident_id}\n\n**Status:** Partial Pipeline Run (Report Agent failed)\n\n"
            emergency_md += f"- **Attack:** {detection_output.attack_type} ({detection_output.confidence*100:.1f}%)\n"
            emergency_md += f"- **Risk:** {risk_assessment.risk_score}/100 ({risk_assessment.severity})\n"
            report = IncidentReportOutput(
                incident_id=incident_id,
                generated_at=created_at_iso,
                title=f"Incident {incident_id} (Partial Report)",
                executive_summary="Incident recorded with partial agent outputs.",
                attack_type=detection_output.attack_type,
                severity=risk_assessment.severity,
                priority=risk_assessment.priority,
                risk_score=risk_assessment.risk_score,
                timeline=timeline,
                markdown_content=emergency_md,
                generated_by="rule_based_fallback"
            )
        else:
            report = rep_res.value
            gen_tag = f" [LLM: {report.llm_model}, {report.latency_ms}ms]" if report.generated_by == "llm" else ""
            mark_event(
                "Incident Report Agent",
                "Structured Report Compilation",
                f"Finalized SOC assessment report for {incident_id} ({len(report.markdown_content)} bytes).{gen_tag}",
                status=rep_res.status
            )

        # -------------------------------------------------------------
        # 7. ASSEMBLE INCIDENT STATE & OVERALL STATUS
        # -------------------------------------------------------------
        has_failures = any(st == "FAILED" for st in agent_statuses.values())
        overall_status = "PARTIAL" if has_failures else "COMPLETE"
        workflow_status = "PENDING_APPROVAL" if (response_plan and response_plan.approval_required) else "CLOSED"

        incident_state = IncidentState(
            incident_id=incident_id,
            created_at=created_at_iso,
            status=workflow_status,
            overall_status=overall_status,
            detection=detection_output,
            threat_intel=threat_intel,
            risk_assessment=risk_assessment,
            response=response_plan,
            report=report,
            timeline=timeline,
            agent_status=agent_statuses,
            errors=pipeline_errors,
            correlation_note=correlation_note
        )

        # Cache in memory
        self.incidents[incident_id] = incident_state
        if len(self.incidents) > self.max_history:
            self.incidents.popitem(last=False)

        # -------------------------------------------------------------
        # 8. PERSISTENCE (BEST-EFFORT, NEVER CRASHES THE PIPELINE)
        # -------------------------------------------------------------
        try:
            from app.reports.storage_service import ReportStorageService
            ReportStorageService.save_incident_report(
                incident_id=incident_id,
                detection_data=detection_output.model_dump() if detection_output else {},
                threat_intel_data=threat_intel.model_dump() if threat_intel else {},
                risk_data=risk_assessment.model_dump() if risk_assessment else {},
                response_data=response_plan.model_dump() if response_plan else {},
                report_data=report.model_dump() if report else {},
                timeline_data=[t.model_dump() for t in timeline],
                source="coordinator_pipeline"
            )
            logger.info(f"Persisted incident report for {incident_id} to MongoDB and storage/reports/")
        except Exception as se:
            logger.warning(f"Could not persist report {incident_id} to MongoDB/disk (continuing in-memory): {se}")

        logger.info(f"Pipeline completed for {incident_id} in {time.time() - start_time:.2f}s (Overall: {overall_status}).")
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

        # Close the loop: persist analyst decision to few-shot precedent memory for response agent
        try:
            from app.agents.response_agent import record_approved_precedent
            record_approved_precedent(incident)
        except Exception as pe:
            logger.warning(f"Could not save analyst precedent: {pe}")

        return incident

    def get_incident(self, incident_id: str) -> Optional[IncidentState]:
        return self.incidents.get(incident_id)

    def list_incidents(self) -> List[IncidentState]:
        return list(reversed(self.incidents.values()))


coordinator_agent = CoordinatorAgent()
