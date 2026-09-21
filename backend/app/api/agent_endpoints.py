import logging
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from fastapi.responses import PlainTextResponse

from app.agents.coordinator_agent import coordinator_agent
from app.agents.agent_schemas import IncidentState

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/agents", tags=["Multi-Agent SOC System"])


class AnalyzeRecordRequest(BaseModel):
    record: Dict[str, Any]
    network_context: Optional[Dict[str, Any]] = None


class AnalystApprovalRequest(BaseModel):
    approved: bool
    analyst_name: str = "SOC Analyst"
    notes: Optional[str] = None


@router.post("/analyze", response_model=Dict[str, Any])
def analyze_telemetry_flow(payload: AnalyzeRecordRequest):
    """
    Executes the complete 6-Agent SOC Pipeline on a raw network flow:
    Detection Agent -> Coordinator Agent -> Threat Intel Agent (RAG) ->
    Risk Assessment Agent -> Response Agent -> Incident Report Agent.
    """
    try:
        incident = coordinator_agent.run_pipeline(
            record=payload.record,
            network_context=payload.network_context
        )
        return incident.dict()
    except Exception as e:
        logger.error(f"Multi-agent analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Multi-agent analysis failed: {str(e)}")


@router.get("/incidents", response_model=List[Dict[str, Any]])
def list_soc_incidents():
    """Returns all tracked incidents in reverse chronological order."""
    incidents = coordinator_agent.list_incidents()
    return [inc.dict() for inc in incidents]


@router.get("/incident/{incident_id}", response_model=Dict[str, Any])
def get_soc_incident(incident_id: str):
    """Retrieves complete structured state, report, and timeline for a specific incident."""
    incident = coordinator_agent.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")
    return incident.dict()


@router.post("/incident/{incident_id}/approval", response_model=Dict[str, Any])
def review_incident_response(incident_id: str, payload: AnalystApprovalRequest):
    """
    Records human SOC Analyst authorization (Approve or Reject) for response actions
    and copyable firewall rules. Enforces no-automated-execution policy.
    """
    try:
        updated_incident = coordinator_agent.record_analyst_approval(
            incident_id=incident_id,
            approved=payload.approved,
            analyst_name=payload.analyst_name,
            notes=payload.notes
        )
        return updated_incident.dict()
    except KeyError as ke:
        raise HTTPException(status_code=404, detail=str(ke))
    except Exception as e:
        logger.error(f"Approval update failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/incident/{incident_id}/report", response_class=PlainTextResponse)
def get_incident_markdown_report(incident_id: str):
    """Returns the formatted Markdown SOC incident report ready for export or review."""
    incident = coordinator_agent.get_incident(incident_id)
    if not incident or not incident.report:
        raise HTTPException(status_code=404, detail=f"Report for incident {incident_id} not found.")
    return incident.report.markdown_content


@router.get("/incident/{incident_id}/download")
def download_incident_report(incident_id: str):
    """Triggers an automatic file download attachment of the Markdown SOC incident report."""
    incident = coordinator_agent.get_incident(incident_id)
    if not incident or not incident.report:
        raise HTTPException(status_code=404, detail=f"Report for incident {incident_id} not found.")
    content = incident.report.markdown_content
    filename = f"incident_report_{incident_id}.md"
    return Response(
        content=content,
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    )
