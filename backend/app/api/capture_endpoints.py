import os
import shutil
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, status
from pydantic import BaseModel

from app.core.config import settings
from app.capture.tshark_capture import capture_manager, get_network_interfaces, find_tshark_path
from app.capture.cicflowmeter import extract_flows_from_pcap, process_pcap_to_detection, aggregate_flow_features
from app.ml.predict_pipeline import explain_prediction
from app.agents.coordinator_agent import coordinator_agent

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/capture", tags=["Network Packet Capture"])


class StartCaptureRequest(BaseModel):
    interface: str = "Default"
    duration_limit: Optional[int] = 0
    packet_limit: Optional[int] = 0


class ProcessPcapRequest(BaseModel):
    pcap_path: Optional[str] = None
    max_flows_to_analyze: Optional[int] = 5


@router.get("/interfaces", response_model=List[Dict[str, Any]])
def list_interfaces():
    """Returns all enumerated physical and virtual network interfaces."""
    try:
        return get_network_interfaces()
    except Exception as e:
        logger.error(f"Error listing network interfaces: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status", response_model=Dict[str, Any])
def get_capture_status():
    """Returns real-time status of the current or most recent capture session."""
    return capture_manager.get_status()


@router.post("/start", response_model=Dict[str, Any])
def start_capture(payload: StartCaptureRequest):
    """Starts packet capture on the selected network adapter."""
    try:
        session = capture_manager.start_capture(
            interface=payload.interface,
            output_dir=settings.UPLOAD_DIR,
            duration_limit=payload.duration_limit,
            packet_limit=payload.packet_limit
        )
        return session.to_dict()
    except RuntimeError as re:
        raise HTTPException(status_code=400, detail=str(re))
    except Exception as e:
        logger.error(f"Failed to start packet capture: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start packet capture: {str(e)}")


@router.post("/stop", response_model=Dict[str, Any])
def stop_capture():
    """Stops the active packet capture and returns the captured PCAP summary."""
    try:
        return capture_manager.stop_capture()
    except RuntimeError as re:
        raise HTTPException(status_code=400, detail=str(re))
    except Exception as e:
        logger.error(f"Failed to stop packet capture: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to stop packet capture: {str(e)}")


@router.post("/upload", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
def upload_pcap(file: UploadFile = File(...)):
    """Uploads a PCAP or PCAPNG capture file for analysis."""
    if not (file.filename.endswith('.pcap') or file.filename.endswith('.pcapng')):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file format. Only .pcap and .pcapng files are supported."
        )

    file_uuid = f"upload_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
    filepath = os.path.join(settings.UPLOAD_DIR, file_uuid)

    try:
        with open(filepath, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        file_size = os.path.getsize(filepath)
    except Exception as e:
        logger.error(f"PCAP upload failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to save uploaded PCAP.")

    return {
        "filename": file.filename,
        "filepath": filepath,
        "file_size": file_size,
        "uploaded_at": datetime.now().isoformat()
    }


@router.post("/process", response_model=Dict[str, Any])
def process_pcap(payload: ProcessPcapRequest):
    """
    Extracts flows from PCAP using CICFlowMeter, aggregates telemetry into an
    overall network representation, and executes:
    1. Overall Detection and AI Explainability (SHAP TreeExplainer on captured data).
    2. Complete 6-Agent SOC Pipeline (Coordinator -> Threat Intel -> Risk Assessment -> Response -> Report).
    """
    pcap_path = payload.pcap_path
    if not pcap_path:
        status_info = capture_manager.get_status()
        pcap_path = status_info.get("output_pcap")

    if not pcap_path or not os.path.exists(pcap_path):
        raise HTTPException(
            status_code=400,
            detail="No valid PCAP file available. Please capture packets or upload a PCAP file first."
        )

    try:
        # 1. Extract flows via CICFlowMeter
        df = extract_flows_from_pcap(pcap_path)
        if df.empty:
            return {
                "message": "No IP packets found in PCAP to formulate network flows.",
                "flows_extracted": 0,
                "overall_prediction": None,
                "overall_explainability": None,
                "overall_incident": None,
                "incidents": []
            }

        # 2. Compute overall aggregated traffic feature record & network context
        agg_record, net_ctx = aggregate_flow_features(df)

        # 3. Compute overall Detection & AI Explainability directly on the captured data
        overall_explainability = explain_prediction(agg_record, top_k=6)
        overall_pred = {
            "label": overall_explainability["label"],
            "confidence": overall_explainability["confidence"],
            "probabilities": overall_explainability["probabilities"]
        }

        # 4. Run overall captured profile through the complete Coordinator Multi-Agent Pipeline
        overall_incident = coordinator_agent.run_pipeline(agg_record, network_context=net_ctx)

        return {
            "pcap_path": pcap_path,
            "flows_extracted": len(df),
            "capture_stats": net_ctx,
            "overall_prediction": overall_pred,
            "overall_explainability": overall_explainability,
            "overall_incident": overall_incident.dict(),
            "incidents": [overall_incident.dict()]
        }
    except Exception as e:
        logger.error(f"Error processing PCAP through multi-agent pipeline: {e}")
        raise HTTPException(status_code=500, detail=f"PCAP processing failed: {str(e)}")
