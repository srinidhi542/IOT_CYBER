import os
import logging
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import FileResponse, PlainTextResponse

from app.core.config import settings
from app.core.mongo import mongo_manager
from app.reports.storage_service import ReportStorageService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reports/storage", tags=["Persistent Report Storage (MongoDB)"])

@router.get("/status", response_model=Dict[str, Any])
def get_storage_status():
    """
    Returns health status of MongoDB persistent connection and report storage directory.
    """
    is_mongo_ok = mongo_manager.is_connected()
    storage_dir = settings.STORAGE_REPORTS_DIR
    dir_exists = os.path.exists(storage_dir)

    total_files = 0
    if dir_exists:
        try:
            total_files = len([f for f in os.listdir(storage_dir) if os.path.isfile(os.path.join(storage_dir, f))])
        except Exception:
            pass

    total_mongo_docs = 0
    if is_mongo_ok:
        try:
            total_mongo_docs = ReportStorageService.get_collection().count_documents({})
        except Exception:
            pass

    return {
        "mongodb_connected": is_mongo_ok,
        "mongodb_uri": settings.MONGODB_URI.split("@")[-1] if "@" in settings.MONGODB_URI else settings.MONGODB_URI,
        "mongodb_database": settings.MONGODB_DB_NAME,
        "storage_directory": storage_dir,
        "directory_exists": dir_exists,
        "total_files_on_disk": total_files,
        "total_records_in_db": total_mongo_docs
    }

@router.get("", response_model=List[Dict[str, Any]])
def list_stored_reports(
    limit: int = Query(50, ge=1, le=200),
    skip: int = Query(0, ge=0),
    attack: Optional[str] = Query(None, description="Filter by attack classification"),
    severity: Optional[str] = Query(None, description="Filter by severity level (Critical, High, Medium, Low)")
):
    """
    Lists persistently stored reports from MongoDB, sorted by creation timestamp descending.
    """
    if not mongo_manager.is_connected():
        raise HTTPException(
            status_code=503,
            detail="MongoDB is not connected. Please ensure MongoDB service is running at mongodb://localhost:27017"
        )
    try:
        return ReportStorageService.list_reports(
            limit=limit,
            skip=skip,
            attack_filter=attack,
            severity_filter=severity
        )
    except Exception as e:
        logger.error(f"Failed to list stored reports from MongoDB: {e}")
        raise HTTPException(status_code=500, detail=f"Database query error: {str(e)}")

@router.get("/{report_id}", response_model=Dict[str, Any])
def get_stored_report_detail(report_id: str):
    """
    Retrieves full structured metadata, flow statistics, agent findings,
    SHAP explainability, and markdown content of a stored report.
    """
    if not mongo_manager.is_connected():
        raise HTTPException(
            status_code=503,
            detail="MongoDB is not connected. Please ensure MongoDB service is running."
        )
    doc = ReportStorageService.get_report(report_id)
    if not doc:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")
    return doc

@router.get("/{report_id}/download")
def download_stored_report_file(report_id: str, format: Optional[str] = Query("md", enum=["md", "json"])):
    """
    Downloads the actual report file (.md or .json) stored in backend/storage/reports/.
    Validates file paths and prevents path traversal attacks.
    """
    doc = ReportStorageService.get_report(report_id)
    if not doc:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")

    base_filepath = doc.get("filepath", "")
    target_filepath = base_filepath
    if format == "json":
        target_filepath = base_filepath.replace(".md", ".json")

    # Path validation & traversal guard
    storage_abs = os.path.abspath(settings.STORAGE_REPORTS_DIR)
    target_abs = os.path.abspath(target_filepath)
    if not target_abs.startswith(storage_abs):
        raise HTTPException(status_code=400, detail="Invalid file path security violation.")

    if not os.path.exists(target_abs):
        raise HTTPException(status_code=404, detail=f"Report file on disk is missing: {os.path.basename(target_abs)}")

    filename = os.path.basename(target_abs)
    media_type = "application/json" if format == "json" else "text/markdown; charset=utf-8"

    return FileResponse(
        path=target_abs,
        media_type=media_type,
        filename=filename
    )

@router.delete("/{report_id}", response_model=Dict[str, Any])
def delete_stored_report(report_id: str):
    """
    Deletes report metadata from MongoDB and purges associated files from disk.
    """
    if not mongo_manager.is_connected():
        raise HTTPException(
            status_code=503,
            detail="MongoDB is not connected. Please ensure MongoDB service is running."
        )
    success = ReportStorageService.delete_report(report_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found to delete.")
    return {
        "message": f"Report '{report_id}' and all associated files deleted successfully.",
        "report_id": report_id,
        "deleted": True
    }
