import os
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from pymongo.errors import PyMongoError, DuplicateKeyError

from app.core.config import settings
from app.core.mongo import get_mongo_db

logger = logging.getLogger(__name__)

class ReportStorageService:
    """
    Manages persistent report storage using MongoDB for rich document metadata
    and backend/storage/reports/ for actual generated files (.md, .json, .pdf).
    """

    @staticmethod
    def get_collection():
        db = get_mongo_db()
        return db["reports"]

    @classmethod
    def save_incident_report(
        cls,
        incident_id: str,
        detection_data: Dict[str, Any],
        threat_intel_data: Dict[str, Any],
        risk_data: Dict[str, Any],
        response_data: Dict[str, Any],
        report_data: Dict[str, Any],
        timeline_data: Optional[List[Dict[str, Any]]] = None,
        source: str = "soc_pipeline"
    ) -> Dict[str, Any]:
        """
        Saves an incident report to disk and stores its rich metadata in MongoDB.
        Prevents duplicates by report_id and ensures atomic filesystem write.
        """
        now = datetime.now()
        report_id = f"REP-{incident_id}"
        filename = f"{report_id}.md"
        filepath = os.path.join(settings.STORAGE_REPORTS_DIR, filename)

        markdown_content = report_data.get("markdown_content", "")

        # 1. Save file to disk safely
        try:
            # Write to a temporary file first, then atomically rename to prevent corruption
            temp_filepath = f"{filepath}.tmp"
            with open(temp_filepath, "w", encoding="utf-8") as f:
                f.write(markdown_content)
            if os.path.exists(filepath):
                os.remove(filepath)
            os.rename(temp_filepath, filepath)
            file_size = os.path.getsize(filepath)
            logger.info(f"Report file saved persistently to {filepath} ({file_size} bytes)")
        except Exception as fe:
            logger.error(f"Failed to write report file {filepath}: {fe}")
            raise IOError(f"Could not write report file to storage: {str(fe)}")

        # Also optionally write JSON metadata bundle alongside the markdown
        json_filename = f"{report_id}.json"
        json_filepath = os.path.join(settings.STORAGE_REPORTS_DIR, json_filename)
        try:
            full_bundle = {
                "report_id": report_id,
                "incident_id": incident_id,
                "detection": detection_data,
                "threat_intel": threat_intel_data,
                "risk": risk_data,
                "response": response_data,
                "report": report_data,
                "timeline": timeline_data or []
            }
            with open(json_filepath, "w", encoding="utf-8") as jf:
                json.dump(full_bundle, jf, indent=2, default=str)
        except Exception as je:
            logger.warning(f"Could not write companion JSON for {report_id}: {je}")

        # 2. Extract structured fields for MongoDB
        attack_type = detection_data.get("attack_type", "Unknown")
        confidence = float(detection_data.get("confidence", 0.0))
        probabilities = detection_data.get("probabilities", {})

        # Flow stats
        net_ctx = detection_data.get("network_context", {})
        flow_stats = {
            "source_ip": net_ctx.get("source_ip"),
            "source_port": net_ctx.get("source_port"),
            "destination_ip": net_ctx.get("destination_ip"),
            "destination_port": net_ctx.get("destination_port"),
            "protocol": net_ctx.get("protocol"),
            "timestamp": net_ctx.get("timestamp"),
            "total_packets": net_ctx.get("total_packets"),
            "total_flows": net_ctx.get("total_flows")
        }

        # SHAP explanations
        shap_explanations = {
            "top_contributing_features": detection_data.get("top_contributing_features", []),
            "shap_values": detection_data.get("shap_values", {})
        }

        # Agent findings
        agent_findings = {
            "executive_summary": report_data.get("executive_summary", ""),
            "mitre_attack": threat_intel_data.get("mitre_attack", {}),
            "threat_category": threat_intel_data.get("threat_category", ""),
            "nvd_cves": threat_intel_data.get("nvd_cves", []),
            "cisa_known_exploited": threat_intel_data.get("cisa_known_exploited", False),
            "iot_threat_context": threat_intel_data.get("iot_threat_context", ""),
            "risk_score": risk_data.get("risk_score", 0.0),
            "severity": risk_data.get("severity", "Low"),
            "priority": risk_data.get("priority", "P4"),
            "contributing_factors": risk_data.get("contributing_factors", [])
        }

        # Mitigation recommendations
        mitigation_recommendations = {
            "actions": response_data.get("actions", []),
            "firewall_rules": response_data.get("firewall_rules", []),
            "requires_human_authorization": response_data.get("requires_human_authorization", True),
            "recommendations": report_data.get("recommendations", [])
        }

        metadata_doc = {
            "report_id": report_id,
            "incident_id": incident_id,
            "title": f"SOC Security Assessment: {attack_type} ({incident_id})",
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
            "source": source,
            "filename": filename,
            "filepath": filepath,
            "file_size": file_size,
            "mime_type": "text/markdown",
            # Detection & classification
            "attack_classification": attack_type,
            "confidence": confidence,
            "probabilities": probabilities,
            # Structured telemetry & explainability
            "flow_statistics": flow_stats,
            "shap_explanations": shap_explanations,
            "agent_findings": agent_findings,
            "mitigation_recommendations": mitigation_recommendations,
            # Timeline & full report markdown preview
            "timeline": timeline_data or [],
            "markdown_content": markdown_content
        }

        # 3. Store / upsert in MongoDB
        try:
            col = cls.get_collection()
            # Upsert so re-running pipeline updates existing record without duplicate key error
            col.update_one(
                {"report_id": report_id},
                {"$set": metadata_doc},
                upsert=True
            )
            logger.info(f"Stored report metadata in MongoDB: {report_id}")
        except PyMongoError as pe:
            logger.error(f"MongoDB write failed for {report_id}: {pe}")
            raise RuntimeError(f"Database error while storing report metadata: {str(pe)}")

        # Clean document for JSON return (convert ObjectId if present)
        metadata_doc.pop("_id", None)
        return metadata_doc

    @classmethod
    def list_reports(
        cls,
        limit: int = 50,
        skip: int = 0,
        attack_filter: Optional[str] = None,
        severity_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Returns list of stored reports ordered by created_at descending.
        Includes file existence verification.
        """
        col = cls.get_collection()
        query = {}
        if attack_filter:
            query["attack_classification"] = attack_filter
        if severity_filter:
            query["agent_findings.severity"] = severity_filter

        cursor = col.find(query, {"markdown_content": 0}).sort("created_at", -1).skip(skip).limit(limit)
        results = []
        for doc in cursor:
            doc.pop("_id", None)
            # Verify file exists on disk
            doc["file_exists"] = os.path.exists(doc.get("filepath", ""))
            results.append(doc)
        return results

    @classmethod
    def get_report(cls, report_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves complete metadata and content of a report by its unique ID.
        """
        col = cls.get_collection()
        doc = col.find_one({"report_id": report_id})
        if not doc:
            # Fallback search by incident_id
            doc = col.find_one({"incident_id": report_id})
        if not doc:
            return None

        doc.pop("_id", None)
        filepath = doc.get("filepath", "")
        doc["file_exists"] = os.path.exists(filepath)

        # If markdown content is in file, ensure it matches
        if os.path.exists(filepath) and not doc.get("markdown_content"):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    doc["markdown_content"] = f.read()
            except Exception:
                pass

        return doc

    @classmethod
    def delete_report(cls, report_id: str) -> bool:
        """
        Safely deletes report metadata from MongoDB and removes the physical files from disk.
        """
        col = cls.get_collection()
        doc = col.find_one({"report_id": report_id})
        if not doc:
            doc = col.find_one({"incident_id": report_id})
        if not doc:
            return False

        # Delete physical file from storage
        filepath = doc.get("filepath", "")
        if filepath and os.path.exists(filepath):
            try:
                os.remove(filepath)
                logger.info(f"Deleted physical report file: {filepath}")
            except Exception as e:
                logger.warning(f"Could not delete physical file {filepath}: {e}")

        # Delete companion JSON file if present
        json_filepath = filepath.replace(".md", ".json")
        if json_filepath and os.path.exists(json_filepath):
            try:
                os.remove(json_filepath)
            except Exception:
                pass

        # Delete from MongoDB
        res = col.delete_one({"report_id": doc["report_id"]})
        return res.deleted_count > 0
