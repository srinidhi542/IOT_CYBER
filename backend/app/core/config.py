import os
import json
from pydantic_settings import BaseSettings
from typing import Dict, Any

class Settings(BaseSettings):
    PROJECT_NAME: str = "IOTShield"
    API_V1_STR: str = "/api"
    
    # Paths
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    UPLOAD_DIR: str = os.path.join(BASE_DIR, "uploads")
    MODEL_DIR: str = os.path.join(BASE_DIR, "models")
    REPORTS_DIR: str = os.path.join(BASE_DIR, "reports")
    SETTINGS_FILE: str = os.path.join(BASE_DIR, "platform_settings.json")
    DATABASE_URL: str = f"sqlite:///{os.path.join(BASE_DIR, 'iot_sentinel.db')}"

    class Config:
        case_sensitive = True

settings = Settings()

# Ensure directories exist
os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
os.makedirs(settings.MODEL_DIR, exist_ok=True)
os.makedirs(settings.REPORTS_DIR, exist_ok=True)

DEFAULT_PLATFORM_SETTINGS: Dict[str, Any] = {
    "network_capture": {
        "default_interface": "Wi-Fi",
        "capture_duration": 30,
        "auto_stop": True,
        "pcap_storage_path": settings.UPLOAD_DIR,
    },
    "flow_extraction": {
        "flow_timeout": 120,
        "output_directory": settings.UPLOAD_DIR,
        "auto_process_pcap": True,
    },
    "detection_engine": {
        "active_model_id": 1,
        "confidence_threshold": 0.70,
        "shap_top_k": 5,
    },
    "multi_agent_pipeline": {
        "execution_mode": "coordinated",
        "analyst_approval_required": True,
    },
    "threat_intelligence": {
        "enable_mitre": True,
        "enable_nvd_cve": True,
        "enable_cisa": True,
        "rag_top_k": 3,
    },
    "data_storage": {
        "pcap_path": settings.UPLOAD_DIR,
        "flow_csv_path": settings.UPLOAD_DIR,
        "report_path": settings.REPORTS_DIR,
        "retention_days": 30,
    }
}

def _write_settings_file(data: Dict[str, Any]) -> None:
    """Helper to write settings directly to disk without loading."""
    try:
        with open(settings.SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Failed to write settings file: {e}")

import copy

def load_platform_settings() -> Dict[str, Any]:
    """Loads platform settings from JSON file with fallback defaults."""
    if not os.path.exists(settings.SETTINGS_FILE):
        _write_settings_file(DEFAULT_PLATFORM_SETTINGS)
        return DEFAULT_PLATFORM_SETTINGS
    
    try:
        with open(settings.SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            merged = copy.deepcopy(DEFAULT_PLATFORM_SETTINGS)
            for key, val in data.items():
                if key in merged and isinstance(val, dict) and isinstance(merged[key], dict):
                    merged[key].update(val)
                else:
                    merged[key] = val
            return merged
    except Exception:
        return DEFAULT_PLATFORM_SETTINGS

def save_platform_settings(new_settings: Dict[str, Any]) -> Dict[str, Any]:
    """Saves platform settings to JSON file."""
    current = load_platform_settings()
    for key, val in new_settings.items():
        if key in current and isinstance(val, dict) and isinstance(current[key], dict):
            current[key].update(val)
        else:
            current[key] = val
    
    # Ensure analyst_approval_required stays True for safety compliance
    if "multi_agent_pipeline" in current:
        current["multi_agent_pipeline"]["analyst_approval_required"] = True
        
    _write_settings_file(current)
    return current
