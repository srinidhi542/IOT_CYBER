from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime

# Dataset schemas
class DatasetBase(BaseModel):
    name: str

class DatasetResponse(DatasetBase):
    id: int
    filepath: str
    row_count: Optional[int] = None
    col_count: Optional[int] = None
    columns: Optional[List[str]] = None
    column_types: Optional[Dict[str, str]] = None
    target_column: Optional[str] = None
    class_distribution: Optional[Dict[str, int]] = None
    status: str
    created_at: datetime

    class Config:
        from_attributes = True

# Preprocess settings
class PreprocessConfig(BaseModel):
    target_column: str
    train_test_split: float = Field(0.8, ge=0.5, le=0.95)

# MLModel schemas
class MLModelTrainRequest(BaseModel):
    dataset_id: int
    algorithm: str = "XGBoost"  # "XGBoost" or "Random Forest"
    train_split: float = 0.8

class AnomalyModelTrainRequest(BaseModel):
    dataset_id: int
    contamination: float = Field(0.05, ge=0.01, le=0.50)

class MLModelResponse(BaseModel):
    id: int
    name: str
    algorithm: str
    model_type: str  # "classifier" or "anomaly"
    dataset_id: int
    contamination: Optional[float] = None
    training_date: datetime
    features: List[str]
    classes: Optional[List[str]] = None
    accuracy: Optional[float] = None
    precision_score: Optional[float] = None
    recall_score: Optional[float] = None
    f1_score: Optional[float] = None
    metrics_json: Optional[Dict[str, Any]] = None
    confusion_matrix: Optional[List[List[int]]] = None
    feature_importance: Optional[Dict[str, float]] = None
    created_at: datetime

    class Config:
        from_attributes = True

# Threat schemas
class ThreatResponse(BaseModel):
    id: int
    detection_job_id: int
    record_index: int
    record_data: Dict[str, Any]
    attack_type: str
    severity: str
    confidence: float
    anomaly_score: Optional[float] = None
    risk_score: Optional[float] = None
    anomaly_status: Optional[str] = None
    explanation: Dict[str, Any]
    recommended_actions: List[str]
    detection_reason: Optional[List[str]] = None
    created_at: datetime

    class Config:
        from_attributes = True

# Detection schemas
class DetectionJobResponse(BaseModel):
    id: int
    dataset_id: int
    model_id: int
    anomaly_model_id: Optional[int] = None
    total_records: int
    benign_count: int
    malicious_count: int
    suspicious_count: int
    critical_count: int
    avg_confidence: float
    avg_risk_score: float
    created_at: datetime

    class Config:
        from_attributes = True

class DetectionRequest(BaseModel):
    dataset_id: int
    model_id: int
    anomaly_model_id: Optional[int] = None

class DetectionResult(BaseModel):
    job: DetectionJobResponse
    threats: List[ThreatResponse]

# Report schemas
class ReportResponse(BaseModel):
    id: int
    detection_job_id: int
    title: str
    summary: Dict[str, Any]
    filepath: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True

# System status
class ComponentStatus(BaseModel):
    name: str
    status: str  # "Operational", "Ready", "Error", "Not Configured"
    details: Optional[str] = None

class SystemStatusResponse(BaseModel):
    api: ComponentStatus
    ml_engine: ComponentStatus
    dataset_engine: ComponentStatus
    detection_engine: ComponentStatus
