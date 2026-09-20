from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.sql import func
from app.core.database import Base

class Dataset(Base):
    __tablename__ = "datasets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    filepath = Column(String)
    row_count = Column(Integer, nullable=True)
    col_count = Column(Integer, nullable=True)
    columns = Column(String, nullable=True)  # JSON list
    column_types = Column(String, nullable=True)  # JSON dict
    target_column = Column(String, nullable=True)
    class_distribution = Column(String, nullable=True)  # JSON dict
    missing_counts = Column(String, nullable=True)  # JSON dict
    status = Column(String, default="uploaded")  # uploaded, preprocessed
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class MLModel(Base):
    __tablename__ = "ml_models"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    algorithm = Column(String)
    model_type = Column(String, default="classifier")  # "classifier" or "anomaly"
    dataset_id = Column(Integer, ForeignKey("datasets.id"))
    contamination = Column(Float, nullable=True)
    training_date = Column(DateTime(timezone=True), server_default=func.now())
    features = Column(String)  # JSON list
    classes = Column(String, nullable=True)  # JSON list (only for classifier)
    accuracy = Column(Float, nullable=True)
    precision_score = Column(Float, nullable=True)
    recall_score = Column(Float, nullable=True)
    f1_score = Column(Float, nullable=True)
    metrics_json = Column(String, nullable=True)  # JSON of detailed metrics
    confusion_matrix = Column(String, nullable=True)  # JSON list of lists
    feature_importance = Column(String, nullable=True)  # JSON dict
    filepath = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class DetectionJob(Base):
    __tablename__ = "detection_jobs"

    id = Column(Integer, primary_key=True, index=True)
    dataset_id = Column(Integer, ForeignKey("datasets.id"))
    model_id = Column(Integer, ForeignKey("ml_models.id"))  # Classifier ID
    anomaly_model_id = Column(Integer, nullable=True)  # Anomaly Model ID (optional)
    total_records = Column(Integer)
    benign_count = Column(Integer)
    malicious_count = Column(Integer)
    suspicious_count = Column(Integer, default=0)  # Count of anomalous records
    critical_count = Column(Integer)
    avg_confidence = Column(Float)
    avg_risk_score = Column(Float, default=0.0)  # Average combined risk score
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Threat(Base):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)
    detection_job_id = Column(Integer, ForeignKey("detection_jobs.id"))
    record_index = Column(Integer)
    record_data = Column(String)  # JSON dict representation of features
    attack_type = Column(String, index=True)  # DDoS, Mirai, or "Unknown / Suspicious"
    severity = Column(String, index=True)  # Critical, High, Medium, Low
    confidence = Column(Float)  # Classification confidence
    anomaly_score = Column(Float, nullable=True)  # Normalized anomaly score (0-100)
    risk_score = Column(Float, nullable=True)  # Unified risk score (0-100)
    anomaly_status = Column(String, nullable=True)  # "Anomalous" or "Normal"
    explanation = Column(String)  # JSON details of why (contributing features)
    recommended_actions = Column(String)  # JSON list of text recommendations
    detection_reason = Column(String, nullable=True)  # JSON list of high-level threat reasons
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class SecurityReport(Base):
    __tablename__ = "security_reports"

    id = Column(Integer, primary_key=True, index=True)
    detection_job_id = Column(Integer, ForeignKey("detection_jobs.id"))
    title = Column(String)
    summary = Column(String)  # JSON summary
    filepath = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
