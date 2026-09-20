import os
import json
import logging
from datetime import datetime
import pandas as pd
import numpy as np
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
import shutil

from app.core.config import settings
from app.core.database import get_db
import app.db.models as models
import app.db.schemas as schemas
from app.preprocessing.pipeline import inspect_csv, preprocess_dataset
from app.ml.pipeline import XGBOOST_AVAILABLE
from app.detection.engine import run_threat_detection
from app.reports.generator import generate_report_summary, export_pdf_report
from app.ml.anomaly.anomaly_service import run_anomaly_inference
from app.ml.threat_engine.threat_engine import evaluate_threat

logger = logging.getLogger(__name__)

router = APIRouter()

# ----------------- 1. HEALTH & SYSTEM STATUS -----------------
@router.get("/health", response_model=Dict[str, str])
def health_check():
    return {"status": "healthy", "service": settings.PROJECT_NAME}


@router.get("/system/status", response_model=schemas.SystemStatusResponse)
def get_system_status(db: Session = Depends(get_db)):
    # Check ML engine capability
    ml_status = "Ready" if XGBOOST_AVAILABLE else "Operational"
    ml_details = "XGBoost + Random Forest active" if XGBOOST_AVAILABLE else "Random Forest fallback active (XGBoost unavailable)"
    
    # Check database connectivity
    try:
        # Simple test query
        db.execute(models.Dataset.__table__.select().limit(1))
        db_status = "Ready"
        db_details = "SQLite DB connection active"
    except Exception as e:
        db_status = "Error"
        db_details = f"Database connection error: {str(e)}"
        
    # Check dataset directory
    ds_status = "Ready"
    ds_details = f"Uploads folder active ({len(os.listdir(settings.UPLOAD_DIR))} files)"
    
    # Check detection engine status
    # It is ready if we have at least one trained model
    try:
        model_count = db.query(models.MLModel).count()
        det_status = "Ready" if model_count > 0 else "Not Configured"
        det_details = f"{model_count} trained model(s) available for threat analysis"
    except Exception:
        det_status = "Not Configured"
        det_details = "Model schema not initialized or no models found"

    return {
        "api": {"name": "API Service", "status": "Operational", "details": "FastAPI engine online"},
        "ml_engine": {"name": "ML Engine", "status": ml_status, "details": ml_details},
        "dataset_engine": {"name": "Dataset Engine", "status": ds_status, "details": ds_details},
        "detection_engine": {"name": "Detection Engine", "status": det_status, "details": det_details}
    }


# ----------------- 2. DATASETS ENDPOINTS -----------------
@router.post("/dataset/upload", response_model=schemas.DatasetResponse, status_code=status.HTTP_201_CREATED)
def upload_dataset(file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file.filename.endswith('.csv'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file format. Only CSV files are supported."
        )
        
    # Generate path and save file
    file_uuid = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}"
    filepath = os.path.join(settings.UPLOAD_DIR, file_uuid)
    
    try:
        with open(filepath, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        logger.error(f"File save error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save uploaded file on host server."
        )
        
    # Analyze the dataset
    try:
        stats = inspect_csv(filepath)
    except Exception as e:
        # Cleanup
        if os.path.exists(filepath):
            os.remove(filepath)
        logger.error(f"CSV Parse error: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Uploaded CSV is empty or structurally malformed. Error: {str(e)}"
        )
        
    # Store metadata in DB
    db_dataset = models.Dataset(
        name=file.filename,
        filepath=filepath,
        row_count=stats["row_count"],
        col_count=stats["col_count"],
        columns=json.dumps(stats["columns"]),
        column_types=json.dumps(stats["column_types"]),
        target_column=stats["target_column"],
        class_distribution=json.dumps(stats["class_distribution"]),
        missing_counts=json.dumps(stats["missing_counts"]),
        status="uploaded"
    )
    
    db.add(db_dataset)
    db.commit()
    db.refresh(db_dataset)
    
    # Load schema fields
    db_dataset.columns = json.loads(db_dataset.columns)
    db_dataset.column_types = json.loads(db_dataset.column_types)
    db_dataset.class_distribution = json.loads(db_dataset.class_distribution)
    db_dataset.missing_counts = json.loads(db_dataset.missing_counts) if db_dataset.missing_counts else None
    
    return db_dataset


@router.get("/dataset/{id}", response_model=schemas.DatasetResponse)
def get_dataset(id: int, db: Session = Depends(get_db)):
    db_dataset = db.query(models.Dataset).filter(models.Dataset.id == id).first()
    if not db_dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")
        
    db_dataset.columns = json.loads(db_dataset.columns)
    db_dataset.column_types = json.loads(db_dataset.column_types)
    db_dataset.class_distribution = json.loads(db_dataset.class_distribution)
    db_dataset.missing_counts = json.loads(db_dataset.missing_counts) if db_dataset.missing_counts else None
    
    return db_dataset


@router.get("/datasets", response_model=List[schemas.DatasetResponse])
def list_datasets(db: Session = Depends(get_db)):
    datasets = db.query(models.Dataset).all()
    for d in datasets:
        d.columns = json.loads(d.columns)
        d.column_types = json.loads(d.column_types)
        d.class_distribution = json.loads(d.class_distribution)
        d.missing_counts = json.loads(d.missing_counts) if d.missing_counts else None
    return datasets


@router.get("/dataset/{id}/preview", response_model=List[Dict[str, Any]])
def get_dataset_preview(id: int, limit: int = 15, db: Session = Depends(get_db)):
    db_dataset = db.query(models.Dataset).filter(models.Dataset.id == id).first()
    if not db_dataset or not os.path.exists(db_dataset.filepath):
        raise HTTPException(status_code=404, detail="Dataset file not found")
        
    try:
        df = pd.read_csv(db_dataset.filepath, nrows=limit)
        # Handle nan/inf
        df = df.replace([np.inf, -np.inf], None)
        df = df.fillna(value=None)
        return df.to_dict(orient="records")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read dataset: {str(e)}")


@router.delete("/dataset/{id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_dataset(id: int, db: Session = Depends(get_db)):
    """Deletes a dataset and cascades: threats → reports → jobs → models → dataset file."""
    db_dataset = db.query(models.Dataset).filter(models.Dataset.id == id).first()
    if not db_dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")

    # Cascade cleanup
    jobs = db.query(models.DetectionJob).filter(models.DetectionJob.dataset_id == id).all()
    for job in jobs:
        db.query(models.Threat).filter(models.Threat.detection_job_id == job.id).delete()
        db.query(models.SecurityReport).filter(models.SecurityReport.detection_job_id == job.id).delete()
    db.query(models.DetectionJob).filter(models.DetectionJob.dataset_id == id).delete()
    db.query(models.MLModel).filter(models.MLModel.dataset_id == id).delete()

    # Remove CSV file from disk
    if db_dataset.filepath and os.path.exists(db_dataset.filepath):
        try:
            os.remove(db_dataset.filepath)
        except Exception as e:
            logger.warning(f"Could not delete file {db_dataset.filepath}: {e}")

    db.delete(db_dataset)
    db.commit()
    return None


@router.post("/preprocess/{id}", response_model=Dict[str, Any])
def run_preprocess_endpoint(id: int, config: schemas.PreprocessConfig, db: Session = Depends(get_db)):
    db_dataset = db.query(models.Dataset).filter(models.Dataset.id == id).first()
    if not db_dataset or not os.path.exists(db_dataset.filepath):
        raise HTTPException(status_code=404, detail="Dataset not found")
        
    # Execute preprocessing
    try:
        _, _, _, _, summary = preprocess_dataset(
            db_dataset.filepath,
            target_column=config.target_column,
            train_split=config.train_test_split
        )
        
        # Update target column
        db_dataset.target_column = config.target_column
        db_dataset.status = "preprocessed"
        db.commit()
        
        return summary
    except Exception as e:
        logger.error(f"Preprocessing failed: {e}")
        raise HTTPException(status_code=400, detail=f"Data preprocessing failed: {str(e)}")




@router.post("/predict", response_model=Dict[str, Any])
def predict_endpoint(record: Dict[str, Any]):
    try:
        from app.ml.predict_pipeline import predict_tuned
        return predict_tuned(record)
    except FileNotFoundError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Prediction failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/predict/explain", response_model=Dict[str, Any])
def explain_endpoint(record: Dict[str, Any]):
    try:
        from app.ml.predict_pipeline import explain_prediction
        return explain_prediction(record, top_k=5)
    except FileNotFoundError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"SHAP explanation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/model/{id}", response_model=schemas.MLModelResponse)
def get_model(id: int, db: Session = Depends(get_db)):
    db_model = db.query(models.MLModel).filter(models.MLModel.id == id).first()
    if not db_model:
        raise HTTPException(status_code=404, detail="Model not found")
        
    db_model.features = json.loads(db_model.features)
    db_model.classes = json.loads(db_model.classes) if db_model.classes else None
    db_model.metrics_json = json.loads(db_model.metrics_json) if db_model.metrics_json else None
    db_model.confusion_matrix = json.loads(db_model.confusion_matrix) if db_model.confusion_matrix else None
    db_model.feature_importance = json.loads(db_model.feature_importance) if db_model.feature_importance else {}
    
    return db_model


@router.get("/models", response_model=List[schemas.MLModelResponse])
def list_models(db: Session = Depends(get_db)):
    models_list = db.query(models.MLModel).all()
    for m in models_list:
        m.features = json.loads(m.features)
        m.classes = json.loads(m.classes) if m.classes else None
        m.metrics_json = json.loads(m.metrics_json) if m.metrics_json else None
        m.confusion_matrix = json.loads(m.confusion_matrix) if m.confusion_matrix else None
        m.feature_importance = json.loads(m.feature_importance) if m.feature_importance else {}
    return models_list


# ----------------- 4. DETECTION RUNS -----------------
@router.post("/detect", response_model=schemas.DetectionResult)
def execute_detection(payload: schemas.DetectionRequest, db: Session = Depends(get_db)):
    db_dataset = db.query(models.Dataset).filter(models.Dataset.id == payload.dataset_id).first()
    db_model = db.query(models.MLModel).filter(models.MLModel.id == payload.model_id).first()
    
    if not db_dataset or not os.path.exists(db_dataset.filepath):
        raise HTTPException(status_code=404, detail="Dataset file not found.")
    if not db_model or not os.path.exists(db_model.filepath):
        raise HTTPException(status_code=404, detail="ML Model file not found.")
        
    try:
        # Load dataset
        df = pd.read_csv(db_dataset.filepath)
        
        # Load model features metadata
        model_features = json.loads(db_model.features)
        
        # Check if features exist
        missing = [f for f in model_features if f not in df.columns]
        if missing:
            raise HTTPException(
                status_code=400,
                detail=f"The selected dataset is missing columns required by the model: {missing}"
            )
            
        # 1. Run Supervised Classification
        classification_summary, supervised_threats = run_threat_detection(
            model_filepath=db_model.filepath,
            dataset_df=df[model_features],
            original_df=df
        )
        
        # 2. Run Unsupervised Anomaly Detection
        # Check if anomaly_model_id is provided, otherwise look up the latest trained anomaly model for this dataset
        anomaly_model = None
        if payload.anomaly_model_id:
            anomaly_model = db.query(models.MLModel).filter(
                models.MLModel.id == payload.anomaly_model_id,
                models.MLModel.model_type == "anomaly"
            ).first()
        else:
            anomaly_model = db.query(models.MLModel).filter(
                models.MLModel.dataset_id == db_dataset.id,
                models.MLModel.model_type == "anomaly"
            ).order_by(models.MLModel.id.desc()).first()
            
        # If no anomaly model trained yet, train a default one on the fly (contamination=0.05)
        if not anomaly_model:
            logger.info("No anomaly model found for dataset. Training default Isolation Forest on the fly...")
            anomaly_model = train_and_save_anomaly_model(
                dataset_id=db_dataset.id,
                contamination=0.05,
                db=db
            )
            
        anomaly_statuses, anomaly_scores = run_anomaly_inference(
            model_filepath=anomaly_model.filepath,
            df=df
        )
        
        # 3. Calculate Benign Stats Baseline for feature deviation (based on classifier predictions)
        benign_stats = {}
        # Find which columns are numeric features
        numeric_features = df[model_features].select_dtypes(include=['number']).columns.tolist()
        
        benign_indices = [
            i for i, t in enumerate(supervised_threats) 
            if t["attack_type"].lower() in ["benign", "normal"]
        ]
        
        if benign_indices:
            benign_df = df.iloc[benign_indices][numeric_features]
        else:
            benign_df = df[numeric_features]
            
        for col in numeric_features:
            benign_stats[col] = {
                "mean": float(benign_df[col].mean()),
                "std": float(benign_df[col].std() if len(benign_df) > 1 else 1.0)
            }
            
        # Extract global feature importance
        feature_importance = json.loads(db_model.feature_importance) if db_model.feature_importance else {}
        
        # 4. Process records through the Threat Intelligence Engine
        combined_threats = []
        total_records = len(df)
        
        for idx in range(total_records):
            sup_t = supervised_threats[idx]
            orig_record = df.iloc[idx].to_dict()
            
            # Map original values to serializable types
            record_data_serializable = {}
            for col_name, val in orig_record.items():
                if pd.isna(val):
                    record_data_serializable[col_name] = None
                elif isinstance(val, (np.integer, int)):
                    record_data_serializable[col_name] = int(val)
                elif isinstance(val, (np.floating, float)):
                    record_data_serializable[col_name] = float(val)
                else:
                    record_data_serializable[col_name] = str(val)
            
            # Run engine evaluation
            eval_result = evaluate_threat(
                predicted_attack=sup_t["attack_type"],
                confidence=sup_t["confidence"],
                anomaly_status=anomaly_statuses[idx],
                anomaly_score=anomaly_scores[idx],
                record_data=record_data_serializable,
                benign_stats=benign_stats,
                feature_importance=feature_importance
            )
            
            # Build unified threat response
            combined_threats.append({
                "record_index": idx,
                "record_data": record_data_serializable,
                "attack_type": eval_result["attack_type"],
                "severity": eval_result["severity"],
                "confidence": eval_result["confidence"],
                "anomaly_score": eval_result["anomaly_score"],
                "risk_score": eval_result["risk_score"],
                "anomaly_status": eval_result["anomaly_status"],
                "explanation": {
                    "summary": eval_result["scenario_description"] or f"Classified as {eval_result['attack_type']} traffic.",
                    "details": eval_result["reasons"]
                },
                "recommended_actions": sup_t["recommended_actions"],
                "detection_reason": eval_result["reasons"]
            })
            
        # 5. Save detection job summary
        benign_count = sum(1 for t in combined_threats if t["severity"] == "Low")
        suspicious_count = sum(1 for t in combined_threats if t["severity"] == "Medium")
        malicious_count = sum(1 for t in combined_threats if t["severity"] in ["High", "Critical"])
        critical_count = sum(1 for t in combined_threats if t["severity"] == "Critical")
        avg_risk = float(np.mean([t["risk_score"] for t in combined_threats]))
        avg_conf = float(np.mean([t["confidence"] for t in combined_threats]))
        
        db_job = models.DetectionJob(
            dataset_id=db_dataset.id,
            model_id=db_model.id,
            anomaly_model_id=anomaly_model.id,
            total_records=total_records,
            benign_count=benign_count,
            malicious_count=malicious_count,
            suspicious_count=suspicious_count,
            critical_count=critical_count,
            avg_confidence=avg_conf,
            avg_risk_score=avg_risk
        )
        db.add(db_job)
        db.commit()
        db.refresh(db_job)
        
        # 6. Save threat logs (all Medium/High/Criticals + sample of Lows to keep DB small)
        saved_threats = []
        lows_saved = 0
        for t in combined_threats:
            is_low = t["severity"] == "Low"
            if not is_low or lows_saved < 150:
                if is_low:
                    lows_saved += 1
                    
                db_threat = models.Threat(
                    detection_job_id=db_job.id,
                    record_index=t["record_index"],
                    record_data=json.dumps(t["record_data"]),
                    attack_type=t["attack_type"],
                    severity=t["severity"],
                    confidence=t["confidence"],
                    anomaly_score=t["anomaly_score"],
                    risk_score=t["risk_score"],
                    anomaly_status=t["anomaly_status"],
                    explanation=json.dumps(t["explanation"]),
                    recommended_actions=json.dumps(t["recommended_actions"]),
                    detection_reason=json.dumps(t["detection_reason"])
                )
                db.add(db_threat)
                saved_threats.append(db_threat)
                
        db.commit()
        
        # Load relationships for schemas
        response_threats = []
        for st in saved_threats:
            db.refresh(st)
            st.record_data = json.loads(st.record_data)
            st.explanation = json.loads(st.explanation)
            st.recommended_actions = json.loads(st.recommended_actions)
            st.detection_reason = json.loads(st.detection_reason) if st.detection_reason else []
            response_threats.append(st)
            
        # Parse Pydantic
        job_resp = schemas.DetectionJobResponse.from_orm(db_job)
        
        return {
            "job": job_resp,
            "threats": response_threats
        }
        
    except Exception as e:
        logger.error(f"Inference run failed: {e}")
        raise HTTPException(status_code=500, detail=f"Threat detection execution failed: {str(e)}")


@router.get("/threats", response_model=List[schemas.ThreatResponse])
def get_threats(detection_job_id: Optional[int] = None, severity: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(models.Threat)
    if detection_job_id is not None:
        query = query.filter(models.Threat.detection_job_id == detection_job_id)
    if severity is not None:
        query = query.filter(models.Threat.severity == severity)
        
    threats = query.order_by(models.Threat.id.desc()).limit(500).all()
    for t in threats:
        t.record_data = json.loads(t.record_data)
        t.explanation = json.loads(t.explanation)
        t.recommended_actions = json.loads(t.recommended_actions)
        t.detection_reason = json.loads(t.detection_reason) if t.detection_reason else []
    return threats


@router.get("/threats/{id}", response_model=schemas.ThreatResponse)
def get_threat_details(id: int, db: Session = Depends(get_db)):
    t = db.query(models.Threat).filter(models.Threat.id == id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Threat record not found")
    t.record_data = json.loads(t.record_data)
    t.explanation = json.loads(t.explanation)
    t.recommended_actions = json.loads(t.recommended_actions)
    t.detection_reason = json.loads(t.detection_reason) if t.detection_reason else []
    return t


@router.get("/threats/{id}/explain")
def explain_threat(id: int, db: Session = Depends(get_db)):
    """Returns per-feature contribution scores for a specific threat record,
    using the classifier model's stored feature_importance weights combined
    with the record's actual feature values."""
    t = db.query(models.Threat).filter(models.Threat.id == id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Threat record not found")

    record_data = json.loads(t.record_data)
    explanation = json.loads(t.explanation)
    detection_reason = json.loads(t.detection_reason) if t.detection_reason else []
    recommended_actions = json.loads(t.recommended_actions)

    # Fetch the classifier model's feature_importance from the detection job
    job = db.query(models.DetectionJob).filter(models.DetectionJob.id == t.detection_job_id).first()
    feature_importance: Dict[str, float] = {}
    if job:
        model = db.query(models.MLModel).filter(
            models.MLModel.id == job.model_id,
            models.MLModel.model_type == "classifier"
        ).first()
        if model and model.feature_importance:
            feature_importance = json.loads(model.feature_importance)

    # Build per-feature contribution scores
    # contribution = global_importance_weight * |normalized_feature_value|
    numeric_features = {
        k: v for k, v in record_data.items()
        if isinstance(v, (int, float)) and v is not None
    }
    max_val = max((abs(v) for v in numeric_features.values() if v != 0), default=1.0)

    contributions = []
    for feat, raw_val in numeric_features.items():
        importance = feature_importance.get(feat, 0.0)
        normalized = abs(raw_val) / max_val if max_val > 0 else 0.0
        contribution = round(importance * normalized * 100, 3)
        direction = "HIGH" if raw_val > 0 else "LOW"
        contributions.append({
            "feature": feat,
            "value": raw_val,
            "importance": round(importance, 4),
            "contribution": contribution,
            "direction": direction
        })

    contributions.sort(key=lambda x: x["contribution"], reverse=True)

    return {
        "threat_id": t.id,
        "record_index": t.record_index,
        "attack_type": t.attack_type,
        "severity": t.severity,
        "risk_score": t.risk_score,
        "anomaly_score": t.anomaly_score,
        "anomaly_status": t.anomaly_status,
        "confidence": t.confidence,
        "feature_contributions": contributions,
        "explanation": explanation,
        "detection_reason": detection_reason,
        "recommended_actions": recommended_actions
    }


# ----------------- 5. SECURITY REPORTS -----------------
@router.post("/reports/generate", response_model=schemas.ReportResponse)
def generate_report_endpoint(detection_job_id: int, db: Session = Depends(get_db)):
    job = db.query(models.DetectionJob).filter(models.DetectionJob.id == detection_job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Detection job not found")
        
    dataset = db.query(models.Dataset).filter(models.Dataset.id == job.dataset_id).first()
    model = db.query(models.MLModel).filter(models.MLModel.id == job.model_id).first()
    
    # Load associated threats
    threats = db.query(models.Threat).filter(models.Threat.detection_job_id == job.id).all()
    threats_parsed = []
    for t in threats:
        threats_parsed.append({
            "record_index": t.record_index,
            "attack_type": t.attack_type,
            "severity": t.severity,
            "confidence": t.confidence,
            "recommended_actions": json.loads(t.recommended_actions)
        })
        
    # Build report summaries
    summary = generate_report_summary(
        dataset_name=dataset.name if dataset else "Unknown",
        model_name=model.name if model else "Unknown",
        algorithm=model.algorithm if model else "Unknown",
        accuracy=model.accuracy if model else 0.0,
        detection_summary={
            "total_records": job.total_records,
            "benign_count": job.benign_count,
            "malicious_count": job.malicious_count,
            "critical_count": job.critical_count
        },
        threats=threats_parsed
    )
    
    # Define PDF filename and path
    pdf_filename = f"report_job_{job.id}.pdf"
    pdf_filepath = os.path.join(settings.UPLOAD_DIR, pdf_filename)
    
    try:
        actual_path = export_pdf_report(summary, pdf_filepath)
    except Exception as e:
        logger.error(f"Failed to generate report file: {e}")
        actual_path = None
        
    db_report = models.SecurityReport(
        detection_job_id=job.id,
        title=f"Security Assessment Report for {dataset.name if dataset else 'IoT Devices'}",
        summary=json.dumps(summary),
        filepath=actual_path
    )
    db.add(db_report)
    db.commit()
    db.refresh(db_report)
    
    db_report.summary = json.loads(db_report.summary)
    return db_report


@router.get("/reports", response_model=List[schemas.ReportResponse])
def list_reports(db: Session = Depends(get_db)):
    reports = db.query(models.SecurityReport).order_by(models.SecurityReport.id.desc()).all()
    for r in reports:
        r.summary = json.loads(r.summary)
    return reports


@router.get("/report/{id}/download")
def download_report(id: int, db: Session = Depends(get_db)):
    report = db.query(models.SecurityReport).filter(models.SecurityReport.id == id).first()
    if not report or not report.filepath or not os.path.exists(report.filepath):
        raise HTTPException(status_code=404, detail="PDF Report file not found")
        
    media_type = "application/pdf" if report.filepath.endswith(".pdf") else "application/json"
    filename = os.path.basename(report.filepath)
    
    return FileResponse(
        path=report.filepath,
        media_type=media_type,
        filename=filename
    )


# ----------------- 6. UNPACKED ANOMALY ENDPOINTS -----------------
@router.post("/anomaly/train", response_model=schemas.MLModelResponse)
def train_anomaly_model_endpoint(payload: schemas.AnomalyModelTrainRequest, db: Session = Depends(get_db)):
    try:
        db_model = train_and_save_anomaly_model(
            dataset_id=payload.dataset_id,
            contamination=payload.contamination,
            db=db
        )
        
        # Parse list metrics for Pydantic response parsing
        db_model.features = json.loads(db_model.features)
        db_model.metrics_json = json.loads(db_model.metrics_json)
        return db_model
    except Exception as e:
        logger.error(f"Anomaly model training failed: {e}")
        raise HTTPException(status_code=500, detail=f"Anomaly training failed: {str(e)}")


@router.get("/anomaly/model/{id}", response_model=schemas.MLModelResponse)
def get_anomaly_model(id: int, db: Session = Depends(get_db)):
    db_model = db.query(models.MLModel).filter(
        models.MLModel.id == id,
        models.MLModel.model_type == "anomaly"
    ).first()
    if not db_model:
        raise HTTPException(status_code=404, detail="Anomaly detector model not found")
        
    db_model.features = json.loads(db_model.features)
    db_model.metrics_json = json.loads(db_model.metrics_json)
    return db_model


# ----------------- 7. ANALYTICS (DASHBOARD) -----------------
@router.get("/analytics", response_model=Dict[str, Any])
def get_dashboard_analytics(db: Session = Depends(get_db)):
    latest_job = db.query(models.DetectionJob).order_by(models.DetectionJob.id.desc()).first()
    total_datasets = db.query(models.Dataset).count()
    total_models = db.query(models.MLModel).count()
    
    # Defaults
    total_records = 0
    threats_detected = 0
    suspicious_detected = 0
    critical_threats = 0
    benign_count = 0
    avg_confidence = 0.0
    avg_risk_score = 0.0
    threat_distribution = {}
    severity_distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    risk_distribution = {"0-25": 0, "26-50": 0, "51-75": 0, "76-100": 0}
    dual_detection = {"ClassifierOnly": 0, "AnomalousOnly": 0, "Both": 0, "TotalAnomalies": 0}
    detection_trend = []
    
    if latest_job:
        total_records = latest_job.total_records
        threats_detected = latest_job.malicious_count
        suspicious_detected = latest_job.suspicious_count
        benign_count = latest_job.benign_count
        critical_threats = latest_job.critical_count
        avg_confidence = latest_job.avg_confidence
        avg_risk_score = latest_job.avg_risk_score
        
        # Load threats from this job for breakdowns
        threats = db.query(models.Threat).filter(models.Threat.detection_job_id == latest_job.id).all()
        for t in threats:
            attack = t.attack_type
            sev = t.severity
            risk = t.risk_score or 0.0
            anomaly_stat = t.anomaly_status or "Normal"
            
            # Threat Distribution
            threat_distribution[attack] = threat_distribution.get(attack, 0) + 1
            
            # Severity Distribution
            severity_distribution[sev] = severity_distribution.get(sev, 0) + 1
            
            # Risk Distribution (0-25 Low, 26-50 Medium, 51-75 High, 76-100 Critical)
            if risk < 25.0:
                risk_distribution["0-25"] += 1
            elif risk <= 50.0:
                risk_distribution["26-50"] += 1
            elif risk <= 75.0:
                risk_distribution["51-75"] += 1
            else:
                risk_distribution["76-100"] += 1
                
            # Dual Detection Aggregation (Section 10)
            is_classifier_malicious = attack.lower() not in ["benign", "normal", "unknown / suspicious"]
            is_anomalous = anomaly_stat == "Anomalous"
            
            if is_anomalous:
                dual_detection["TotalAnomalies"] += 1
                
            if is_classifier_malicious and is_anomalous:
                dual_detection["Both"] += 1
            elif is_classifier_malicious:
                dual_detection["ClassifierOnly"] += 1
            elif is_anomalous:
                dual_detection["AnomalousOnly"] += 1
                
        # Fill in counts for non-saved benign/low risk elements if they exist
        saved_count = len(threats)
        unsaved_benign = max(0, total_records - saved_count)
        
        # Add remaining benigns to low risk
        risk_distribution["0-25"] += unsaved_benign
        severity_distribution["Low"] += unsaved_benign
        if "Benign" not in threat_distribution:
            threat_distribution["Benign"] = 0
        threat_distribution["Benign"] += benign_count
        
        # Detection Trend
        chunk_size = max(1, total_records // 10)
        chunks = []
        for i in range(0, total_records, chunk_size):
            end_idx = min(i + chunk_size, total_records)
            chunk_threats = db.query(models.Threat).filter(
                models.Threat.detection_job_id == latest_job.id,
                models.Threat.record_index >= i,
                models.Threat.record_index < end_idx,
                ~models.Threat.attack_type.in_(["Benign", "Normal"])
            ).count()
            chunks.append({
                "range": f"{i}-{end_idx}",
                "threats": chunk_threats
            })
        detection_trend = chunks

    # Model accuracy
    current_model = None
    last_analysis_time = None
    if latest_job:
        model = db.query(models.MLModel).filter(models.MLModel.id == latest_job.model_id).first()
        if model:
            current_model = f"{model.name} ({model.algorithm})"
        last_analysis_time = latest_job.created_at.strftime("%Y-%m-%d %H:%M:%S")

    return {
        "total_records": total_records,
        "threats_detected": threats_detected,
        "suspicious_detected": suspicious_detected,
        "critical_threats": critical_threats,
        "avg_confidence": avg_confidence,
        "avg_risk_score": avg_risk_score,
        "benign_count": benign_count,
        "malicious_count": threats_detected,
        "total_datasets": total_datasets,
        "total_models": total_models,
        "current_model": current_model,
        "last_analysis_time": last_analysis_time,
        "threat_distribution": threat_distribution,
        "severity_distribution": severity_distribution,
        "risk_distribution": risk_distribution,
        "dual_detection": dual_detection,
        "detection_trend": detection_trend
    }

