import os
import json
import logging
import joblib
import pandas as pd
from typing import Dict, Any, List, Tuple
from sqlalchemy.orm import Session

from app.core.config import settings
import app.db.models as models
from app.preprocessing.pipeline import preprocess_dataset
from app.ml.anomaly.isolation_forest import train_anomaly_detector, normalize_anomaly_scores

logger = logging.getLogger(__name__)

def train_and_save_anomaly_model(
    dataset_id: int,
    contamination: float,
    db: Session
) -> models.MLModel:
    """
    Service to preprocess dataset, train Isolation Forest, save artifact,
    and insert model record in database.
    """
    ds = db.query(models.Dataset).filter(models.Dataset.id == dataset_id).first()
    if not ds or not os.path.exists(ds.filepath):
        raise FileNotFoundError(f"Dataset #{dataset_id} file not found.")
        
    # Run standard preprocessing to extract correct feature matrix
    X_train, X_test, y_train, y_test, prep_summary = preprocess_dataset(
        ds.filepath,
        target_column=ds.target_column,
        train_split=0.8
    )
    
    # Isolation Forest only trains on features (no target labels!)
    # X_train already has dropped identifiers and target label column excluded!
    # Ensure all columns are numeric
    numeric_features = X_train.select_dtypes(include=['number']).columns.tolist()
    X_numeric = X_train[numeric_features]
    
    # Ground truth classes for evaluating anomaly accuracy
    y_full_labels = pd.concat([y_train, y_test])
    # Convert encoded label ints back to strings
    classes_list = prep_summary["classes"]
    y_ground_truth_str = pd.Series([classes_list[idx] for idx in y_full_labels])
    
    # Train anomaly model
    # We train on full X to get overall contamination statistics
    X_full = pd.concat([X_train, X_test])[numeric_features]
    
    model, scaler, metrics = train_anomaly_detector(
        X=X_full,
        contamination=contamination,
        y_ground_truth=y_ground_truth_str
    )
    
    # Define save path
    model_name = f"anomaly_ds_{ds.id}_isolation_forest"
    model_uuid = f"anomaly_{ds.id}_{contamination}.joblib"
    model_filepath = os.path.join(settings.MODEL_DIR, model_uuid)
    
    # Save model artifact
    artifact = {
        "model": model,
        "scaler": scaler,
        "features": numeric_features,
        "contamination": contamination,
        "metrics": metrics
    }
    joblib.dump(artifact, model_filepath)
    logger.info(f"Anomaly model saved to {model_filepath}")
    
    # Insert in DB
    db_model = models.MLModel(
        name=model_name,
        algorithm="Isolation Forest",
        model_type="anomaly",
        dataset_id=ds.id,
        contamination=contamination,
        features=json.dumps(numeric_features),
        accuracy=metrics.get("ground_truth_evaluation", {}).get("f1_score", 0.0), # Save F1 as main accuracy proxy
        metrics_json=json.dumps(metrics),
        filepath=model_filepath
    )
    db.add(db_model)
    db.commit()
    db.refresh(db_model)
    
    return db_model

def run_anomaly_inference(
    model_filepath: str,
    df: pd.DataFrame
) -> Tuple[List[str], List[float]]:
    """
    Loads saved anomaly model, standardizes incoming dataframe on same features,
    and returns list of anomaly statuses and normalized anomaly scores.
    """
    if not os.path.exists(model_filepath):
        raise FileNotFoundError(f"Anomaly model file not found: {model_filepath}")
        
    artifact = joblib.load(model_filepath)
    model = artifact["model"]
    scaler = artifact["scaler"]
    features = artifact["features"]
    
    # Align features (ensure numeric columns exist and are sorted)
    missing = [f for f in features if f not in df.columns]
    if missing:
        raise ValueError(f"Dataset is missing features required by anomaly model: {missing}")
        
    X = df[features].copy()
    
    # Impute NaNs and Infs
    X = X.replace([float('inf'), float('-inf')], float('nan'))
    for col in X.columns:
        X[col] = X[col].fillna(X[col].median() if not pd.isna(X[col].median()) else 0.0)
        
    # Scale features
    X_scaled = scaler.transform(X)
    
    # Predict
    preds = model.predict(X_scaled)
    decision_scores = model.decision_function(X_scaled)
    
    # Normalize scores
    norm_scores = normalize_anomaly_scores(decision_scores).tolist()
    
    # Statuses
    statuses = ["Anomalous" if p == -1 else "Normal" for p in preds]
    
    return statuses, norm_scores
