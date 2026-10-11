import os
import json
import logging
import joblib
import pandas as pd
import numpy as np
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

    The saved artifact now includes 'score_calibration' (ref_min / ref_max)
    derived from training-data decision scores so that run_anomaly_inference()
    can produce a mathematically consistent 0-100 anomaly score at test time.
    """
    ds = db.query(models.Dataset).filter(models.Dataset.id == dataset_id).first()
    if not ds or not os.path.exists(ds.filepath):
        raise FileNotFoundError(f"Dataset #{dataset_id} file not found.")

    # Standard preprocessing → correct feature matrix
    X_train, X_test, y_train, y_test, prep_summary = preprocess_dataset(
        ds.filepath,
        target_column=ds.target_column,
        train_split=0.8
    )

    # Isolation Forest trains on numeric features only (no target label)
    numeric_features = X_train.select_dtypes(include=['number']).columns.tolist()
    X_full = pd.concat([X_train, X_test])[numeric_features]

    # Ground truth for optional evaluation
    y_full_labels = pd.concat([y_train, y_test])
    classes_list = prep_summary["classes"]
    y_ground_truth_str = pd.Series([classes_list[idx] for idx in y_full_labels])

    # Train — returns model, scaler, and metrics including score_calibration
    model, scaler, metrics = train_anomaly_detector(
        X=X_full,
        contamination=contamination,
        y_ground_truth=y_ground_truth_str
    )

    # Define save path
    model_name = f"anomaly_ds_{ds.id}_isolation_forest"
    model_uuid = f"anomaly_{ds.id}_{contamination}.joblib"
    model_filepath = os.path.join(settings.MODEL_DIR, model_uuid)

    # Build artifact — include calibration bounds so inference can use them
    calibration = metrics.get("score_calibration", {})
    artifact = {
        "model": model,
        "scaler": scaler,
        "features": numeric_features,
        "contamination": contamination,
        "metrics": metrics,
        # Top-level convenience fields for fast access in run_anomaly_inference
        "score_ref_min": calibration.get("ref_min"),
        "score_ref_max": calibration.get("ref_max"),
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
        accuracy=metrics.get("ground_truth_evaluation", {}).get("f1_score", 0.0),
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
    Loads saved anomaly model, standardizes incoming dataframe on the same
    features, and returns anomaly statuses and normalized anomaly scores.

    Uses the calibration bounds (ref_min / ref_max) stored in the artifact at
    train time so the 0-100 score is consistent with training-time scores.
    """
    if not os.path.exists(model_filepath):
        raise FileNotFoundError(f"Anomaly model file not found: {model_filepath}")

    artifact = joblib.load(model_filepath)
    model: object = artifact["model"]
    scaler = artifact["scaler"]
    features: List[str] = artifact["features"]

    # Retrieve stored calibration bounds (may be None for legacy artifacts)
    ref_min: float = artifact.get("score_ref_min")
    ref_max: float = artifact.get("score_ref_max")

    if ref_min is None or ref_max is None:
        logger.warning(
            "Anomaly artifact missing score_calibration bounds (legacy artifact). "
            "Falling back to observed range of inference-time scores — "
            "scores may not be directly comparable to training-time scores. "
            "Re-train the anomaly model to get calibrated bounds."
        )

    # Align features
    missing = [f for f in features if f not in df.columns]
    if missing:
        raise ValueError(
            f"Dataset is missing features required by anomaly model: {missing}"
        )

    X = df[features].copy()

    # Clean NaNs / Infs
    X = X.replace([float('inf'), float('-inf')], float('nan'))
    for col in X.columns:
        median_val = X[col].median()
        X[col] = X[col].fillna(median_val if not pd.isna(median_val) else 0.0)

    # Scale features
    X_scaled = scaler.transform(X)

    # Predict
    preds = model.predict(X_scaled)
    decision_scores = model.decision_function(X_scaled)

    # Normalize using stored calibration bounds (or observed range as fallback)
    norm_scores = normalize_anomaly_scores(
        decision_scores,
        ref_min=ref_min,
        ref_max=ref_max
    ).tolist()

    statuses = ["Anomalous" if p == -1 else "Normal" for p in preds]

    return statuses, norm_scores
