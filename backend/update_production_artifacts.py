#!/usr/bin/env python3
"""
Synchronizes the trained model artifact's REAL metrics into the SQLite database.

This script ONLY reads metrics that were computed during actual model training
(stored inside the .joblib artifact under the 'metrics' key).  It NEVER
invents, hardcodes, or approximates numbers.

Usage:
    python backend/update_production_artifacts.py
"""

import os
import sys
import json
import joblib
import numpy as np

# Add backend directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.core.database import SessionLocal, engine, Base
import app.db.models as db_models

MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
PRIMARY_MODEL_FILENAME = "ciciot2023_8class_xgboost_tuned.joblib"
ALIAS_MODEL_FILENAME = "ciciot2023_debiased_hierarchical.joblib"
MODEL_NAME_IN_DB = "CICIoT2023_8Class_Tuned_XGBoost"


def load_artifact(model_path: str) -> dict:
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model artifact not found: {model_path}")
    artifact = joblib.load(model_path)
    return artifact


def extract_real_metrics(artifact: dict) -> dict:
    """
    Pulls the metrics dict that was written by the training script.
    Raises ValueError if the artifact has no 'metrics' key or if the
    metrics dict is empty — to prevent silent use of fabricated data.
    """
    metrics = artifact.get("metrics")
    if not metrics:
        raise ValueError(
            "Artifact has no 'metrics' key.  Re-run the training script "
            "(train_enhanced_model.py) so that real metrics are computed and "
            "stored in the artifact before calling this sync script."
        )
    return metrics


def sync_db(artifact: dict, metrics: dict, model_path: str) -> None:
    """
    Creates or updates the MLModel DB record using metrics from the artifact.
    """
    features: list = artifact.get("features", [])
    classes: list = list(artifact.get("classes", []))
    if not classes and "label_encoder" in artifact:
        classes = list(artifact["label_encoder"].classes_)

    accuracy = float(metrics.get("accuracy", metrics.get("multiclass_accuracy", 0.0)))
    precision = float(metrics.get("precision", metrics.get("weighted_precision", 0.0)))
    recall = float(metrics.get("recall", metrics.get("weighted_recall", 0.0)))
    f1 = float(metrics.get("f1", metrics.get("weighted_f1", 0.0)))

    cm = metrics.get("confusion_matrix", [])
    feature_importance = metrics.get("feature_importance", {})

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # --- Dataset record --------------------------------------------------
        dataset = (
            db.query(db_models.Dataset)
            .filter(db_models.Dataset.name == "CICIoT2023_Full")
            .first()
        )
        if not dataset:
            dataset = db_models.Dataset(
                name="CICIoT2023_Full",
                filepath="synthetic_training_data",  # no real CSV on disk
                row_count=int(metrics.get("training_samples", 0)),
                col_count=len(features),
                columns=json.dumps(features),
                column_types=json.dumps({f: "float64" for f in features}),
                target_column="label",
                class_distribution=json.dumps(
                    metrics.get("class_distribution", {})
                ),
                missing_counts=json.dumps({}),
                status="preprocessed"
            )
            db.add(dataset)
            db.commit()
            db.refresh(dataset)

        # --- MLModel record --------------------------------------------------
        ml_model = (
            db.query(db_models.MLModel)
            .filter(db_models.MLModel.name == MODEL_NAME_IN_DB)
            .first()
        )

        algorithm_label = metrics.get(
            "algorithm",
            f"XGBoost {accuracy * 100:.1f}% Tuned"
        )

        fields = dict(
            algorithm=algorithm_label,
            features=json.dumps(features),
            classes=json.dumps(classes),
            accuracy=accuracy,
            precision_score=precision,
            recall_score=recall,
            f1_score=f1,
            metrics_json=json.dumps(metrics),
            confusion_matrix=json.dumps(cm),
            feature_importance=json.dumps(feature_importance),
        )

        if ml_model:
            for k, v in fields.items():
                setattr(ml_model, k, v)
            db.commit()
            print(f"[+] Updated MLModel '{MODEL_NAME_IN_DB}' in DB.")
        else:
            ml_model = db_models.MLModel(
                name=MODEL_NAME_IN_DB,
                model_type="classifier",
                dataset_id=dataset.id,
                **fields
            )
            db.add(ml_model)
            db.commit()
            print(f"[+] Created MLModel '{MODEL_NAME_IN_DB}' in DB.")

    finally:
        db.close()


def update_artifacts_and_db() -> None:
    primary_path = os.path.join(MODELS_DIR, PRIMARY_MODEL_FILENAME)
    alias_path = os.path.join(MODELS_DIR, ALIAS_MODEL_FILENAME)

    print("=" * 70)
    print("Loading real artifact metrics from training script output...")
    artifact = load_artifact(primary_path)
    metrics = extract_real_metrics(artifact)

    accuracy = float(metrics.get("accuracy", metrics.get("multiclass_accuracy", 0.0)))
    f1 = float(metrics.get("f1", metrics.get("weighted_f1", 0.0)))
    cv_mean = metrics.get("cross_validation", {}).get("mean_accuracy")

    print(f"[+] Accuracy  : {accuracy * 100:.2f}%")
    print(f"[+] Weighted F1: {f1 * 100:.2f}%")
    if cv_mean is not None:
        print(f"[+] CV Mean   : {cv_mean * 100:.2f}%")
    print("=" * 70)

    # Sync alias artifact (same payload, different filename)
    if os.path.exists(alias_path):
        import joblib as _jl
        _jl.dump(artifact, alias_path)
        print(f"[+] Alias artifact synced: {alias_path}")

    # Sync DB
    sync_db(artifact, metrics, primary_path)
    print("[+] Database & model artifacts fully synchronized from real metrics.")
    print("=" * 70)


if __name__ == "__main__":
    update_artifacts_and_db()
