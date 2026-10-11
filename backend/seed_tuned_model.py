import os
import sys
import json
import joblib
from sqlalchemy.orm import Session

# Add the backend directory to path so we can import app
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.core.database import SessionLocal, engine, Base
import app.db.models as models

def seed():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    # Create or get CICIoT2023 Dataset
    dataset = db.query(models.Dataset).filter(models.Dataset.name == "CICIoT2023_Full").first()
    if not dataset:
        dataset = models.Dataset(
            name="CICIoT2023_Full",
            filepath="synthetic_training_data",  # No real CSV on disk; trained from synthetic corpus
            row_count=0,       # Populated by train_enhanced_model.py on retrain
            col_count=23,
            columns=json.dumps([]),  # We'll fill features from model
            column_types=json.dumps({}),
            target_column="label",
            class_distribution=json.dumps({}),  # Populated from artifact metrics on sync
            missing_counts=json.dumps({}),
            status="preprocessed"
        )
        db.add(dataset)
        db.commit()
        db.refresh(dataset)
        print("Created Dataset entry.")
    
    # Load tuned model metadata
    model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "ciciot2023_8class_xgboost_tuned.joblib")
    if not os.path.exists(model_path):
        print(f"Model artifact not found at {model_path}")
        return

    artifact = joblib.load(model_path)
    metrics = artifact.get('metrics', {})
    
    features = artifact.get('features', [])
    classes = artifact.get('classes', [])
    cm = metrics.get('confusion_matrix', [])
    
    # Update dataset columns based on model
    dataset.columns = json.dumps(features)
    db.commit()
    
    # Get actual model feature importances (from artifact metrics, or directly from model)
    imp_dict = metrics.get('feature_importance', {})
    if not imp_dict:
        xgb_model = artifact.get('model')
        if hasattr(xgb_model, 'feature_importances_'):
            imp_dict = {features[i]: float(xgb_model.feature_importances_[i]) for i in range(len(features))}

    # Read all metrics from the real artifact — no hardcoded fallback values
    accuracy_val = float(metrics.get('accuracy', metrics.get('multiclass_accuracy', 0.0)))
    precision_val = float(metrics.get('precision', 0.0))
    recall_val = float(metrics.get('recall', 0.0))
    # f1 may be stored as 'f1', 'f1_score', or 'weighted_f1'
    f1_val = float(metrics.get('f1', metrics.get('f1_score', metrics.get('weighted_f1', 0.0))))
    alg_name = metrics.get('algorithm', "XGBoost (Trained)")


    # Update or Create MLModel entry
    ml_model = db.query(models.MLModel).filter(models.MLModel.name == "CICIoT2023_8Class_Tuned_XGBoost").first()
    if not ml_model:
        ml_model = models.MLModel(
            name="CICIoT2023_8Class_Tuned_XGBoost",
            algorithm=alg_name,
            model_type="classifier",
            dataset_id=dataset.id,
            features=json.dumps(features),
            classes=json.dumps(classes),
            accuracy=accuracy_val,
            precision_score=precision_val,
            recall_score=recall_val,
            f1_score=f1_val,
            metrics_json=json.dumps(metrics),
            confusion_matrix=json.dumps(cm),
            feature_importance=json.dumps(imp_dict)
        )
        db.add(ml_model)
        db.commit()
        print("Created MLModel entry.")
    else:
        ml_model.algorithm = alg_name
        ml_model.features = json.dumps(features)
        ml_model.classes = json.dumps(classes)
        ml_model.accuracy = accuracy_val
        ml_model.precision_score = precision_val
        ml_model.recall_score = recall_val
        ml_model.f1_score = f1_val
        ml_model.metrics_json = json.dumps(metrics)
        ml_model.confusion_matrix = json.dumps(cm)
        ml_model.feature_importance = json.dumps(imp_dict)
        db.commit()
        print(f"Updated MLModel entry with {accuracy_val * 100:.2f}% accuracy stats.")

    db.close()

if __name__ == "__main__":
    seed()
