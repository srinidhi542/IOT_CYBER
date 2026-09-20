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
            filepath="/placeholder/ciciot2023",
            row_count=46776697,
            col_count=39,
            columns=json.dumps([]),  # We'll fill features from model
            column_types=json.dumps({}),
            target_column="label_8",
            class_distribution=json.dumps({
                "Benign": 25000, # Representing the balanced subset or actual distribution
                "Brute Force": 13064,
                "DDoS": 25122,
                "DoS": 25021,
                "Mirai": 25040,
                "Recon": 22262,
                "Spoofing": 25000,
                "Web Attack": 20733
            }),
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
    
    # Get actual model feature importances
    xgb_model = artifact.get('model')
    if hasattr(xgb_model, 'feature_importances_'):
        imp_dict = {features[i]: float(xgb_model.feature_importances_[i]) for i in range(len(features))}
    else:
        imp_dict = {}

    # Create MLModel entry
    ml_model = db.query(models.MLModel).filter(models.MLModel.name == "CICIoT2023_8Class_Tuned_XGBoost").first()
    if not ml_model:
        ml_model = models.MLModel(
            name="CICIoT2023_8Class_Tuned_XGBoost",
            algorithm="XGBoost (Tuned 181K Balanced)",
            model_type="classifier",
            dataset_id=dataset.id,
            features=json.dumps(features),
            classes=json.dumps(classes),
            accuracy=metrics.get('accuracy', 0.0),
            precision_score=metrics.get('macro_precision', 0.0), # or weighted
            recall_score=metrics.get('macro_recall', 0.0),
            f1_score=metrics.get('macro_f1', 0.0),
            metrics_json=json.dumps(metrics),
            confusion_matrix=json.dumps(cm),
            feature_importance=json.dumps(imp_dict)
        )
        db.add(ml_model)
        db.commit()
        print("Created MLModel entry.")
    else:
        ml_model.feature_importance = json.dumps(imp_dict)
        db.commit()
        print("Updated MLModel entry.")

    db.close()

if __name__ == "__main__":
    seed()
