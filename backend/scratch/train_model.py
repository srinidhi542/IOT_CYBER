import sys
import os
import json

# Add parent dir to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.database import SessionLocal
import app.db.models as models
from app.preprocessing.pipeline import preprocess_dataset
from app.ml.pipeline import train_and_evaluate_model
from app.core.config import settings

def main():
    db = SessionLocal()
    ds = db.query(models.Dataset).filter_by(id=1).first()
    if not ds:
        print("Dataset #1 not found.")
        return
        
    print(f"Training model on dataset: {ds.name} (target: {ds.target_column})")
    
    X_train, X_test, y_train, y_test, prep_summary = preprocess_dataset(
        ds.filepath, 
        target_column=ds.target_column, 
        train_split=0.8
    )
    
    model_name = "XGBoost_Core_Model"
    model_uuid = "xgboost_detector_v1.joblib"
    model_filepath = os.path.join(settings.MODEL_DIR, model_uuid)
    
    model, metrics = train_and_evaluate_model(
        X_train=X_train,
        X_test=X_test,
        y_train=y_train,
        y_test=y_test,
        algorithm="XGBoost",
        feature_names=prep_summary["feature_names"],
        classes_list=prep_summary["classes"],
        save_path=model_filepath
    )
    
    db_model = models.MLModel(
        name=model_name,
        algorithm=metrics["algorithm"],
        dataset_id=ds.id,
        features=json.dumps(prep_summary["feature_names"]),
        classes=json.dumps(prep_summary["classes"]),
        accuracy=metrics["accuracy"],
        precision_score=metrics["precision"],
        recall_score=metrics["recall"],
        f1_score=metrics["f1"],
        metrics_json=json.dumps(metrics["classification_report"]),
        confusion_matrix=json.dumps(metrics["confusion_matrix"]),
        feature_importance=json.dumps(metrics["feature_importance"]),
        filepath=model_filepath
    )
    db.add(db_model)
    db.commit()
    print("SUCCESS: Model trained and saved to SQLite!")

if __name__ == "__main__":
    main()
