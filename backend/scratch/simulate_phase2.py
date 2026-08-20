import sys
import os
import json
import shutil
import urllib.request
import pandas as pd

# Add parent to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.database import SessionLocal
import app.db.models as models
from app.preprocessing.pipeline import preprocess_dataset
from app.ml.pipeline import train_and_evaluate_model
from app.ml.anomaly.anomaly_service import train_and_save_anomaly_model
from app.core.config import settings

def main():
    db = SessionLocal()
    
    # 1. Setup sample dataset copy in uploads
    csv_src = "app/sample_data/iot_sample_traffic.csv"
    if not os.path.exists(csv_src):
        print(f"Source CSV {csv_src} not found!")
        return
        
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    csv_dest = os.path.join(settings.UPLOAD_DIR, "iot_sample_traffic.csv")
    shutil.copy(csv_src, csv_dest)
    
    df = pd.read_csv(csv_dest)
    cols = df.columns.tolist()
    col_types = {col: str(df[col].dtype) for col in cols}
    counts = df["Label"].value_counts().to_dict()
    
    db_ds = models.Dataset(
        name="iot_sample_traffic.csv",
        filepath=csv_dest,
        row_count=len(df),
        col_count=len(cols),
        columns=json.dumps(cols),
        column_types=json.dumps(col_types),
        target_column="Label",
        class_distribution=json.dumps(counts),
        status="preprocessed"
    )
    db.add(db_ds)
    db.commit()
    db.refresh(db_ds)
    print(f"SUCCESS: Dataset #{db_ds.id} added.")
    
    X_train, X_test, y_train, y_test, prep_summary = preprocess_dataset(
        db_ds.filepath, target_column="Label", train_split=0.8
    )
    
    model_name = "XGBoost_Classifier_Core"
    model_uuid = "xgboost_detector_v1.joblib"
    model_filepath = os.path.join(settings.MODEL_DIR, model_uuid)
    os.makedirs(settings.MODEL_DIR, exist_ok=True)
    
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
        model_type="classifier",
        dataset_id=db_ds.id,
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
    db.refresh(db_model)
    print(f"SUCCESS: Supervised Classifier Model #{db_model.id} trained.")
    
    # 3. Train unsupervised anomaly model
    db_anomaly = train_and_save_anomaly_model(
        dataset_id=db_ds.id,
        contamination=0.05,
        db=db
    )
    print(f"SUCCESS: Unsupervised Anomaly Model #{db_anomaly.id} trained.")
    
    # 4. Trigger detection run via HTTP call to running uvicorn on port 8005
    print("Triggering combined threat detection API...")
    detect_payload = {
        "dataset_id": db_ds.id,
        "model_id": db_model.id,
        "anomaly_model_id": db_anomaly.id
    }
    
    req = urllib.request.Request(
        "http://127.0.0.1:8005/api/detect",
        data=json.dumps(detect_payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    
    try:
        with urllib.request.urlopen(req) as res:
            print(f"SUCCESS: Detection run API returned status {res.status}")
            
        # 5. Generate report
        report_req = urllib.request.Request(
            "http://127.0.0.1:8005/api/reports/generate?detection_job_id=1",
            data=b"",
            method="POST"
        )
        with urllib.request.urlopen(report_req) as res_rep:
            print(f"SUCCESS: Report generation API returned status {res_rep.status}")
            
    except Exception as e:
        print(f"ERROR: HTTP trigger failed: {e}")

if __name__ == "__main__":
    main()
