import numpy as np
import pandas as pd
import logging
import joblib
from typing import Dict, Any, List, Tuple
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_recall_fscore_support

logger = logging.getLogger(__name__)

def normalize_anomaly_scores(decision_scores: np.ndarray) -> np.ndarray:
    """
    Normalizes raw Isolation Forest decision scores to a user-friendly 0-100 range.
    * 0 = most normal
    * 50 = anomaly boundary
    * 100 = most anomalous
    """
    normalized = []
    for score in decision_scores:
        if score >= 0:
            # Normal point: map [0.5, 0] to [0, 50]
            # Max possible positive decision score is approx 0.5
            mapped = (1.0 - (score / 0.5)) * 50
        else:
            # Anomalous point: map [0, -0.5] to [50, 100]
            # Min possible negative decision score is approx -0.5
            mapped = 50 + (abs(score) / 0.5) * 50
        normalized.append(float(np.clip(mapped, 0.0, 100.0)))
    return np.array(normalized)

def train_anomaly_detector(
    X: pd.DataFrame,
    contamination: float = 0.05,
    y_ground_truth: pd.Series = None
) -> Tuple[IsolationForest, StandardScaler, Dict[str, Any]]:
    """
    Trains an Isolation Forest anomaly model, standardizes features,
    and returns model, scaler, and evaluation metrics.
    """
    logger.info(f"Training Isolation Forest (contamination={contamination})...")
    
    # Standardize features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Train Isolation Forest
    model = IsolationForest(
        contamination=contamination,
        random_state=42,
        n_estimators=100,
        n_jobs=-1
    )
    
    model.fit(X_scaled)
    
    # Predict
    # returns 1 for inliers (normal), -1 for outliers (anomalous)
    preds = model.predict(X_scaled)
    
    # Raw decision scores (negative is anomaly)
    decision_scores = model.decision_function(X_scaled)
    
    # Normalized scores [0, 100]
    norm_scores = normalize_anomaly_scores(decision_scores)
    
    anomalous_mask = (preds == -1)
    num_anomalies = int(np.sum(anomalous_mask))
    total_records = len(X)
    anomaly_pct = float((num_anomalies / total_records) * 100)
    
    metrics = {
        "algorithm": "Isolation Forest",
        "contamination": contamination,
        "total_records": total_records,
        "num_anomalies": num_anomalies,
        "anomaly_percentage": anomaly_pct,
        "score_distribution": {
            "min": float(np.min(norm_scores)),
            "max": float(np.max(norm_scores)),
            "mean": float(np.mean(norm_scores)),
            "std": float(np.std(norm_scores)),
            "q25": float(np.percentile(norm_scores, 25)),
            "q50": float(np.percentile(norm_scores, 50)),
            "q75": float(np.percentile(norm_scores, 75))
        }
    }
    
    # Compare with ground truth if available (without leak during training)
    if y_ground_truth is not None:
        # Convert true class labels to binary: Benign/Normal vs Malicious
        # y_ground_truth elements are strings
        y_true_binary = np.array([0 if str(lbl).lower() in ["benign", "normal"] else 1 for lbl in y_ground_truth])
        
        # Isolation Forest prediction: -1 is anomaly (malicious), 1 is normal (benign)
        y_pred_binary = np.array([1 if p == -1 else 0 for p in preds])
        
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_true_binary, 
            y_pred_binary, 
            average='binary', 
            zero_division=0
        )
        
        metrics["ground_truth_evaluation"] = {
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1),
            "methodology": "Isolation Forest Outlier predictions compared directly against dataset ground-truth attack labels (outliers predicted as malicious, inliers as benign)."
        }
        
    return model, scaler, metrics
