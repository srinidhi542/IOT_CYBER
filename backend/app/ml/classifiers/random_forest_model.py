import numpy as np
import pandas as pd
import logging
from typing import Dict, Any, List, Tuple
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix, classification_report

logger = logging.getLogger(__name__)

def train_random_forest(
    X_train: pd.DataFrame,
    X_test: pd.DataFrame,
    y_train: pd.Series,
    y_test: pd.Series,
    feature_names: List[str],
    classes_list: List[str]
) -> Tuple[Any, Dict[str, Any]]:
    """
    Trains a RandomForestClassifier and calculates metrics.
    """
    logger.info("Training Random Forest Classifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        max_depth=12,
        n_jobs=-1
    )
    
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    
    # Probabilities
    y_prob = model.predict_proba(X_test)
    avg_confidence = float(np.mean(np.max(y_prob, axis=1)))
    
    # Calculate metrics
    accuracy = float(accuracy_score(y_test, y_pred))
    precision_w, recall_w, f1_w, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted', zero_division=0)
    precision_mac, recall_mac, f1_mac, _ = precision_recall_fscore_support(y_test, y_pred, average='macro', zero_division=0)
    
    cm = confusion_matrix(y_test, y_pred)
    class_report = classification_report(y_test, y_pred, target_names=classes_list, output_dict=True, zero_division=0)
    
    # Feature Importance
    feature_importances = {}
    if hasattr(model, 'feature_importances_'):
        importances = model.feature_importances_
        for name, imp in zip(feature_names, importances):
            feature_importances[name] = float(imp)
        feature_importances = dict(sorted(feature_importances.items(), key=lambda item: item[1], reverse=True))
        
    metrics = {
        "algorithm": "Random Forest",
        "accuracy": accuracy,
        "precision": float(precision_w),
        "recall": float(recall_w),
        "f1": float(f1_w),
        "macro_f1": float(f1_mac),
        "weighted_f1": float(f1_w),
        "avg_confidence": avg_confidence,
        "confusion_matrix": cm.tolist(),
        "classification_report": class_report,
        "feature_importance": feature_importances
    }
    
    return model, metrics
