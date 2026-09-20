import numpy as np
import pandas as pd
import logging
from typing import Dict, Any, List, Tuple
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix, classification_report

logger = logging.getLogger(__name__)

XGBOOST_AVAILABLE = False
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    logger.warning("XGBoost is not installed on this system.")

from sklearn.model_selection import StratifiedKFold, cross_val_score

def train_xgboost(
    X_train: pd.DataFrame,
    X_test: pd.DataFrame,
    y_train: pd.Series,
    y_test: pd.Series,
    feature_names: List[str],
    classes_list: List[str]
) -> Tuple[Any, Dict[str, Any]]:
    """
    Trains an XGBClassifier and calculates train, test, CV, and per-class metrics.
    """
    if not XGBOOST_AVAILABLE:
        raise RuntimeError("XGBoost library is not available.")
        
    logger.info("Training XGBoost Classifier...")
    model = xgb.XGBClassifier(
        use_label_encoder=False,
        eval_metric='mlogloss',
        random_state=42,
        n_estimators=100,
        max_depth=6
    )
    
    # 1. 5-Fold Stratified Cross-Validation on TRAINING data only
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X_train, y_train, cv=cv, scoring='accuracy')
    cv_mean = float(np.mean(cv_scores))
    cv_std = float(np.std(cv_scores))
    
    # 2. Fit model on full training set
    model.fit(X_train, y_train)
    
    # 3. Training set metrics
    y_train_pred = model.predict(X_train)
    train_accuracy = float(accuracy_score(y_train, y_train_pred))
    train_p, train_r, train_f1, _ = precision_recall_fscore_support(y_train, y_train_pred, average='weighted', zero_division=0)
    
    # 4. Test set metrics
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)
    avg_confidence = float(np.mean(np.max(y_prob, axis=1)))
    
    accuracy = float(accuracy_score(y_test, y_pred))
    precision_w, recall_w, f1_w, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted', zero_division=0)
    precision_mac, recall_mac, f1_mac, _ = precision_recall_fscore_support(y_test, y_pred, average='macro', zero_division=0)
    
    cm = confusion_matrix(y_test, y_pred)
    class_report = classification_report(y_test, y_pred, target_names=classes_list, output_dict=True, zero_division=0)
    
    # Performance Gap
    performance_gap = round(float(train_accuracy - accuracy), 4)
    
    # Feature Importance
    feature_importances = {}
    if hasattr(model, 'feature_importances_'):
        importances = model.feature_importances_
        for name, imp in zip(feature_names, importances):
            feature_importances[name] = float(imp)
        feature_importances = dict(sorted(feature_importances.items(), key=lambda item: item[1], reverse=True))
        
    metrics = {
        "algorithm": "XGBoost",
        "accuracy": accuracy,
        "precision": float(precision_w),
        "recall": float(recall_w),
        "f1": float(f1_w),
        "macro_f1": float(f1_mac),
        "weighted_f1": float(f1_w),
        "avg_confidence": avg_confidence,
        "train_metrics": {
            "accuracy": train_accuracy,
            "precision": float(train_p),
            "recall": float(train_r),
            "f1": float(train_f1)
        },
        "test_metrics": {
            "accuracy": accuracy,
            "precision": float(precision_w),
            "recall": float(recall_w),
            "f1": float(f1_w)
        },
        "cross_validation": {
            "folds": 5,
            "mean_accuracy": cv_mean,
            "std_accuracy": cv_std,
            "scores": [float(s) for s in cv_scores]
        },
        "performance_gap": performance_gap,
        "confusion_matrix": cm.tolist(),
        "classification_report": class_report,
        "feature_importance": feature_importances
    }
    
    return model, metrics
