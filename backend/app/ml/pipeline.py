import os
import joblib
import logging
from typing import Dict, Any, List, Tuple

from app.ml.classifiers.xgboost_model import train_xgboost, XGBOOST_AVAILABLE
from app.ml.classifiers.random_forest_model import train_random_forest

logger = logging.getLogger(__name__)

def train_and_evaluate_model(
    X_train: Any,
    X_test: Any,
    y_train: Any,
    y_test: Any,
    algorithm: str,
    feature_names: List[str],
    classes_list: List[str],
    save_path: str
) -> Tuple[Any, Dict[str, Any]]:
    """
    Wrapper pipeline function that routes training requests to appropriate classifiers.
    """
    actual_algorithm = algorithm
    
    if algorithm.upper() == "XGBOOST" and XGBOOST_AVAILABLE:
        model, metrics = train_xgboost(
            X_train=X_train,
            X_test=X_test,
            y_train=y_train,
            y_test=y_test,
            feature_names=feature_names,
            classes_list=classes_list
        )
    else:
        if algorithm.upper() == "XGBOOST":
            logger.warning("XGBoost selected but not available. Falling back to Random Forest.")
            actual_algorithm = "Random Forest"
            
        model, metrics = train_random_forest(
            X_train=X_train,
            X_test=X_test,
            y_train=y_train,
            y_test=y_test,
            feature_names=feature_names,
            classes_list=classes_list
        )
        
    # Override algorithm string in metrics if fell back
    metrics["algorithm"] = actual_algorithm
    
    # Save model artifact
    model_artifact = {
        "model": model,
        "algorithm": actual_algorithm,
        "features": feature_names,
        "classes": classes_list,
        "metrics": metrics
    }
    
    joblib.dump(model_artifact, save_path)
    logger.info(f"Classifier model saved successfully to {save_path}")
    
    return model, metrics
