import os
import joblib
import pandas as pd
import numpy as np
import shap
from typing import Dict, Any
from app.core.config import settings

_MODEL_CACHE = {}

def get_tuned_model():
    if 'tuned_model' not in _MODEL_CACHE:
        model_path = os.path.join(settings.MODEL_DIR, "ciciot2023_8class_xgboost_tuned.joblib")
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Tuned model not found at {model_path}")
        _MODEL_CACHE['tuned_model'] = joblib.load(model_path)
    return _MODEL_CACHE['tuned_model']

def get_shap_explainer():
    if 'shap_explainer' not in _MODEL_CACHE:
        artifact = get_tuned_model()
        model = artifact['model']
        _MODEL_CACHE['shap_explainer'] = shap.TreeExplainer(model)
    return _MODEL_CACHE['shap_explainer']

def predict_tuned(record: Dict[str, Any]) -> Dict[str, Any]:
    artifact = get_tuned_model()
    
    features = artifact['features']
    scaler = artifact['scaler']
    model = artifact['model']
    le = artifact['label_encoder']
    
    # Extract features in the exact order expected, default to 0.0 if missing
    row = []
    for f in features:
        val = record.get(f, 0.0)
        try:
            val = float(val)
        except (ValueError, TypeError):
            val = 0.0
        row.append(val)
        
    X_raw = pd.DataFrame([row], columns=features)
    
    # Scale
    X_scaled = scaler.transform(X_raw)
    
    # Predict
    probs = model.predict_proba(X_scaled)[0]
    pred_idx = int(np.argmax(probs))
    pred_class = str(le.inverse_transform([pred_idx])[0])
    confidence = float(probs[pred_idx])
    
    # Build probabilities dict
    class_probs = {str(le.classes_[i]): float(probs[i]) for i in range(len(le.classes_))}
    
    return {
        "label": pred_class,
        "confidence": confidence,
        "probabilities": class_probs
    }

def explain_prediction(record: Dict[str, Any], top_k: int = 5) -> Dict[str, Any]:
    artifact = get_tuned_model()
    features = artifact['features']
    scaler = artifact['scaler']
    model = artifact['model']
    le = artifact['label_encoder']
    
    # Extract features in the exact order expected
    row = []
    for f in features:
        val = record.get(f, 0.0)
        try:
            val = float(val)
        except (ValueError, TypeError):
            val = 0.0
        row.append(val)
        
    X_raw = pd.DataFrame([row], columns=features)
    X_scaled = scaler.transform(X_raw)
    
    # Prediction
    probs = model.predict_proba(X_scaled)[0]
    pred_idx = int(np.argmax(probs))
    pred_class = str(le.inverse_transform([pred_idx])[0])
    confidence = float(probs[pred_idx])
    class_probs = {str(le.classes_[i]): float(probs[i]) for i in range(len(le.classes_))}
    
    # Compute real SHAP values
    explainer = get_shap_explainer()
    shap_vals = explainer.shap_values(X_scaled)
    
    # Extract SHAP vector for the predicted class
    if isinstance(shap_vals, list):
        class_shap = shap_vals[pred_idx][0]
    elif len(shap_vals.shape) == 3:
        class_shap = shap_vals[0, :, pred_idx]
    else:
        class_shap = shap_vals[0]
        
    # Build feature contribution items
    contributions = []
    for i, f_name in enumerate(features):
        c_val = float(class_shap[i])
        raw_val = float(row[i])
        direction = "increases" if c_val >= 0 else "decreases"
        contributions.append({
            "feature": f_name,
            "value": raw_val,
            "shap_value": c_val,
            "abs_shap": abs(c_val),
            "direction": direction
        })
        
    # Sort by absolute SHAP contribution descending
    contributions.sort(key=lambda x: x["abs_shap"], reverse=True)
    top_contributions = contributions[:top_k]
    
    # Convert to clean output objects
    top_features = []
    for item in top_contributions:
        top_features.append({
            "feature": item["feature"],
            "value": item["value"],
            "shap_value": round(item["shap_value"], 4),
            "direction": item["direction"]
        })
        
    all_shap_dict = {item["feature"]: round(item["shap_value"], 4) for item in contributions}
    
    return {
        "label": pred_class,
        "confidence": confidence,
        "probabilities": class_probs,
        "top_contributing_features": top_features,
        "shap_values": all_shap_dict
    }
