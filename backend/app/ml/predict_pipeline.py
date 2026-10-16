import os
import joblib
import pandas as pd
import numpy as np
import shap
from typing import Dict, Any, Optional
from app.core.config import settings

_MODEL_CACHE = {}

def get_tuned_model():
    if 'tuned_model' not in _MODEL_CACHE:
        model_path = os.path.join(settings.MODEL_DIR, "ciciot2023_8class_xgboost_tuned.joblib")
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Tuned model not found at {model_path}")
        _MODEL_CACHE['tuned_model'] = joblib.load(model_path)
    return _MODEL_CACHE['tuned_model']

def _patch_shap_ubjson_decoder():
    """Patches SHAP's decode_ubjson_buffer to handle multi-class XGBoost base_score arrays gracefully."""
    try:
        import shap.explainers._tree as tree_mod
        if getattr(tree_mod, "_patched_for_multiclass", False):
            return
        orig_decode = tree_mod.decode_ubjson_buffer
        def safe_decode(fd):
            jmodel = orig_decode(fd)
            try:
                lmp = jmodel['learner']['learner_model_param']
                bs = lmp.get('base_score')
                if isinstance(bs, str) and bs.startswith('['):
                    lmp['base_score'] = '0.5'
            except Exception:
                pass
            return jmodel
        tree_mod.decode_ubjson_buffer = safe_decode
        tree_mod._patched_for_multiclass = True
    except Exception:
        pass

def get_shap_explainer():
    if 'shap_explainer' not in _MODEL_CACHE:
        _patch_shap_ubjson_decoder()
        artifact = get_tuned_model()
        model = artifact['model']
        _MODEL_CACHE['shap_explainer'] = shap.TreeExplainer(model)
    return _MODEL_CACHE['shap_explainer']

def predict_tuned(record: Dict[str, Any]) -> Dict[str, Any]:
    artifact = get_tuned_model()
    
    features = artifact['features']
    scaler = artifact['scaler']
    model = artifact.get('multiclass_model', artifact.get('model'))
    binary_model = artifact.get('binary_model', None)
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
    X_scaled = scaler.transform(X_raw)
    
    # -------------------------------------------------------------------------
    # Two-Stage Hierarchical Inference
    # -------------------------------------------------------------------------
    # Stage 1: Binary Anomaly / Threat Gate
    is_binary_attack = False
    bin_conf = 0.50
    if binary_model is not None:
        bin_pred = binary_model.predict(X_scaled)[0]
        bin_probs = binary_model.predict_proba(X_scaled)[0]
        if bin_pred == 1:
            is_binary_attack = True
            bin_conf = float(bin_probs[1])
        else:
            bin_conf = float(bin_probs[0])
            
    # Stage 2: Multi-class prediction
    probs = model.predict_proba(X_scaled)[0]
    pred_idx = int(np.argmax(probs))
    raw_pred_class = str(le.inverse_transform([pred_idx])[0])
    raw_conf = float(probs[pred_idx])

    # Pure ML Model Decision
    if is_binary_attack:
        if raw_pred_class.lower() in ["benign", "normal"]:
            # Binary stage flagged threat: select highest-probability attack class
            attack_indices = [i for i, c in enumerate(le.classes_) if str(c).lower() not in ["benign", "normal"]]
            best_att_idx = max(attack_indices, key=lambda i: probs[i])
            pred_class = str(le.classes_[best_att_idx])
            confidence = float(probs[best_att_idx])
        else:
            pred_class = raw_pred_class
            confidence = raw_conf
    else:
        benign_indices = [i for i, c in enumerate(le.classes_) if str(c).lower() in ["benign", "normal"]]
        pred_class = str(le.classes_[benign_indices[0]]) if benign_indices else raw_pred_class
        confidence = float(probs[benign_indices[0]]) if benign_indices else bin_conf
    
    # Build probabilities dict
    class_probs = {str(le.classes_[i]): float(probs[i]) for i in range(len(le.classes_))}
    
    # Run Isolation Forest unsupervised anomaly evaluation
    from app.ml.anomaly.isolation_forest import predict_flow_anomaly
    anomaly_res = predict_flow_anomaly(record)

    return {
        "label": pred_class,
        "confidence": confidence,
        "probabilities": class_probs,
        "anomaly_score": anomaly_res.get("anomaly_score", 0.0),
        "anomaly_status": anomaly_res.get("anomaly_status", "Normal")
    }

def explain_prediction(record: Dict[str, Any], top_k: Optional[int] = None) -> Dict[str, Any]:
    from app.core.config import load_platform_settings
    if top_k is None:
        p_settings = load_platform_settings()
        top_k = p_settings.get("detection_engine", {}).get("shap_top_k", 5)

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
    raw_pred_idx = int(np.argmax(probs))
    raw_pred_class = str(le.inverse_transform([raw_pred_idx])[0])
    raw_conf = float(probs[raw_pred_idx])
    binary_model = artifact.get('binary_model', None)
    is_binary_attack = False
    bin_conf = 0.50
    if binary_model is not None:
        bin_pred = binary_model.predict(X_scaled)[0]
        bin_probs = binary_model.predict_proba(X_scaled)[0]
        if bin_pred == 1:
            is_binary_attack = True
            bin_conf = float(bin_probs[1])
        else:
            bin_conf = float(bin_probs[0])

    # Pure ML Model Decision
    if is_binary_attack:
        if raw_pred_class.lower() in ["benign", "normal"]:
            attack_indices = [i for i, c in enumerate(le.classes_) if str(c).lower() not in ["benign", "normal"]]
            pred_idx = max(attack_indices, key=lambda i: probs[i])
            pred_class = str(le.classes_[pred_idx])
            confidence = float(probs[pred_idx])
        else:
            pred_idx = raw_pred_idx
            pred_class = raw_pred_class
            confidence = raw_conf
    else:
        benign_indices = [i for i, c in enumerate(le.classes_) if str(c).lower() in ["benign", "normal"]]
        pred_idx = benign_indices[0] if benign_indices else raw_pred_idx
        pred_class = str(le.classes_[pred_idx]) if benign_indices else raw_pred_class
        confidence = float(probs[benign_indices[0]]) if benign_indices else bin_conf
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
    
    # Run Isolation Forest unsupervised anomaly evaluation
    from app.ml.anomaly.isolation_forest import predict_flow_anomaly
    anomaly_res = predict_flow_anomaly(record)

    return {
        "label": pred_class,
        "confidence": confidence,
        "probabilities": class_probs,
        "top_contributing_features": top_features,
        "shap_values": all_shap_dict,
        "anomaly_score": anomaly_res.get("anomaly_score", 0.0),
        "anomaly_status": anomaly_res.get("anomaly_status", "Normal"),
        "anomaly_model": anomaly_res.get("model_name", "Isolation Forest (Calibrated)"),
        "anomaly_raw_score": anomaly_res.get("raw_score", 0.0)
    }
