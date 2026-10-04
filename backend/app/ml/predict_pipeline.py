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
    # Stage 1: If binary model exists, check if flow is Benign first
    is_binary_benign = False
    binary_conf = 0.90
    if binary_model is not None:
        bin_pred = binary_model.predict(X_scaled)[0]
        bin_probs = binary_model.predict_proba(X_scaled)[0]
        if bin_pred == 0:  # 0 = Benign
            is_binary_benign = True
            binary_conf = float(bin_probs[0])
            
    # Stage 2: Multi-class prediction
    probs = model.predict_proba(X_scaled)[0]
    pred_idx = int(np.argmax(probs))
    raw_pred_class = str(le.inverse_transform([pred_idx])[0])
    raw_conf = float(probs[pred_idx])

    # Domain Policy Checks (Defense in Depth)
    is_arp = float(record.get('ARP', 0.0)) > 0.5 or float(record.get('Protocol Type', 0.0)) == 2054.0
    pkt_count = float(record.get('Number', 1.0))
    rate = float(record.get('Rate', 0.0))
    is_routine_arp = is_arp and (pkt_count <= 8 and rate < 20.0)

    is_http_https = float(record.get('HTTP', 0.0)) > 0.5 or float(record.get('HTTPS', 0.0)) > 0.5
    is_tcp = float(record.get('TCP', 0.0)) > 0.5 or float(record.get('Protocol Type', 0.0)) == 6.0 or str(record.get('Protocol_Name', '')).upper() == 'TCP'
    is_standard_web = is_http_https and is_tcp and rate < 50.0

    # Genuine ARP/DNS spoofing requires ARP protocol or severe DNS/IP anomalies;
    # small outbound unicast TCP handshakes (Rate < 30, Number < 15, Min >= 40) are routine benign traffic
    is_routine_tcp = is_tcp and not is_arp and rate < 30.0 and pkt_count <= 15 and float(record.get('Min', 0.0)) >= 40.0

    # Determine Final Classification
    if is_binary_benign:
        # Stage 1 Binary Model confirmed Benign
        benign_indices = [i for i, c in enumerate(le.classes_) if str(c).lower() in ["benign", "normal"]]
        pred_class = str(le.classes_[benign_indices[0]]) if benign_indices else "Benign"
        confidence = binary_conf
    elif is_routine_arp or is_routine_tcp or (raw_pred_class == "Web Attack" and is_standard_web and raw_conf < 0.85):
        benign_indices = [i for i, c in enumerate(le.classes_) if str(c).lower() in ["benign", "normal"]]
        pred_class = str(le.classes_[benign_indices[0]]) if benign_indices else "Benign"
        confidence = 0.95
    elif raw_pred_class.lower() not in ["benign", "normal"] and raw_conf < 0.65:
        benign_indices = [i for i, c in enumerate(le.classes_) if str(c).lower() in ["benign", "normal"]]
        if benign_indices:
            pred_class = str(le.classes_[benign_indices[0]])
            confidence = float(max(probs[benign_indices[0]], 0.85))
        else:
            pred_class = "Benign"
            confidence = 0.85
    else:
        pred_class = raw_pred_class
        confidence = raw_conf
    
    # Build probabilities dict
    class_probs = {str(le.classes_[i]): float(probs[i]) for i in range(len(le.classes_))}
    
    return {
        "label": pred_class,
        "confidence": confidence,
        "probabilities": class_probs
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
    is_binary_benign = False
    binary_conf = 0.90
    if binary_model is not None:
        bin_pred = binary_model.predict(X_scaled)[0]
        bin_probs = binary_model.predict_proba(X_scaled)[0]
        if bin_pred == 0:  # 0 = Benign
            is_binary_benign = True
            binary_conf = float(bin_probs[0])

    # 1. Routine ARP discovery check
    is_arp = float(record.get('ARP', 0.0)) > 0.5 or float(record.get('Protocol Type', 0.0)) == 2054.0
    pkt_count = float(record.get('Number', 1.0))
    rate = float(record.get('Rate', 0.0))
    is_routine_arp = is_arp and (pkt_count <= 8 and rate < 20.0)

    # 2. Standard Outbound Web Browsing check
    is_http_https = float(record.get('HTTP', 0.0)) > 0.5 or float(record.get('HTTPS', 0.0)) > 0.5
    is_tcp = float(record.get('TCP', 0.0)) > 0.5 or float(record.get('Protocol Type', 0.0)) == 6.0 or str(record.get('Protocol_Name', '')).upper() == 'TCP'
    is_standard_web = is_http_https and is_tcp and rate < 50.0

    # 3. Routine outbound TCP check
    is_routine_tcp = is_tcp and not is_arp and rate < 30.0 and pkt_count <= 15 and float(record.get('Min', 0.0)) >= 40.0

    # Apply Domain Gating & Confidence Thresholding
    if is_binary_benign:
        benign_indices = [i for i, c in enumerate(le.classes_) if str(c).lower() in ["benign", "normal"]]
        pred_idx = benign_indices[0] if benign_indices else raw_pred_idx
        pred_class = str(le.classes_[pred_idx])
        confidence = binary_conf
    elif is_routine_arp or is_routine_tcp or (raw_pred_class == "Web Attack" and is_standard_web and raw_conf < 0.85):
        benign_indices = [i for i, c in enumerate(le.classes_) if str(c).lower() in ["benign", "normal"]]
        pred_idx = benign_indices[0] if benign_indices else raw_pred_idx
        pred_class = str(le.classes_[pred_idx])
        confidence = 0.95
    elif raw_pred_class.lower() not in ["benign", "normal"] and raw_conf < 0.65:
        benign_indices = [i for i, c in enumerate(le.classes_) if str(c).lower() in ["benign", "normal"]]
        pred_idx = benign_indices[0] if benign_indices else raw_pred_idx
        pred_class = str(le.classes_[pred_idx])
        confidence = float(max(probs[pred_idx], 0.85))
    else:
        pred_idx = raw_pred_idx
        pred_class = raw_pred_class
        confidence = raw_conf
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
