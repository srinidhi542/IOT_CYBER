import os
import joblib
import pandas as pd
import numpy as np
import json
import logging
from typing import Dict, Any, List, Tuple
from app.core.config import settings

logger = logging.getLogger(__name__)

# Severity mapping criteria
# Attack labels to severity ranks
SEVERITY_MAPPING = {
    "benign": "Low",
    "normal": "Low",
    "reconnaissance": "Medium",
    "spoofing": "Medium",
    "brute force": "High",
    "dos": "High",
    "malware": "High",
    "ddos": "Critical",
    "mirai": "Critical",
    "botnet": "Critical"
}

RESPONSE_RECOMMENDATIONS = {
    "DDoS": [
        "Isolate affected endpoint to prevent outbound amplification",
        "Rate-limit suspicious traffic incoming at network border",
        "Review source IP patterns and coordinate with upstream ISP",
        "Monitor interface traffic volume and queue drops"
    ],
    "DoS": [
        "Isolate target node to prevent server exhaustion",
        "Enable SYN flood protections (e.g., TCP SYN cookies)",
        "Check local host firewall drops and connection limits",
        "Investigate traffic patterns for spoofed sources"
    ],
    "Botnet": [
        "Isolate suspected IoT device from the main network",
        "Review outbound connections, especially to unverified external IPs",
        "Check and update device firmware immediately",
        "Investigate potential command-and-control (C2) indicators"
    ],
    "Mirai": [
        "Isolate infected IoT node immediately (disconnect from network)",
        "Inspect active sessions for telnet/SSH brute force activity",
        "Reboot device to clear memory resident malware",
        "Update default login credentials and disable unnecessary open ports"
    ],
    "Reconnaissance": [
        "Investigate scanning source IP and log connection attempts",
        "Temporarily block scanner IP at host or network firewall",
        "Restrict unnecessary exposed services and scan targets",
        "Verify internal asset inventory for unpatched vulnerabilities"
    ],
    "Spoofing": [
        "Enable anti-spoofing filters (e.g., Unicast Reverse Path Forwarding)",
        "Inspect ARP cache and MAC table for anomalies",
        "Review local authentication and encryption protocols",
        "Isolate spoofing IP/MAC from logical network segments"
    ],
    "Brute Force": [
        "Enforce strict rate-limiting on authentication endpoints",
        "Block attacking IP address temporarily at firewall",
        "Review accounts with high authentication failures",
        "Enforce multi-factor authentication (MFA) and rotate credentials"
    ],
    "Malware": [
        "Quarantine infected device in an isolated VLAN",
        "Perform deep inspection of memory and filesystem logs",
        "Re-flash firmware from trusted official media",
        "Audit network permissions and outbound traffic limits"
    ],
    "Benign": [
        "No security action required.",
        "System remains under continuous monitoring."
    ]
}

def get_severity(attack_type: str, confidence: float) -> str:
    """
    Computes rule-based threat severity.
    """
    attack_lower = attack_type.lower()
    
    # Direct mapping lookup
    base_severity = "Medium"
    for key, val in SEVERITY_MAPPING.items():
        if key in attack_lower:
            base_severity = val
            break
            
    if base_severity == "Low":
        return "Low"
        
    # Scale down if low confidence
    if confidence < 0.6:
        if base_severity == "Critical":
            return "High"
        if base_severity == "High":
            return "Medium"
        if base_severity == "Medium":
            return "Low"
            
    # Scale up if high confidence and high risk
    if confidence > 0.95 and base_severity == "High":
        return "Critical"
        
    return base_severity

def get_recommendations(attack_type: str) -> List[str]:
    """
    Maps attack type to actionable recommendations.
    """
    attack_lower = attack_type.lower()
    for key, recs in RESPONSE_RECOMMENDATIONS.items():
        if key.lower() in attack_lower:
            return recs
    return ["Monitor network traffic for anomalies.", "Review network firewall rules."]

def generate_record_explanation(
    record_dict: Dict[str, Any],
    benign_stats: Dict[str, Dict[str, float]],
    feature_importance: Dict[str, float],
    attack_type: str
) -> Dict[str, Any]:
    """
    Generates explainability text highlighting which features contributed to the threat prediction
    by looking at deviations from benign stats and global feature importance.
    """
    if attack_type.lower() in ["benign", "normal"]:
        return {
            "summary": "This traffic exhibits patterns consistent with typical baseline activity.",
            "details": []
        }
        
    explanations = []
    
    # Look at features that deviate significantly from benign means
    # Sort features by importance so we check high-importance features first
    sorted_features = sorted(feature_importance.keys(), key=lambda k: feature_importance[k], reverse=True)
    
    checked = 0
    for feat in sorted_features:
        if feat not in record_dict or feat not in benign_stats:
            continue
            
        feat_val = record_dict[feat]
        b_mean = benign_stats[feat].get("mean", 0.0)
        b_std = benign_stats[feat].get("std", 1.0)
        if b_std == 0:
            b_std = 1.0
            
        # Calculate standard deviation score (z-score)
        z_score = (feat_val - b_mean) / b_std
        
        # Check for significant deviations (e.g. 1.5 standard deviations away)
        # Or simple ratio deviations for positive metrics (like duration, bytes, packets)
        if abs(z_score) > 1.5 or (b_mean > 0 and feat_val / b_mean > 2.0):
            friendly_name = feat.replace('_', ' ').title()
            
            # Format custom explanation text based on the feature type
            if z_score > 1.5:
                direction = "elevated" if feat_val > b_mean else "depressed"
                explanations.append(
                    f"Abnormal {friendly_name}: value is significantly {direction} compared to benign traffic."
                )
            else:
                explanations.append(
                    f"Elevated {friendly_name}: {feat_val:.2f} (benign average: {b_mean:.2f})."
                )
            checked += 1
            if checked >= 4:  # Limit explanation points
                break
                
    if not explanations:
        # Fallback to general message if no features show major deviation
        explanations = [
            "Corresponds to statistical patterns observed in historical training samples.",
            f"Matches signature profiles for {attack_type} based on model feature importances."
        ]
        
    return {
        "summary": f"Classified as {attack_type} because of feature anomalies in high-impact indicators.",
        "details": explanations
    }

def run_threat_detection(
    model_filepath: str,
    dataset_df: pd.DataFrame,
    original_df: pd.DataFrame = None
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Executes detection on df using loaded model.
    Returns: Job summary and detailed threat records.
    """
    if not os.path.exists(model_filepath):
        raise FileNotFoundError(f"Model file not found: {model_filepath}")
        
    artifact = joblib.load(model_filepath)
    model = artifact["model"]
    features = artifact["features"]
    classes = artifact["classes"]
    global_importance = artifact["metrics"].get("feature_importance", {})
    
    # Align features (ensure columns exist and are sorted)
    # Check if any columns are missing in dataset_df
    missing_cols = [f for f in features if f not in dataset_df.columns]
    if missing_cols:
        raise ValueError(f"Dataset is missing required features: {missing_cols}")
        
    X = dataset_df[features].copy()
    
    # Replace infs and NaNs just in case
    X = X.replace([np.inf, -np.inf], np.nan)
    for col in X.columns:
        X[col] = X[col].fillna(X[col].median() if not pd.isna(X[col].median()) else 0.0)
        
    # Inference
    preds = model.predict(X)
    
    confidences = []
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(X)
        confidences = [float(c) for c in np.max(probs, axis=1)]
    else:
        confidences = [1.0] * len(X)
        
    # Prepare original records for front-end view (IPs, ports, etc.)
    # If original_df is not passed, use dataset_df
    view_df = original_df if original_df is not None else dataset_df
    
    # Calculate benign statistics from the model training dataset if stored.
    # If not stored, calculate benign stats from current predictions to have a base of comparison.
    # Let's check if the model has stats. If not, generate now.
    benign_stats = {}
    benign_mask = np.array([classes[p].lower() in ["benign", "normal"] for p in preds])
    
    # We calculate stats using records predicted as benign, or fallback to the whole dataset.
    ref_df = X[benign_mask] if benign_mask.any() else X
    for col in X.columns:
        benign_stats[col] = {
            "mean": float(ref_df[col].mean()),
            "std": float(ref_df[col].std())
        }
        
    threats = []
    benign_count = 0
    malicious_count = 0
    critical_count = 0
    
    total = len(X)
    
    for idx in range(total):
        pred_class_idx = preds[idx]
        pred_label = classes[pred_class_idx]
        conf = confidences[idx]
        
        is_benign = pred_label.lower() in ["benign", "normal"]
        
        severity = get_severity(pred_label, conf)
        
        if is_benign:
            benign_count += 1
        else:
            malicious_count += 1
            if severity == "Critical":
                critical_count += 1
                
        # Record details for UI
        # Map original values (including IPs, port, time) if they exist
        record_data = {}
        row_orig = view_df.iloc[idx]
        for c in view_df.columns:
            val = row_orig[c]
            if pd.isna(val):
                record_data[c] = None
            elif isinstance(val, (np.integer, int)):
                record_data[c] = int(val)
            elif isinstance(val, (np.floating, float)):
                record_data[c] = float(val)
            else:
                record_data[c] = str(val)
                
        # Generate explanations for threats
        explanation = generate_record_explanation(
            X.iloc[idx].to_dict(),
            benign_stats,
            global_importance,
            pred_label
        )
        
        recs = get_recommendations(pred_label)
        
        # Add to list
        threats.append({
            "record_index": idx,
            "record_data": record_data,
            "attack_type": pred_label,
            "severity": severity,
            "confidence": conf,
            "explanation": explanation,
            "recommended_actions": recs
        })
        
    avg_conf = float(np.mean(confidences)) if confidences else 1.0
    
    summary = {
        "total_records": total,
        "benign_count": benign_count,
        "malicious_count": malicious_count,
        "critical_count": critical_count,
        "avg_confidence": avg_conf
    }
    
    return summary, threats
