import json
import numpy as np
from typing import Dict, Any, List, Tuple

SEVERITY_WEIGHTS = {
    "benign": 0.0,
    "normal": 0.0,
    "reconnaissance": 40.0,
    "spoofing": 40.0,
    "brute force": 60.0,
    "dos": 80.0,
    "malware": 80.0,
    "ddos": 100.0,
    "mirai": 100.0,
    "botnet": 100.0
}

def get_attack_severity_score(attack_type: str) -> float:
    """
    Returns base threat score (0-100) for a given attack label.
    """
    attack_lower = attack_type.lower()
    # Sort keys by length descending so longer patterns ('ddos') match before shorter ones ('dos')
    for key in sorted(SEVERITY_WEIGHTS.keys(), key=len, reverse=True):
        if key in attack_lower:
            return SEVERITY_WEIGHTS[key]
    return 50.0  # default for unknown attacks

def evaluate_threat(
    predicted_attack: str,
    confidence: float,  # 0.0 to 1.0
    anomaly_status: str,  # "Anomalous" or "Normal"
    anomaly_score: float,  # 0.0 to 100.0
    record_data: Dict[str, Any],
    benign_stats: Dict[str, Dict[str, float]] = None,
    feature_importance: Dict[str, float] = None
) -> Dict[str, Any]:
    """
    Intelligent Threat Intelligence Engine core.
    Combines supervised and unsupervised predictions to compute Risk Score,
    maps final severity, handles zero-day anomalies, and assesses feature deviations.
    """
    # 1. Calculate Malicious Confidence (how confident are we that it is NOT benign)
    is_benign_pred = predicted_attack.lower() in ["benign", "normal"]
    if is_benign_pred:
        malicious_confidence = (1.0 - confidence) * 100.0
        attack_severity_score = 0.0
    else:
        malicious_confidence = confidence * 100.0
        attack_severity_score = get_attack_severity_score(predicted_attack)
        
    # 2. Risk Score calculation (0-100)
    # Formula: Risk = (Mal_Conf * 0.45) + (Anomaly_Score * 0.35) + (Severity_Score * 0.20)
    risk_score = (malicious_confidence * 0.45) + (anomaly_score * 0.35) + (attack_severity_score * 0.20)
    risk_score = float(np.clip(risk_score, 0.0, 100.0))
    
    # 3. Detect Unknown / Zero-day Anomalies (Section 8)
    # If Isolation Forest detects a strong anomaly, but the classifier predicts Benign with moderate/high confidence:
    override_reason = None
    final_attack = predicted_attack
    
    if anomaly_score > 75.0 and is_benign_pred:
        final_attack = "Unknown / Suspicious"
        # Force risk to at least High (e.g. minimum 55) or update severity
        risk_score = max(risk_score, 55.0)
        override_reason = "The traffic does not strongly match a known attack category but exhibits highly unusual characteristics."
        
    # 4. Determine Combined Threat Severity (Section 4)
    # Low: Risk < 25
    # Medium: Risk 25 to 50
    # High: Risk 51 to 75
    # Critical: Risk > 75
    if risk_score < 25.0:
        severity = "Low"
    elif risk_score <= 50.0:
        severity = "Medium"
    elif risk_score <= 75.0:
        severity = "High"
    else:
        severity = "Critical"
        
    # Scenario overrides (Section 5)
    scenario_desc = ""
    if final_attack == "Unknown / Suspicious":
        scenario_desc = "Unusual network behavior detected. Further investigation recommended."
    elif severity == "Critical" and predicted_attack.lower() in ["ddos", "mirai", "botnet"]:
        scenario_desc = f"High-confidence {predicted_attack} classification with strongly anomalous traffic characteristics."
    elif severity == "Low" and is_benign_pred:
        scenario_desc = "Normal traffic profile verified."
    elif is_benign_pred and severity == "Medium" and anomaly_score > 70.0:
        scenario_desc = "Unusual network behavior detected. Further investigation recommended."
        
    # 5. Extract Feature Deviation (Section 13)
    feature_deviations = {}
    reasons_list = []
    
    if anomaly_status == "Anomalous":
        reasons_list.append("Strong anomaly score")
    if malicious_confidence >= 80.0:
        reasons_list.append("High classification confidence")
        
    if benign_stats:
        # Check standard deviations for numeric features
        # Sort features by importance or check all
        for feat, val in record_data.items():
            if feat not in benign_stats:
                continue
                
            stats = benign_stats[feat]
            mean_val = stats.get("mean", 0.0)
            std_val = stats.get("std", 1.0)
            if std_val == 0:
                std_val = 1.0
                
            try:
                numeric_val = float(val)
            except (ValueError, TypeError):
                continue
                
            z_score = (numeric_val - mean_val) / std_val
            
            # If value deviates by more than 1.5 standard deviations
            if abs(z_score) > 1.5:
                direction = "HIGH" if numeric_val > mean_val else "LOW"
                feature_deviations[feat] = direction
                
                # Format friendly reason
                friendly_name = feat.replace('_', ' ').title()
                if len(reasons_list) < 4:
                    reasons_list.append(f"Abnormal {friendly_name.lower()}")
                    
    # Generate generic explanations if none populated
    if not reasons_list:
        reasons_list = ["Unusual flow characteristics"]
        
    return {
        "attack_type": final_attack,
        "severity": severity,
        "risk_score": round(risk_score, 1),
        "anomaly_status": anomaly_status,
        "anomaly_score": round(anomaly_score, 1),
        "confidence": confidence,
        "scenario_description": override_reason or scenario_desc,
        "feature_deviations": feature_deviations,
        "reasons": reasons_list
    }
