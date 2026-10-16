import numpy as np
import pandas as pd
import logging
from typing import Dict, Any, Tuple, Optional
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_recall_fscore_support

logger = logging.getLogger(__name__)


def normalize_anomaly_scores(
    decision_scores: np.ndarray,
    ref_min: float = None,
    ref_max: float = None
) -> np.ndarray:
    """
    Normalizes raw Isolation Forest decision_function() output to [0, 100].

    Mapping:
      * 100 = most anomalous  (lowest decision score)
      * 0   = most normal     (highest decision score)

    ref_min / ref_max MUST come from the TRAINING data's decision scores so
    the scale is calibrated and consistent between train-time and inference.
    If they are None, we fall back to the observed range of the supplied
    decision_scores (graceful degradation for ad-hoc / one-off calls).

    This replaces the previous hardcoded ±0.5 bounds which were empirically
    incorrect — the actual decision_function() range is dataset-dependent.
    """
    scores = np.asarray(decision_scores, dtype=float)

    if ref_min is None:
        ref_min = float(scores.min())
    if ref_max is None:
        ref_max = float(scores.max())

    # Guard against degenerate case (all scores identical)
    score_range = ref_max - ref_min
    if score_range < 1e-9:
        # No variation: return mid-point 50 for all
        return np.full(len(scores), 50.0)

    # Linear map: ref_max → 0 (most normal), ref_min → 100 (most anomalous)
    normalized = 100.0 * (ref_max - scores) / score_range
    return np.clip(normalized, 0.0, 100.0)


def train_anomaly_detector(
    X: pd.DataFrame,
    contamination: float = 0.05,
    y_ground_truth: Optional[pd.Series] = None
) -> Tuple[IsolationForest, StandardScaler, Dict[str, Any]]:
    """
    Trains an Isolation Forest anomaly model, standardizes features,
    and returns (model, scaler, metrics).

    The returned metrics dict includes a 'score_calibration' sub-dict with
    ref_min and ref_max computed from the TRAINING decision_function() scores.
    These values MUST be saved in the model artifact and passed to
    normalize_anomaly_scores() at inference time so the 0-100 score is
    mathematically consistent across different inputs.
    """
    logger.info(f"Training Isolation Forest (contamination={contamination})...")

    # --- Standardize features ------------------------------------------------
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # --- Train model ---------------------------------------------------------
    model = IsolationForest(
        contamination=contamination,
        random_state=42,
        n_estimators=100,
        n_jobs=-1
    )
    model.fit(X_scaled)

    # --- Predict & score -----------------------------------------------------
    # predict() returns 1 (inlier / normal) or -1 (outlier / anomalous)
    preds = model.predict(X_scaled)
    # decision_function(): lower score → more anomalous
    decision_scores = model.decision_function(X_scaled)

    # Calibration bounds derived from actual training-data score distribution
    ref_min = float(decision_scores.min())
    ref_max = float(decision_scores.max())
    logger.info(
        f"IsolationForest score calibration: ref_min={ref_min:.5f}, ref_max={ref_max:.5f}"
    )

    # Calibrated normalized scores [0, 100]
    norm_scores = normalize_anomaly_scores(decision_scores, ref_min=ref_min, ref_max=ref_max)

    anomalous_mask = (preds == -1)
    num_anomalies = int(np.sum(anomalous_mask))
    total_records = len(X)
    anomaly_pct = float((num_anomalies / total_records) * 100)

    metrics: Dict[str, Any] = {
        "algorithm": "Isolation Forest",
        "contamination": contamination,
        "total_records": total_records,
        "num_anomalies": num_anomalies,
        "anomaly_percentage": anomaly_pct,
        # -----------------------------------------------------------------------
        # Calibration bounds — these MUST be stored in the artifact so that
        # run_anomaly_inference() can reconstruct the same 0-100 scale at
        # inference time without re-computing from potentially different data.
        # -----------------------------------------------------------------------
        "score_calibration": {
            "ref_min": ref_min,
            "ref_max": ref_max,
        },
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

    # --- Optional ground-truth evaluation ------------------------------------
    if y_ground_truth is not None:
        # Binary: Benign/Normal → 0, everything else → 1
        y_true_binary = np.array([
            0 if str(lbl).lower() in ["benign", "normal"] else 1
            for lbl in y_ground_truth
        ])
        # IsolationForest: -1 → outlier (pred=1), 1 → inlier (pred=0)
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
            "methodology": (
                "Isolation Forest outlier predictions compared against dataset "
                "ground-truth labels (outliers → malicious, inliers → benign)."
            )
        }

    return model, scaler, metrics


_FLOW_ANOMALY_CACHE: Dict[str, Any] = {}

def get_flow_anomaly_model() -> Optional[Dict[str, Any]]:
    """
    Retrieves or loads the calibrated flow Isolation Forest model artifact.
    Falls back gracefully if the artifact is not found.
    """
    if 'flow_anomaly' not in _FLOW_ANOMALY_CACHE:
        import os
        import joblib
        from app.core.config import settings

        # Priority 1: Calibrated CICIoT2023 flow anomaly model
        preferred_path = os.path.join(settings.MODEL_DIR, "ciciot2023_isolation_forest.joblib")
        if os.path.exists(preferred_path):
            try:
                _FLOW_ANOMALY_CACHE['flow_anomaly'] = joblib.load(preferred_path)
                logger.info(f"Loaded primary flow anomaly model from {preferred_path}")
                return _FLOW_ANOMALY_CACHE['flow_anomaly']
            except Exception as e:
                logger.warning(f"Error loading primary flow anomaly model: {e}")

        # Priority 2: Look for any anomaly model in model directory
        if os.path.exists(settings.MODEL_DIR):
            for fname in os.listdir(settings.MODEL_DIR):
                if fname.startswith("anomaly_") and fname.endswith(".joblib"):
                    p = os.path.join(settings.MODEL_DIR, fname)
                    try:
                        _FLOW_ANOMALY_CACHE['flow_anomaly'] = joblib.load(p)
                        logger.info(f"Loaded fallback anomaly model from {p}")
                        return _FLOW_ANOMALY_CACHE['flow_anomaly']
                    except Exception as e:
                        logger.warning(f"Could not load fallback anomaly model {p}: {e}")

        logger.warning("No Isolation Forest flow anomaly model found on disk.")
        return None

    return _FLOW_ANOMALY_CACHE.get('flow_anomaly')


def predict_flow_anomaly(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates an individual network flow record through the calibrated Isolation Forest.
    Returns:
      - anomaly_status: 'Normal' or 'Anomalous'
      - anomaly_score: float in [0.0, 100.0]
      - raw_score: float from decision_function()
      - is_outlier: bool (True if Isolation Forest flags outlier or score >= 50.0)
      - model_name: string identifier of the model
    """
    artifact = get_flow_anomaly_model()
    if artifact is None:
        return {
            "anomaly_status": "Normal",
            "anomaly_score": 0.0,
            "raw_score": 0.0,
            "is_outlier": False,
            "model_name": "Isolation Forest (Default Baseline)"
        }

    try:
        model = artifact['model']
        scaler = artifact['scaler']
        features = artifact['features']
        ref_min = artifact.get('score_ref_min')
        ref_max = artifact.get('score_ref_max')

        # Extract features in expected order, defaulting missing to 0.0
        row = []
        for f in features:
            v = record.get(f, 0.0)
            try:
                row.append(float(v) if v is not None else 0.0)
            except (ValueError, TypeError):
                row.append(0.0)

        df_row = pd.DataFrame([row], columns=features)
        scaled = scaler.transform(df_row)

        pred = int(model.predict(scaled)[0])
        raw_score = float(model.decision_function(scaled)[0])
        norm_score = float(normalize_anomaly_scores([raw_score], ref_min=ref_min, ref_max=ref_max)[0])
        norm_score = round(max(0.0, min(100.0, norm_score)), 1)

        # An outlier is flagged if Isolation Forest decision is -1 OR calibrated score >= 50.0
        is_outlier = bool(pred == -1 or norm_score >= 50.0)
        status = "Anomalous" if is_outlier else "Normal"

        return {
            "anomaly_status": status,
            "anomaly_score": norm_score,
            "raw_score": round(raw_score, 4),
            "is_outlier": is_outlier,
            "model_name": "Isolation Forest (Calibrated)"
        }
    except Exception as e:
        logger.error(f"Flow anomaly prediction failed: {e}")
        return {
            "anomaly_status": "Normal",
            "anomaly_score": 0.0,
            "raw_score": 0.0,
            "is_outlier": False,
            "model_name": "Isolation Forest (Error Fallback)"
        }

