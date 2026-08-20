import unittest
import numpy as np
import pandas as pd
from typing import Dict, Any

from app.ml.anomaly.isolation_forest import normalize_anomaly_scores, train_anomaly_detector
from app.ml.threat_engine.threat_engine import evaluate_threat, get_attack_severity_score

class TestAnomalyAndThreatEngine(unittest.TestCase):

    def setUp(self):
        # Create a mock dataset for testing
        np.random.seed(42)
        normal_data = np.random.normal(loc=0.0, scale=1.0, size=(100, 5))
        anomaly_data = np.random.normal(loc=10.0, scale=2.0, size=(5, 5))
        
        self.feature_names = [f"feat_{i}" for i in range(5)]
        self.df_normal = pd.DataFrame(normal_data, columns=self.feature_names)
        self.df_anomaly = pd.DataFrame(anomaly_data, columns=self.feature_names)
        self.df_combined = pd.concat([self.df_normal, self.df_anomaly]).reset_index(drop=True)
        
        # Ground truth labels
        self.y_true = pd.Series(["Benign"] * 100 + ["DDoS"] * 5)
        
        # Basic benign stats baseline
        self.benign_stats = {}
        for feat in self.feature_names:
            self.benign_stats[feat] = {
                "mean": float(self.df_normal[feat].mean()),
                "std": float(self.df_normal[feat].std())
            }

    def test_anomaly_score_normalization(self):
        """
        Verify Isolation Forest raw decision score to 0-100 percentage mapping.
        """
        raw_scores = np.array([0.4, 0.1, 0.0, -0.1, -0.4])
        norm_scores = normalize_anomaly_scores(raw_scores)
        
        # Max positive (0.4) should map below 50 (normal)
        self.assertLess(norm_scores[0], 50.0)
        # Boundary (0.0) should map to exactly 50
        self.assertEqual(norm_scores[2], 50.0)
        # Negatives should map above 50 (anomalous)
        self.assertGreater(norm_scores[3], 50.0)
        
        # All scores must be within [0, 100]
        for s in norm_scores:
            self.assertTrue(0.0 <= s <= 100.0)

    def test_anomaly_detector_training(self):
        """
        Verify Isolation Forest model training, contamination rates, and ground-truth evaluations.
        """
        model, scaler, metrics = train_anomaly_detector(
            X=self.df_combined,
            contamination=0.05,
            y_ground_truth=self.y_true
        )
        
        self.assertEqual(metrics["algorithm"], "Isolation Forest")
        self.assertEqual(metrics["total_records"], 105)
        self.assertAlmostEqual(metrics["num_anomalies"], 5, delta=1)  # 5% of 105 is approx 5 records
        self.assertIn("ground_truth_evaluation", metrics)
        self.assertGreaterEqual(metrics["ground_truth_evaluation"]["f1_score"], 0.5)

    def test_risk_score_calculation(self):
        """
        Verify combined Risk Score output.
        Formula: Risk = (Mal_Conf * 0.45) + (Anomaly_Score * 0.35) + (Severity_Score * 0.20)
        """
        # Scenario A: Benign prediction, low anomaly
        res_a = evaluate_threat(
            predicted_attack="Benign",
            confidence=0.96,
            anomaly_status="Normal",
            anomaly_score=8.0,
            record_data={"feat_0": 0.1},
            benign_stats=self.benign_stats
        )
        # Malicious confidence = 4.0%
        # Risk = 4.0 * 0.45 + 8.0 * 0.35 + 0.0 * 0.20 = 1.8 + 2.8 = 4.6
        self.assertEqual(res_a["severity"], "Low")
        self.assertAlmostEqual(res_a["risk_score"], 4.6, places=1)
        
        # Scenario C: DDoS prediction, high anomaly
        res_c = evaluate_threat(
            predicted_attack="DDoS",
            confidence=0.97,
            anomaly_status="Anomalous",
            anomaly_score=91.0,
            record_data={"feat_0": 12.0},
            benign_stats=self.benign_stats
        )
        # Malicious confidence = 97.0%
        # DDoS Severity = 100.0
        # Risk = 97.0 * 0.45 + 91.0 * 0.35 + 100.0 * 0.20 = 43.65 + 31.85 + 20.0 = 95.5
        self.assertEqual(res_c["severity"], "Critical")
        self.assertAlmostEqual(res_c["risk_score"], 95.5, places=1)
        self.assertIn("strongly anomalous", res_c["scenario_description"])

    def test_unknown_behavior_handling(self):
        """
        Verify that unseen/unknown anomalies override predicted label and set risk to high.
        """
        res = evaluate_threat(
            predicted_attack="Benign",
            confidence=0.85, # Predicted benign with moderate confidence
            anomaly_status="Anomalous",
            anomaly_score=94.0, # Highly anomalous!
            record_data={"feat_0": 10.0},
            benign_stats=self.benign_stats
        )
        
        self.assertEqual(res["attack_type"], "Unknown / Suspicious")
        self.assertGreaterEqual(res["risk_score"], 50.0)
        self.assertEqual(res["severity"], "High")
        self.assertIn("does not strongly match", res["scenario_description"])

    def test_feature_deviation_assessment(self):
        """
        Verify that deviant features are correctly labeled with HIGH/LOW.
        """
        # Set feat_0 value to be very high (15.0) relative to benign mean (0.0) and std (1.0)
        record = {"feat_0": 15.0, "feat_1": -10.0}
        res = evaluate_threat(
            predicted_attack="Benign",
            confidence=0.99,
            anomaly_status="Anomalous",
            anomaly_score=80.0,
            record_data=record,
            benign_stats=self.benign_stats
        )
        
        self.assertIn("feat_0", res["feature_deviations"])
        self.assertEqual(res["feature_deviations"]["feat_0"], "HIGH")
        self.assertIn("feat_1", res["feature_deviations"])
        self.assertEqual(res["feature_deviations"]["feat_1"], "LOW")

    def test_empty_dataset_handling(self):
        """
        Verify training behavior on empty or single-row inputs.
        """
        df_empty = pd.DataFrame(columns=self.feature_names)
        with self.assertRaises(Exception):
            train_anomaly_detector(df_empty, contamination=0.05)

    def test_single_class_dataset(self):
        """
        Verify training continues correctly if all true labels are identical (single class).
        """
        y_single = pd.Series(["Benign"] * 105)
        model, scaler, metrics = train_anomaly_detector(
            X=self.df_combined,
            contamination=0.05,
            y_ground_truth=y_single
        )
        self.assertIn("ground_truth_evaluation", metrics)
        # Since no true positive anomalies exist, F1 score is 0.0
        self.assertEqual(metrics["ground_truth_evaluation"]["f1_score"], 0.0)

    def test_missing_and_invalid_values(self):
        """
        Verify evaluation handles NaNs and missing feature entries gracefully.
        """
        record_nan = {"feat_0": None, "feat_1": "invalid_number", "feat_2": 0.5}
        res = evaluate_threat(
            predicted_attack="Benign",
            confidence=0.99,
            anomaly_status="Normal",
            anomaly_score=10.0,
            record_data=record_nan,
            benign_stats=self.benign_stats
        )
        # Should execute successfully without throwing ValueError or TypeError
        self.assertEqual(res["severity"], "Low")
        # Should not attempt feature deviation calculations on missing or non-numeric values
        self.assertNotIn("feat_0", res["feature_deviations"])
        self.assertNotIn("feat_1", res["feature_deviations"])


if __name__ == "__main__":
    unittest.main()
