"""Focused checks for model risk-score validation and SHAP failure paths."""

import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import numpy as np
import pandas as pd
from fastapi import HTTPException

from backend.main import PredictionRequest, calculate_risk_score, explain_model, predict


FEATURES = [f"feature_{index}" for index in range(82)]


class RiskAndExplanationTests(unittest.TestCase):
    def test_predict_uses_attack_class_index_when_classes_are_reversed(self):
        model = Mock()
        model.classes_ = np.array([1, 0])
        model.predict.return_value = np.array([0])
        model.predict_proba.return_value = np.array([[0.2, 0.8]])
        with (
            patch("backend.main.joblib.load", side_effect=[model, FEATURES]),
            patch("backend.main.record_detection") as record_detection,
        ):
            result = predict({"features": [0.0] * 82})

        self.assertEqual(result["prediction"], "Benign")
        self.assertEqual(result["risk_score"], 20.0)
        self.assertEqual(result["severity"], "Low")
        self.assertEqual(record_detection.call_args.kwargs["prediction"], "Benign")
        self.assertEqual(record_detection.call_args.kwargs["risk_score"], 20.0)

    def test_predict_fails_closed_if_model_has_no_attack_class(self):
        model = Mock()
        model.classes_ = np.array([0])
        model.predict.return_value = np.array([0])
        model.predict_proba.return_value = np.array([[1.0]])
        with (
            patch("backend.main.joblib.load", side_effect=[model, FEATURES]),
            patch("backend.main.record_detection") as record_detection,
        ):
            with self.assertRaises(HTTPException) as raised:
                predict({"features": [0.0] * 82})

        self.assertEqual(raised.exception.status_code, 500)
        self.assertEqual(
            raised.exception.detail,
            "The model does not contain the expected attack class.",
        )
        record_detection.assert_not_called()

    def test_risk_score_rejects_wrong_length_and_nonfinite_values(self):
        model = Mock()
        with patch("backend.main.joblib.load", side_effect=[model, FEATURES] * 2):
            for values, detail in (
                ([0.0] * 81, "Expected 82 features, received 81."),
                ([0.0] * 81 + [float("nan")], "Features must contain only finite numeric values."),
            ):
                with self.subTest(detail=detail):
                    with self.assertRaises(HTTPException) as raised:
                        calculate_risk_score(PredictionRequest(features=values))
                    self.assertEqual(raised.exception.status_code, 400)
                    self.assertEqual(raised.exception.detail, detail)

    def test_risk_score_uses_attack_class_probability_for_risk(self):
        model = Mock()
        model.classes_ = np.array([1, 0])
        model.predict.return_value = np.array([1])
        model.predict_proba.return_value = np.array([[0.75, 0.25]])
        with patch("backend.main.joblib.load", side_effect=[model, FEATURES]):
            result = calculate_risk_score(PredictionRequest(features=[0.0] * 82))

        self.assertEqual(result["risk_score"], 75)
        self.assertEqual(result["attack_probability"], 0.75)
        self.assertEqual(result["predicted_class"], "Attack")
        self.assertEqual(result["severity"], "Critical")
        self.assertIn("provisional", result["note"])

    def test_risk_severity_uses_unrounded_boundary_and_model_class(self):
        model = Mock()
        model.classes_ = np.array([0, 1])
        model.predict.return_value = np.array([0])
        model.predict_proba.return_value = np.array([[0.754, 0.246]])
        with patch("backend.main.joblib.load", side_effect=[model, FEATURES]):
            result = calculate_risk_score(PredictionRequest(features=[0.0] * 82))

        self.assertEqual(result["risk_score"], 25)
        self.assertEqual(result["severity"], "Low")
        self.assertEqual(result["predicted_class"], "Benign")

    def test_explanation_reports_missing_optional_dataset(self):
        exists = Path.exists

        def model_files_exist(path):
            if path.name == "UDPLag.csv":
                return False
            return exists(path)

        with patch.object(Path, "exists", model_files_exist):
            with self.assertRaises(HTTPException) as raised:
                explain_model()

        self.assertEqual(raised.exception.status_code, 404)
        self.assertEqual(raised.exception.detail, "UDPLag dataset not found")

    def test_explanation_failure_is_reported_without_fabricated_output(self):
        imputer = Mock()
        imputer.transform.return_value = np.zeros((1, len(FEATURES)))
        model = Mock()
        model.classes_ = np.array([0, 1])
        pipeline = Mock()
        pipeline.named_steps = {"imputer": imputer, "model": model}
        pipeline.predict.return_value = np.array([0])
        sample = pd.DataFrame([{feature: 0 for feature in FEATURES}])

        with (
            patch.object(Path, "exists", return_value=True),
            patch("backend.main.joblib.load", side_effect=[pipeline, FEATURES]),
            patch("backend.main.pd.read_csv", return_value=sample),
            patch("backend.main.shap.TreeExplainer", side_effect=RuntimeError("test explainer failure")),
        ):
            with self.assertRaises(HTTPException) as raised:
                explain_model()

        self.assertEqual(raised.exception.status_code, 500)
        self.assertEqual(
            raised.exception.detail,
            "SHAP explanation failed: test explainer failure",
        )

    def test_shap_explanation_uses_the_sample_predicted_class(self):
        imputer = Mock()
        imputer.transform.return_value = np.zeros((1, len(FEATURES)))
        model = Mock()
        model.classes_ = np.array([0, 1])
        pipeline = Mock()
        pipeline.named_steps = {"imputer": imputer, "model": model}
        pipeline.predict.return_value = np.array([0])
        sample = pd.DataFrame([{feature: 0 for feature in FEATURES}])
        explainer = Mock()
        explainer.shap_values.return_value = [
            np.zeros((1, len(FEATURES))),
            np.ones((1, len(FEATURES))),
        ]

        with (
            patch.object(Path, "exists", return_value=True),
            patch("backend.main.joblib.load", side_effect=[pipeline, FEATURES]),
            patch("backend.main.pd.read_csv", return_value=sample),
            patch("backend.main.shap.TreeExplainer", return_value=explainer),
        ):
            result = explain_model()

        self.assertEqual(result["explained_class"], "Benign")
        self.assertTrue(all(item["impact"] == 0 for item in result["explanation"]))
        self.assertIn("not an explanation for the latest dashboard prediction", result["note"])


if __name__ == "__main__":
    unittest.main()
