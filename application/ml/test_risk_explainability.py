"""Checks for V3 probability-based decisions and SHAP availability behavior."""

import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import numpy as np
from fastapi import HTTPException

from backend import main


V3_DIR = Path(__file__).resolve().parents[2] / "model_v3"
FEATURES = json.loads((V3_DIR / "v3_features.json").read_text(encoding="utf-8"))


def fake_v3(probability):
    return SimpleNamespace(
        features=FEATURES,
        meta={"operating_points": {
            "balanced_default": {"threshold": 0.5},
            "strict_low_fpr": {"threshold": 0.9988},
        }},
        model=object(),
        medians=np.zeros(len(FEATURES)),
        prepare=lambda frame: frame,
        predict_proba_attack=lambda frame: np.full(len(frame), probability),
    )


class RiskAndExplanationTests(unittest.TestCase):
    def test_predict_uses_balanced_probability_threshold(self):
        with patch("backend.main.load_v3_model", return_value=fake_v3(0.75)), patch(
            "backend.main.record_detection"
        ) as record_detection:
            result = main.predict({"features": [0.0] * 47}, mode="balanced")

        self.assertEqual(result["prediction"], "Attack")
        self.assertEqual(result["risk_score"], round(main.calibrate_attack_probability(0.75) * 100, 2))
        self.assertEqual(result["threshold"], 0.5)
        self.assertEqual(result["mode"], "balanced")
        self.assertEqual(record_detection.call_args.kwargs["prediction"], "Attack")

    def test_predict_fails_for_wrong_v3_feature_count(self):
        with patch("backend.main.load_v3_model", return_value=fake_v3(0.2)):
            with self.assertRaises(HTTPException) as raised:
                main.predict({"features": [0.0] * 82})
        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn("exactly 47", raised.exception.detail)

    def test_risk_score_rejects_wrong_length_and_nonfinite_values(self):
        with patch("backend.main.load_v3_model", return_value=fake_v3(0.2)):
            for values, detail in (
                ([0.0] * 46, "Expected 47 V3 features, received 46."),
                ([0.0] * 46 + [float("nan")], "Features must contain only finite numeric values."),
            ):
                with self.subTest(detail=detail):
                    with self.assertRaises(HTTPException) as raised:
                        main.calculate_risk_score(main.PredictionRequest(features=values))
                    self.assertEqual(raised.exception.status_code, 400)
                    self.assertEqual(raised.exception.detail, detail)

    def test_risk_score_uses_probability_for_risk_and_mode_label(self):
        with patch("backend.main.load_v3_model", return_value=fake_v3(0.75)):
            balanced = main.calculate_risk_score(
                main.PredictionRequest(features=[0.0] * 47), mode="balanced"
            )
            strict = main.calculate_risk_score(
                main.PredictionRequest(features=[0.0] * 47), mode="strict"
            )

        self.assertEqual(balanced["risk_score"], round(main.calibrate_attack_probability(0.75) * 100, 2))
        self.assertEqual(balanced["predicted_class"], "Attack")
        self.assertEqual(strict["predicted_class"], "Benign")
        self.assertEqual(strict["threshold"], 0.9988)
        self.assertIn("provisional, uncalibrated", strict["severity_note"])

    def test_severity_uses_probability_score_and_existing_cutoffs(self):
        with patch("backend.main.load_v3_model", return_value=fake_v3(0.246)):
            result = main.calculate_risk_score(
                main.PredictionRequest(features=[0.0] * 47)
            )
        self.assertEqual(result["risk_score"], round(main.calibrate_attack_probability(0.246) * 100, 2))
        self.assertEqual(result["severity"], "Low")
        self.assertEqual(result["predicted_class"], "Benign")

    def test_explanation_reports_unavailable_when_tree_explainer_fails(self):
        with patch("backend.main.load_v3_model", return_value=fake_v3(0.6)), patch(
            "backend.main.shap.TreeExplainer", side_effect=RuntimeError("test explainer failure")
        ):
            result = main.explain_model()
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["message"], "SHAP explanations unavailable.")

    def test_explanation_uses_v3_model_and_prepared_frame(self):
        v3 = fake_v3(0.6)
        explanation_values = np.ones((1, len(FEATURES)))
        explainer = Mock()
        explainer.return_value = SimpleNamespace(values=explanation_values)
        with patch("backend.main.load_v3_model", return_value=v3), patch(
            "backend.main.shap.TreeExplainer", return_value=explainer
        ) as tree_explainer:
            result = main.explain_model()
        tree_explainer.assert_called_once_with(v3.model)
        explainer.assert_called_once()
        self.assertEqual(result["status"], "available")
        self.assertEqual(result["model"], "XGBoost V3")
        self.assertEqual(len(result["explanation"]), 15)


if __name__ == "__main__":
    unittest.main()
