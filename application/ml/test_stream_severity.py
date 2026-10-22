"""Focused tests for consistent provisional risk-to-severity mapping."""

from io import BytesIO
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import joblib
import numpy as np
import pandas as pd
from starlette.datastructures import UploadFile

from backend.main import severity_for_risk_score, stream_csv

FEATURE_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "backend"
    / "real_model_features_v2.joblib"
)


def invoke_handler(coroutine):
    try:
        coroutine.send(None)
    except StopIteration as completed:
        return completed.value


class StreamSeverityTests(unittest.TestCase):
    def test_provisional_thresholds_are_consistent_at_boundaries(self):
        cases = [
            (24.99, "Low"),
            (25, "Medium"),
            (49.99, "Medium"),
            (50, "High"),
            (74.99, "High"),
            (75, "Critical"),
        ]
        for risk_score, expected in cases:
            with self.subTest(risk_score=risk_score):
                self.assertEqual(severity_for_risk_score(risk_score), expected)

    def test_csv_stream_uses_probability_severity_for_benign_prediction(self):
        features = joblib.load(FEATURE_SCHEMA_PATH)
        mock_model = Mock()
        mock_model.classes_ = np.array([1, 0])
        mock_model.predict.return_value = np.array([0])
        mock_model.predict_proba.return_value = np.array([[0.6, 0.4]])
        chunk = pd.DataFrame([{feature: 0 for feature in features}])

        with (
            patch("backend.main.joblib.load", side_effect=[mock_model, features]),
            patch("backend.main.pd.read_csv", return_value=iter([chunk])),
            patch("backend.main.record_detection") as record_detection,
        ):
            result = invoke_handler(
                stream_csv(
                    UploadFile(filename="temporary.csv", file=BytesIO(b"mock"))
                )
            )

        self.assertEqual(result["benign_traffic"], 1)
        self.assertEqual(record_detection.call_args.kwargs["prediction"], "Benign")
        self.assertEqual(record_detection.call_args.kwargs["risk_score"], 60.0)
        self.assertEqual(record_detection.call_args.kwargs["severity"], "High")


if __name__ == "__main__":
    unittest.main()
