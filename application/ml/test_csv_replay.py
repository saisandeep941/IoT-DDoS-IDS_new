"""Focused tests for frozen-model CSV traffic replay validation and controls."""

import csv
import json
from io import BytesIO, StringIO
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import joblib
import numpy as np
from fastapi import HTTPException
from starlette.datastructures import UploadFile

from backend import main

FEATURE_PATH = Path(__file__).resolve().parents[1] / "backend" / "real_model_features_v2.joblib"
FEATURES = joblib.load(FEATURE_PATH)
V3_FEATURES = json.loads((Path(__file__).resolve().parents[2] / "model_v3" / "v3_features.json").read_text(encoding="utf-8"))


def make_csv(headers=None, rows=None):
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(headers if headers is not None else FEATURES + ["Label", "Timestamp"])
    writer.writerows(rows if rows is not None else [[0] * len(FEATURES) + ["BENIGN", "t1"], [1] * len(FEATURES) + ["UDP", "t2"]])
    return output.getvalue().encode()


def start(payload, batch_size=2):
    return main.start_csv_replay(
        UploadFile(filename="replay.csv", file=BytesIO(payload)), batch_size=batch_size
    )


class CsvReplayTests(unittest.TestCase):
    def setUp(self):
        with main.detection_history_lock:
            self.history = list(main.detection_records)
        main.control_csv_replay("clear")
        self.model = Mock()
        self.model.features = V3_FEATURES
        self.model.meta = {"operating_points": {
            "balanced_default": {"threshold": 0.5},
            "strict_low_fpr": {"threshold": 0.9988},
        }}
        self.model.prepare.side_effect = lambda frame: frame
        self.model.predict_proba_attack.side_effect = lambda frame: np.array(
            [0.4 if value == 0 else 0.9 for value in frame["Flow Duration"]]
        )
        self.load_patch = patch("backend.main.load_v3_model", return_value=self.model)
        self.schema_patch = patch("backend.main.load_v2_schema", return_value=FEATURES)
        self.load_patch.start()
        self.schema_patch.start()
        self.shap_patch = patch("backend.main.shap.TreeExplainer", side_effect=RuntimeError("test explainer unavailable"))
        self.shap_patch.start()

    def tearDown(self):
        self.load_patch.stop()
        self.schema_patch.stop()
        self.shap_patch.stop()
        main.control_csv_replay("clear")
        with main.detection_history_lock:
            main.detection_records.clear()
            main.detection_records.extend(self.history)

    def test_csv_replay_uses_ordered_source_records_and_controls(self):
        started = start(make_csv())
        self.assertEqual(started["mode"], "balanced")
        self.assertEqual(started["simulation"], "CSV traffic replay simulation")
        self.assertEqual(started["threshold"], 0.5)
        with self.assertRaises(HTTPException) as conflict:
            start(make_csv())
        self.assertEqual(conflict.exception.status_code, 409)

        batch = main.advance_csv_replay()
        self.assertEqual(batch["processed"], 2)
        self.assertEqual([event["prediction"] for event in batch["events"]], ["Benign", "Attack"])
        self.assertEqual(batch["events"][0]["risk_score"], round(main.calibrate_attack_probability(0.4) * 100, 2))
        self.assertEqual(batch["events"][0]["severity"], main.severity_for_risk_score(batch["events"][0]["risk_score"]))
        self.assertEqual(batch["events"][0]["mode"], "balanced")
        self.assertEqual(batch["events"][0]["ground_truth"], "Benign")
        self.assertEqual(batch["events"][0]["traffic_timestamp"], "t1")
        self.assertEqual(batch["events"][0]["explanation"]["status"], "unavailable")
        with main.detection_history_lock:
            self.assertTrue(any(record.get("replay_session_id") == started["session_id"] for record in main.detection_records))

        self.assertEqual(main.control_csv_replay("pause")["status"], "paused")
        self.assertEqual(main.advance_csv_replay()["events"], [])
        self.assertEqual(main.control_csv_replay("resume")["status"], "running")
        self.assertEqual(main.advance_csv_replay()["status"], "completed")
        self.assertEqual(main.control_csv_replay("clear")["status"], "cleared")
        with main.detection_history_lock:
            self.assertFalse(any(record.get("replay_session_id") == started["session_id"] for record in main.detection_records))

    def test_replay_rejects_reordered_missing_and_empty_csv(self):
        reordered = FEATURES.copy()
        reordered[0], reordered[1] = reordered[1], reordered[0]
        for payload in (make_csv(headers=reordered, rows=[[0] * len(reordered)]), b""):
            with self.subTest(payload_size=len(payload)):
                with self.assertRaises(HTTPException) as raised:
                    start(payload)
                self.assertEqual(raised.exception.status_code, 400)

        missing = FEATURES[1:] + ["Label"]
        with self.assertRaises(HTTPException) as raised:
            start(make_csv(headers=missing, rows=[[0] * len(missing)]))
        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn(FEATURES[0], str(raised.exception.detail))

        with self.assertRaises(HTTPException) as raised:
            start(make_csv(headers=FEATURES + ["Label"], rows=[]))
        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn("no data rows", raised.exception.detail)

    def test_synthetic_zero_vector_endpoint_is_disabled(self):
        with self.assertRaises(HTTPException) as raised:
            main.start_stream(main.PredictionRequest(features=[0.0] * 82))
        self.assertEqual(raised.exception.status_code, 410)

    def test_replay_rejects_blank_ground_truth_without_recording_predictions(self):
        payload = make_csv(rows=[[0] * len(FEATURES) + ["  ", "t1"]])
        start(payload)
        with self.assertRaises(HTTPException) as raised:
            main.advance_csv_replay()
        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn("missing or empty Label", raised.exception.detail)
        self.assertEqual(main.csv_replay["status"], "error")
        with main.detection_history_lock:
            self.assertFalse(any(record.get("replay_session_id") == main.csv_replay["id"] for record in main.detection_records))


if __name__ == "__main__":
    unittest.main()
