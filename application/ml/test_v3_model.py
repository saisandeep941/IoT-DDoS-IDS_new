"""V3 model loading, threshold, feature-order, and legacy CSV schema checks."""

import csv
import hashlib
import json
from io import BytesIO, StringIO
from pathlib import Path
from unittest.mock import patch

import joblib
import numpy as np
import pandas as pd
import pytest
from fastapi import HTTPException
from starlette.datastructures import UploadFile

from backend import main


ROOT = Path(__file__).resolve().parents[2]
V3_DIR = ROOT / "model_v3"
V2_SCHEMA = joblib.load(ROOT / "application" / "backend" / "real_model_features_v2.joblib")


def make_upload(headers, values):
    stream = StringIO()
    writer = csv.writer(stream)
    writer.writerow(headers)
    writer.writerow(values)
    return UploadFile(filename="v3_test.csv", file=BytesIO(stream.getvalue().encode()))


def run_csv_prediction(upload, mode="balanced"):
    coroutine = main.predict_csv(upload, mode=mode)
    try:
        coroutine.send(None)
    except StopIteration as completed:
        return completed.value
    raise AssertionError("CSV prediction unexpectedly awaited asynchronous work")


def test_v3_model_loads_and_threshold_modes_flag_different_rows():
    v3 = main.load_v3_model()
    assert len(v3.features) == 47
    assert len(set(v3.features)) == 47
    assert not ({"Source Port", "Destination Port", "Protocol", "Inbound", "SimillarHTTP"} & set(v3.features))

    rng = np.random.default_rng(42)
    frame = pd.DataFrame(
        rng.uniform(-1e6, 1e6, size=(16, len(v3.features))),
        columns=v3.features,
    )
    probabilities = v3.predict_proba_attack(frame)
    balanced, _, balanced_threshold = v3.predict(frame, mode="balanced")
    strict, _, strict_threshold = v3.predict(frame, mode="strict")

    assert np.isfinite(probabilities).all()
    assert ((probabilities >= 0) & (probabilities <= 1)).all()
    assert (balanced_threshold, strict_threshold) == (0.5, 0.9988)
    assert int(strict.sum()) < int(balanced.sum())


def test_v3_feature_selection_preserves_saved_order_after_82_column_check():
    v3 = main.load_v3_model()
    seen = {}

    class StubV3:
        features = v3.features
        meta = v3.meta

        def predict_proba_attack(self, frame):
            seen["columns"] = list(frame.columns)
            return np.array([0.75])

    upload = make_upload(V2_SCHEMA + ["Label", "Timestamp"], [0] * len(V2_SCHEMA) + ["BENIGN", "t1"])
    with patch("backend.main.load_v3_model", return_value=StubV3()), patch(
        "backend.main.load_v2_schema", return_value=V2_SCHEMA
    ):
        result = run_csv_prediction(upload, mode="strict")

    assert seen["columns"] == v3.features
    assert result["total_rows"] == 1
    assert result["predicted_attacks"] == 0
    assert result["mode"] == "strict"
    assert result["threshold"] == 0.9988


def test_balanced_and_strict_modes_change_label_between_thresholds():
    v3 = main.load_v3_model()
    balanced, balanced_threshold = main.classify_attack_probability(v3, 0.75, "balanced")
    strict, strict_threshold = main.classify_attack_probability(v3, 0.75, "strict")
    assert (balanced, strict) == ("Attack", "Benign")
    assert (balanced_threshold, strict_threshold) == (0.5, 0.9988)


def test_csv_prediction_still_rejects_invalid_82_column_schema():
    v3 = main.load_v3_model()

    class StubV3:
        features = v3.features
        meta = v3.meta

        def predict_proba_attack(self, frame):
            raise AssertionError("Prediction must not run for an invalid schema")

    with patch("backend.main.load_v3_model", return_value=StubV3()), patch(
        "backend.main.load_v2_schema", return_value=V2_SCHEMA
    ):
        with pytest.raises(HTTPException) as error:
            run_csv_prediction(make_upload(["Label", "Timestamp"], ["BENIGN", "t1"]))
    assert error.value.status_code == 400
    assert "missing model features" in error.value.detail


def test_csv_schema_rejects_missing_v2_column_even_when_all_v3_features_exist():
    v3 = main.load_v3_model()

    class StubV3:
        features = v3.features
        meta = v3.meta

        def predict_proba_attack(self, frame):
            raise AssertionError("Prediction must not run for an invalid schema")

    headers = [name for name in V2_SCHEMA if name != "Destination Port"]
    headers += ["Label", "Timestamp"]
    values = [0] * len(headers)
    values[-2:] = ["BENIGN", "t1"]
    with patch("backend.main.load_v3_model", return_value=StubV3()), patch(
        "backend.main.load_v2_schema", return_value=V2_SCHEMA
    ):
        with pytest.raises(HTTPException) as error:
            run_csv_prediction(make_upload(headers, values))
    assert error.value.status_code == 400
    assert "Destination Port" in error.value.detail


def test_v3_export_hashes_match_metadata():
    metadata = json.loads((V3_DIR / "v3_metadata.json").read_text(encoding="utf-8"))
    for name, expected in metadata["sha256"].items():
        actual = hashlib.sha256((V3_DIR / name).read_bytes()).hexdigest()
        assert actual == expected
