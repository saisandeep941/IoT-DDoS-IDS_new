import pandas as pd
import io
import shap
import numpy as np
import os
import tempfile
import uuid
import csv
import json
import importlib.util
import hmac
from functools import lru_cache
from contextlib import asynccontextmanager
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi import UploadFile, File, HTTPException
from sklearn.metrics import confusion_matrix, classification_report
from datetime import datetime, timezone
from collections import deque
from datetime import datetime, timezone
from threading import Lock
from backend.detection_history import DetectionHistoryStore
from backend.dataset_validation import (
    DatasetSchemaError,
    validate_ground_truth_labels,
    validate_model_feature_columns,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
V3_DIR = PROJECT_ROOT / "model_v3"
V31_RESULTS_DIR = PROJECT_ROOT / "research" / "results_v31"
V2_SCHEMA_PATH = Path(__file__).resolve().parent / "real_model_features_v2.joblib"


@lru_cache(maxsize=1)
def _isotonic_mapping():
    try:
        return json.loads((V31_RESULTS_DIR / "isotonic_calibrator.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, KeyError, TypeError):
        return None


def calibrate_attack_probability(probability):
    """Apply the saved isotonic mapping; retain raw probability for fixed labels."""
    mapping = _isotonic_mapping()
    if mapping is None:
        return float(probability)
    return float(np.interp(float(probability), mapping["x_thresholds"], mapping["y_thresholds"]))


def load_v3_model():
    """Load the version-independent V3 artifacts through the supplied loader."""
    loader_path = V3_DIR / "v3_loader.py"
    spec = importlib.util.spec_from_file_location("project_v3_loader", loader_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load V3 loader from {loader_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.V3Model(folder=str(V3_DIR))


def load_v2_schema():
    """Load only the protected V2 feature names for strict CSV compatibility."""
    return joblib.load(V2_SCHEMA_PATH)


def threshold_for_mode(v3, mode):
    if mode not in {"balanced", "strict"}:
        raise HTTPException(status_code=400, detail="mode must be 'balanced' or 'strict'.")
    point = "balanced_default" if mode == "balanced" else "strict_low_fpr"
    return float(v3.meta["operating_points"][point]["threshold"])


def classify_attack_probability(v3, probability, mode):
    threshold = threshold_for_mode(v3, mode)
    return ("Attack" if float(probability) >= threshold else "Benign"), threshold


history_store = DetectionHistoryStore()
detection_records = deque(history_store.latest(), maxlen=history_store.limit)
detection_history_lock = Lock()
csv_replay_lock = Lock()
csv_replay = None


@asynccontextmanager
async def lifespan(_app):
    history_store.initialize()
    with detection_history_lock:
        detection_records.clear()
        detection_records.extend(history_store.latest())
    yield
    capture_controller.shutdown()


app = FastAPI(title="SentinelAI API", lifespan=lifespan)
from backend.capture_routes import router as capture_router, controller as capture_controller
app.include_router(capture_router)


@app.middleware("http")
async def require_configured_api_key(request: Request, call_next):
    api_key = os.getenv("SENTINEL_API_KEY")
    if api_key and request.url.path != "/api/health" and request.method != "OPTIONS":
        supplied = request.headers.get("X-API-Key", "")
        if not hmac.compare_digest(supplied, api_key):
            from starlette.responses import JSONResponse
            return JSONResponse(status_code=401, content={"detail": "A valid X-API-Key is required."})
    return await call_next(request)


def append_detection(prediction, risk_score, severity, source, **metadata):
    with detection_history_lock:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "prediction": prediction,
            "risk_score": round(float(risk_score), 2),
            "severity": severity,
            "source": source,
        }
        record.update(metadata)
        record = history_store.append(record)
        detection_records.appendleft(record)


def record_detection(prediction, risk_score, severity, source, **metadata):
    append_detection(prediction, risk_score, severity, source, **metadata)


def severity_for_risk_score(risk_score):
    """Apply the application's provisional severity thresholds consistently."""
    if risk_score >= 75:
        return "Critical"
    if risk_score >= 50:
        return "High"
    if risk_score >= 25:
        return "Medium"
    return "Low"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {
        "message": "SentinelAI API is running",
        "status": "success"
    }




@app.get("/api/dashboard")
def get_dashboard():
    with detection_history_lock:
        history = list(detection_records)

    total_traffic = len(history)
    attacks_detected = sum(
        1 for item in history
        if item["prediction"] == "Attack"
    )

    benign_detected = total_traffic - attacks_detected

    return {
        "total_traffic": total_traffic,
        "attacks_detected": attacks_detected,
        "threats_blocked": 0,
        "detection_rate": round(
            attacks_detected / total_traffic * 100, 2
        ) if total_traffic else 0,
        "mode": "simulated" if total_traffic else "waiting",
        "message": (
            "Showing recorded model predictions"
            if total_traffic
            else "Waiting for traffic data"
        ),
        "benign_detected": benign_detected,
    }



@app.get("/api/alerts")
def get_alerts():
    with detection_history_lock:
        alerts = [
            {
                "id": item["id"],
                "prediction": item["prediction"],
                "severity": item["severity"],
                "risk_score": item["risk_score"],
                "timestamp": item["timestamp"],
                "source": item["source"],
        **{key: item[key] for key in (
            "record_index", "traffic_timestamp", "replay_session_id", "explanation"
        ) if key in item},
            }
            for item in detection_records
            if item["prediction"] == "Attack"
        ]
    return {
        "alerts": alerts,
        "mode": "recorded_predictions",
        "message": "Alerts list only model predictions recorded in this backend session; no attack blocking is performed.",
    }


@app.get("/api/health")
def health():
    return {"status": "healthy"}

from pydantic import BaseModel
from typing import List

class PredictionRequest(BaseModel):
    features: List[float]

@app.post("/api/predict")
def predict(data: dict, mode: str = "balanced"):
    v3 = load_v3_model()
    feature_names = v3.features
    values = data.get("features")
    if not isinstance(values, list) or len(values) != len(feature_names):
        raise HTTPException(
            status_code=400,
            detail=f"Provide exactly {len(feature_names)} numeric V3 features in a 'features' list",
        )
    try:
        row = np.asarray(values, dtype=float)
        if not np.isfinite(row).all():
            raise ValueError("Features must be finite numbers")
        frame = pd.DataFrame([row], columns=feature_names)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Features must be finite numeric values")

    probability = float(v3.predict_proba_attack(frame)[0])
    prediction, threshold = classify_attack_probability(v3, probability, mode)
    calibrated_probability = calibrate_attack_probability(probability)
    risk = calibrated_probability * 100
    severity = severity_for_risk_score(risk)
    record_detection(
        prediction=prediction, risk_score=risk, severity=severity,
        source="V3-model API", mode=mode, threshold=threshold,
    )
    return {
        "prediction": prediction,
        "risk_score": round(risk, 2),
        "attack_probability": probability,
        "calibrated_attack_probability": calibrated_probability,
        "severity": severity,
        "model": "XGBoost V3",
        "features_required": len(feature_names),
        "mode": mode,
        "threshold": threshold,
        "severity_note": "Severity cutoffs are provisional, uncalibrated.",
    }



@app.post("/api/risk-score")
def calculate_risk_score(request: PredictionRequest, mode: str = "balanced"):
    v3 = load_v3_model()
    threshold = threshold_for_mode(v3, mode)
    features = request.features

    if not features:
        return {
            "risk_score": 0,
            "severity": "Unknown",
            "mode": mode,
            "threshold": threshold,
            "note": "No features supplied."
        }

    feature_names = v3.features

    if len(features) != len(feature_names):
        raise HTTPException(
            status_code=400,
            detail=f"Expected {len(feature_names)} V3 features, "
                   f"received {len(features)}."
        )

    values = np.asarray(features, dtype=float)

    if not np.isfinite(values).all():
        raise HTTPException(
            status_code=400,
            detail="Features must contain only finite numeric values."
        )

    X = pd.DataFrame([values], columns=feature_names)

    attack_probability = float(v3.predict_proba_attack(X)[0])
    calibrated_probability = calibrate_attack_probability(attack_probability)
    raw_risk_score = calibrated_probability * 100
    risk_score = round(raw_risk_score, 2)
    severity = severity_for_risk_score(raw_risk_score)
    predicted_label, threshold = classify_attack_probability(v3, attack_probability, mode)

    return {
        "risk_score": risk_score,
        "attack_probability": round(attack_probability, 4),
        "calibrated_attack_probability": round(calibrated_probability, 6),
        "predicted_class": predicted_label,
        "severity": severity,
        "mode": mode,
        "threshold": threshold,
        "severity_note": "Severity cutoffs are provisional, uncalibrated.",
        "note": (
            "Model-estimated attack probability expressed as a score "
            "from 0 to 100. Severity cutoffs are provisional, uncalibrated."
        )
    }



@app.post("/api/dataset/preview")
async def preview_dataset(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=400,
            detail="Please upload a CSV file."
        )

    content = await file.read()

    try:
        df = pd.read_csv(io.BytesIO(content), nrows=100)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Unable to read the CSV file."
        )

    return {
        "filename": file.filename,
        "rows_previewed": len(df),
        "columns": df.columns.tolist(),
        "preview": df.head(5).fillna("").to_dict(orient="records")
    }

@app.post("/api/model/train-sample")
def train_sample_model():
    dataset_path = Path(__file__).resolve().parent.parent / "dataset" / "sample_traffic.csv"

    if not dataset_path.exists():
        raise HTTPException(
            status_code=404,
            detail="sample_traffic.csv not found in dataset folder"
        )

    df = pd.read_csv(dataset_path)
    df.columns = df.columns.str.strip()

    if "Label" not in df.columns:
        raise HTTPException(
            status_code=400,
            detail="Dataset must contain a Label column"
        )

    X = df.drop(columns=["Label"])
    y = (df["Label"].astype(str).str.upper() != "BENIGN").astype(int)

    X = X.apply(pd.to_numeric, errors="coerce")
    base_dir = Path(__file__).resolve().parent
    medians = joblib.load(base_dir.parent / "ml" / "recovered_medians.joblib")
    X = X.replace([float("inf"), float("-inf")], float("nan"))
    X = X.fillna(pd.Series(medians)).fillna(0)

    if y.nunique() < 2 or y.value_counts().min() < 2:
        raise HTTPException(
            status_code=400,
            detail="Need at least two records from each class for training and testing"
        )

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.4, random_state=42, stratify=y
    )

    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X_train, y_train)

    accuracy = accuracy_score(y_test, model.predict(X_test))
    y_pred = model.predict(X_test)
    matrix = confusion_matrix(y_test, y_pred)
    report = classification_report(y_test,y_pred,
    output_dict=True,zero_division=0)

    model_path = Path(__file__).resolve().parent / "sample_model.joblib"
    joblib.dump(
        {"model": model, "features": X.columns.tolist()},
        model_path
    )

    return {
    "status": "success",
    "model": "Random Forest",
    "training_records": len(X_train),
    "testing_records": len(X_test),
    "accuracy": round(accuracy * 100, 2),
    "confusion_matrix": matrix.tolist(),
    "precision": round(report["1"]["precision"] * 100, 2),
    "recall": round(report["1"]["recall"] * 100, 2),
    "f1_score": round(report["1"]["f1-score"] * 100, 2),
    "warning": "Tiny synthetic sample only; metrics are not meaningful for real-world performance."
}


@app.get("/api/model/status")
def model_status():
    metadata_path = V3_DIR / "v3_metadata.json"
    required_paths = [
        metadata_path, V3_DIR / "v3_loader.py", V3_DIR / "v3_xgb_model.json",
        V3_DIR / "v3_features.json", V3_DIR / "v3_imputer_medians.json",
    ]
    model_exists = all(path.is_file() for path in required_paths)
    metadata = json.loads(metadata_path.read_text(encoding="utf-8")) if model_exists else {}
    return {
        "model_trained": model_exists,
        "model_name": "XGBoost V3",
        "active_model": "V3",
        "dataset": "CIC-DDoS2019",
        "feature_count": metadata.get("n_features", 47),
        "trained_on": metadata.get("trained_on", "CIC-DDoS2019 01-12 sample"),
        "evaluated_on": "CIC-DDoS2019 03-11 sample",
        "operating_points": metadata.get("operating_points", {}),
        "limitations": metadata.get("limitations", []),
        "calibration": _calibration_status(),
        "v2_reference_only": {"model_name": "Random Forest V2", "status": "reference only"},
        "status": "V3 model available" if model_exists else "V3 model not found",
    }


def _calibration_status():
    path = V31_RESULTS_DIR / "phase_c_calibration.json"
    try:
        results = json.loads(path.read_text(encoding="utf-8"))
        return {"method": "isotonic", "trained_on": "CIC-DDoS2019 03-11 UDPLag first time half", "evaluation": results["results"]}
    except (OSError, ValueError, KeyError, TypeError):
        return {"method": "unavailable"}


@app.get("/api/model/explain")
def explain_model():
    try:
        v3 = load_v3_model()
        frame = pd.DataFrame([v3.medians], columns=v3.features)
        prepared = v3.prepare(frame)
        probability = float(v3.predict_proba_attack(frame)[0])
        explanation = shap.TreeExplainer(v3.model)(prepared)
        values = np.asarray(explanation.values)
        if values.ndim == 3:
            values = values[0, :, 1]
        else:
            values = values.reshape(-1, len(v3.features))[0]
        importance = [
            {"feature": name, "impact": round(float(value), 6)}
            for name, value in zip(v3.features, values)
        ]
        importance.sort(key=lambda item: abs(item["impact"]), reverse=True)
        return {
            "status": "available",
            "method": "SHAP TreeExplainer",
            "model": "XGBoost V3",
            "explained_class": "Attack" if probability >= 0.5 else "Benign",
            "explanation": importance[:15],
            "note": "SHAP values for a median-feature reference profile; they are not causal explanations or a live-flow explanation.",
        }
    except Exception as exc:
        return {"status": "unavailable", "message": "SHAP explanations unavailable.", "reason": str(exc)}


@app.get("/api/model/feature-importance")
def feature_importance():
    v3 = load_v3_model()
    model = v3.model

    importance = sorted(
        [
            {"feature": name, "importance": float(value)}
            for name, value in zip(
                v3.features, model.feature_importances_
            )
        ],
    key=lambda item: item["importance"],
    reverse=True
    )


    return {
        "feature_importance": importance,
        "model": "Trained XGBoost V3",
        "note": "Feature importance from the trained CIC-DDoS2019 V3 model."
    }


@app.get("/api/detection-history")
def get_detection_history():
    with detection_history_lock:
        history = list(detection_records)

    return {
        "history": history,
        "count": len(history),
        "note": "Recent predictions recorded during this backend session."
    }


@app.get("/api/system/summary")
def system_summary():
    model_exists = (V3_DIR / "v3_xgb_model.json").is_file()

    return {
        "api_status": "healthy",
        "model_trained": model_exists,
        "model_type": "XGBoost V3 (V2 reference only)",
        "dataset": "CIC-DDoS2019",
        "mode": "real_model" if model_exists else "unavailable"
    }


@app.get("/api/system/metrics")
def system_metrics():
    model_exists = (V3_DIR / "v3_xgb_model.json").is_file()

    return {
        "api_status": "healthy",
        "model": "XGBoost V3" if model_exists else "Unavailable",
        "dataset": "CIC-DDoS2019" if model_exists else "Unavailable",
        "mode": "real_model" if model_exists else "unavailable"
    }


@app.get("/api/research/evaluation")
def saved_research_evaluation():
    """Expose saved results as recorded; do not recalculate or refit metrics."""
    results_dir = Path(__file__).resolve().parents[2] / "research" / "results"
    metadata_path = results_dir / "run_metadata_submission.json"
    baseline_path = results_dir / "baseline_results.csv"
    reference_path = results_dir / "deployed_v2_reference.csv"
    intervals_path = results_dir / "confidence_intervals.csv"
    efficiency_path = results_dir / "efficiency.csv"
    required = (metadata_path, baseline_path, reference_path, intervals_path, efficiency_path)
    if not all(path.is_file() for path in required):
        raise HTTPException(
            status_code=503,
            detail="Saved research evaluation artifacts are incomplete.",
        )

    def load_rows(path):
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            return list(csv.DictReader(stream))

    def result_row(row):
        return {
            "model": row["model"],
            "accuracy": float(row["accuracy"]),
            "precision": float(row["precision"]),
            "recall": float(row["recall"]),
            "f1": float(row["f1"]),
            "roc_auc": float(row["roc_auc"]),
            "average_precision": float(row["average_precision"]),
            "confusion_matrix": [
                [int(row["tn"]), int(row["fp"])],
                [int(row["fn"]), int(row["tp"])],
            ],
        }

    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        holdout = metadata["holdout"]
        training = metadata["training"]
        baselines = [result_row(row) for row in load_rows(baseline_path)]
        references = [result_row(row) for row in load_rows(reference_path)]
        confidence_intervals = [
            {
                "model": row["model"],
                "type": row["ci_type"],
                "metric": row["metric"],
                "lower_95": float(row["lower_95"]),
                "upper_95": float(row["upper_95"]),
                "replicates": int(row["replicates"]),
            }
            for row in load_rows(intervals_path)
        ]
        efficiency = [
            {
                "model": row["model"],
                "single_row_p50_ms": float(row["model_only_single_row_p50_ms"]),
                "single_row_p95_ms": float(row["model_only_single_row_p95_ms"]),
                "full_test_batch_rows_per_second": float(
                    row["full_test_batch_throughput_rows_per_second"]
                ),
                "latency_scope": row["latency_scope"],
                "throughput_scope": row["throughput_scope"],
            }
            for row in load_rows(efficiency_path)
        ]
        if len(references) != 1 or not baselines:
            raise ValueError("Unexpected saved result inventory")
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise HTTPException(
            status_code=503,
            detail=f"Unable to read saved research evaluation artifacts: {error}",
        ) from error

    return {
        "dataset": "CIC-DDoS2019-derived UDPLag.csv",
        "evaluation_type": "Same-source forward-time, tuple-purged research refit; frozen V2 is reference only",
        "positive_class": "ATTACK",
        "decision_threshold": 0.5,
        "test_rows": int(holdout["rows"]),
        "actual_class_counts": {
            "BENIGN": int(holdout["class_counts"]["BENIGN"]),
            "ATTACK": int(holdout["class_counts"]["ATTACK"]),
        },
        "protocol": {
            "natural_prevalence": bool(holdout["natural_prevalence"]),
            "gap_seconds": int(training["gap_seconds"]),
            "training_rows_purged_for_tuple_overlap": int(
                training["rows_removed_for_tuple_overlap"]
            ),
            "capture_session_independence": "unverified",
            "independent_dataset_evaluation": "not established",
        },
        "matched_research_refits": baselines,
        "frozen_v2_reference_only": references[0],
        "confidence_intervals": confidence_intervals,
        "efficiency": efficiency,
        "confusion_matrix_layout": "[[true benign, false attack], [missed attack, detected attack]]",
        "limitations": [
            "The frozen V2 result uses this previously evaluated UDPLag block and is reference-only, not independent validation.",
            "Matched models are research-only refits, not the deployed frozen V2 model.",
            "Capture/session independence is not verified; the available data has no capture IDs or PCAPs.",
            "Efficiency is model-only and batch throughput, not end-to-end API latency.",
        ],
    }


@app.get("/api/system/time")
def system_time():
    return {
        "server_time": datetime.now(timezone.utc).isoformat(),
        "status": "online"
    }
@app.get("/api/project/info")
def project_info():
    return {
        "title": "Intelligent Machine Learning-Based Intrusion Detection System for DDoS Attacks in IoT Networks",
        "dataset": "CIC-DDoS2019",
        "algorithm": "XGBoost V3 (V2 reference only)",
        "explainability": "SHAP",
        "frontend": "React",
        "backend": "FastAPI",
        "status": "Development"
    }


@app.post("/api/dataset/analyze")
async def analyze_dataset(file: UploadFile = File(...)):
    df = pd.read_csv(file.file, low_memory=False)
    df.columns = df.columns.str.strip()

    if "Label" not in df.columns:
        raise HTTPException(
            status_code=400,
            detail="CSV must contain a Label column"
        )

    labels = validate_ground_truth_labels(df["Label"])
    benign_count = int((labels == "BENIGN").sum())
    total = len(df)
    attack_count = total - benign_count

    return {
        "filename": file.filename,
        "total_traffic": total,
        "attacks_detected": attack_count,
        "benign_traffic": benign_count,
        "attack_types": {
            str(label): int(count)
            for label, count in labels[labels != "BENIGN"].value_counts().items()
        },
        "mode": "CSV analysis"
    }


def _iter_prediction_csv(file_obj):
    """Yield prediction CSV chunks or return a client error for invalid CSV input."""
    try:
        yield from pd.read_csv(file_obj, chunksize=10000, low_memory=False)
    except (pd.errors.ParserError, pd.errors.EmptyDataError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=400,
            detail="Unable to parse the uploaded CSV file.",
        ) from exc

@app.post("/api/predict/csv")
async def predict_csv(file: UploadFile = File(...), mode: str = "balanced"):
    from collections import deque
    from sklearn.metrics import confusion_matrix

    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Please upload a CSV file.")

    v3 = load_v3_model()
    schema_features = load_v2_schema()
    feature_names = v3.features
    threshold = threshold_for_mode(v3, mode)

    total_rows = 0
    predicted_attacks = 0
    predicted_benign = 0
    actual_counts = {0: 0, 1: 0}
    latest_risk_score = None
    cm = np.zeros((2, 2), dtype=np.int64)

    # Keep only a small sample of this upload's predictions.
    recent_samples = deque(maxlen=20)

    for chunk in _iter_prediction_csv(file.file):
        chunk.columns = chunk.columns.str.strip()
        try:
            validate_model_feature_columns(chunk.columns, schema_features)
        except DatasetSchemaError as error:
            raise HTTPException(
                status_code=400,
                detail=str(error),
            ) from error

        X = chunk[feature_names]
        X = X.apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)

        if X.isna().all(axis=1).any():
            raise HTTPException(
                status_code=400,
                detail="CSV contains rows with no valid numeric model features.",
            )

        probabilities = v3.predict_proba_attack(X)
        predictions = (probabilities >= threshold).astype(int)
        risks = np.asarray([calibrate_attack_probability(p) for p in probabilities]) * 100

        total_rows += len(chunk)
        predicted_attacks += int((predictions == 1).sum())
        predicted_benign += int((predictions == 0).sum())

        # Retain at most the latest 20 predictions from this upload.
        for prediction, risk in zip(predictions, risks):
            severity = severity_for_risk_score(risk)

            recent_samples.append({
                "prediction": "Attack" if prediction == 1 else "Benign",
                "risk_score": round(float(risk), 2),
                "severity": severity,
                "source": f"CSV upload: {file.filename}",
            })

        if "Label" in chunk.columns:
            labels = chunk["Label"].astype("string").str.strip().str.upper()

            if labels.isna().any() or labels.eq("").any():
                raise HTTPException(
                    status_code=400,
                    detail="CSV contains missing or empty Label values.",
                )

            actual = labels.ne("BENIGN").astype(int).to_numpy()
            cm += confusion_matrix(actual, predictions, labels=[0, 1])
            actual_counts[0] += int((actual == 0).sum())
            actual_counts[1] += int((actual == 1).sum())

    if total_rows == 0:
        raise HTTPException(status_code=400, detail="The CSV file is empty.")

    # Save the sampled predictions to the existing backend history.
    for sample in recent_samples:
        append_detection(**sample)

    result = {
        "filename": file.filename,
        "total_rows": total_rows,
        "predicted_attacks": predicted_attacks,
        "predicted_benign": predicted_benign,
        "model": "XGBoost V3",
        "mode": mode,
        "threshold": threshold,
        "severity_note": "Severity cutoffs are provisional, uncalibrated.",
        "history_records_added": len(recent_samples),
        "note": "Predictions are model estimates. History contains a sample of the latest CSV predictions.",
    }

    if actual_counts[0] + actual_counts[1] > 0:
        tn, fp, fn, tp = cm.ravel()
        result.update({
            "accuracy": round((tn + tp) / cm.sum(), 6),
            "precision": round(tp / (tp + fp), 6) if tp + fp else 0,
            "recall": round(tp / (tp + fn), 6) if tp + fn else 0,
            "f1_score": round(
                2 * tp / (2 * tp + fp + fn), 6
            ) if 2 * tp + fp + fn else 0,
            "confusion_matrix": cm.tolist(),
        })

    return result


@app.post("/api/stream/start")
def start_stream(request: PredictionRequest):
    raise HTTPException(
        status_code=410,
        detail="Synthetic feature streaming is disabled. Use CSV traffic replay simulation with source records.",
    )


def _close_csv_replay(state):
    if state is None:
        return
    reader = state.get("reader")
    if reader is not None:
        reader.close()
    path = state.get("path")
    if path:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def _csv_row_explanation(state, row, prediction):
    """Return per-row SHAP contributions, or an explicit unavailable status."""
    try:
        if state.get("explainer_error"):
            raise RuntimeError(state["explainer_error"])
        v3 = state["model"]
        prepared = v3.prepare(row)
        if state.get("explainer") is None:
            state["explainer"] = shap.TreeExplainer(v3.model)
        explanation = state["explainer"](prepared)
        values = np.asarray(explanation.values)
        if values.ndim == 3:
            impacts = values[0, :, int(prediction)]
        else:
            impacts = values.reshape(-1, len(v3.features))[0]
        names = v3.features
        top = sorted(
            zip(names, impacts.tolist()), key=lambda item: abs(float(item[1])), reverse=True
        )[:3]
        return {
            "status": "available",
            "method": "SHAP TreeExplainer",
            "note": "Feature contributions describe this model output; they are not causal explanations.",
            "top_features": [
                {"feature": name, "impact": round(float(value), 6)}
                for name, value in top
            ],
        }
    except Exception as error:
        state["explainer_error"] = str(error)
        return {"status": "unavailable", "reason": str(error)}


@app.post("/api/stream/replay/start")
def start_csv_replay(file: UploadFile = File(...), batch_size: int = 50, mode: str = "balanced"):
    """Start a paced simulation that replays CSV records through V3."""
    global csv_replay
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Please upload a CSV file.")
    if batch_size < 1 or batch_size > 200:
        raise HTTPException(status_code=400, detail="batch_size must be between 1 and 200.")

    with csv_replay_lock:
        if csv_replay and csv_replay["status"] in {"running", "paused"}:
            raise HTTPException(status_code=409, detail="A CSV replay session is already active.")

        v3 = load_v3_model()
        schema_features = load_v2_schema()
        feature_names = v3.features
        threshold = threshold_for_mode(v3, mode)
        if len(feature_names) != 47 or len(set(feature_names)) != 47:
            raise HTTPException(status_code=500, detail="Model feature configuration is invalid.")

        base_dir = Path(__file__).resolve().parent
        replay_dir = base_dir / ".csv_replay_tmp"
        replay_dir.mkdir(exist_ok=True)
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", suffix=".csv", prefix="replay_", dir=replay_dir, delete=False
            ) as temp_file:
                temp_path = temp_file.name
                while True:
                    block = file.file.read(1024 * 1024)
                    if not block:
                        break
                    temp_file.write(block)

            if os.path.getsize(temp_path) == 0:
                raise HTTPException(status_code=400, detail="The CSV file is empty.")
            header = pd.read_csv(temp_path, nrows=0, low_memory=False)
            header.columns = header.columns.str.strip()
            try:
                validate_model_feature_columns(header.columns, schema_features)
            except DatasetSchemaError as error:
                raise HTTPException(status_code=400, detail=str(error)) from error
            reader = pd.read_csv(temp_path, chunksize=batch_size, low_memory=False)
            try:
                first_chunk = next(reader)
            except StopIteration as error:
                reader.close()
                raise HTTPException(
                    status_code=400, detail="CSV contains a header but no data rows."
                ) from error
            if first_chunk.empty:
                reader.close()
                raise HTTPException(
                    status_code=400, detail="CSV contains a header but no data rows."
                )
            session_id = str(uuid.uuid4())
            csv_replay = {
                "id": session_id,
                "status": "running",
                "filename": Path(file.filename).name,
                "path": temp_path,
                "reader": reader,
                "pending_chunk": first_chunk,
                "model": v3,
                "feature_names": feature_names,
                "schema_features": schema_features,
                "mode": mode,
                "threshold": threshold,
                "batch_size": batch_size,
                "processed": 0,
                "attacks": 0,
                "benign": 0,
                "explainer": None,
                "explainer_error": None,
            }
            temp_path = None
            return {
                "status": "running", "mode": mode,
                "simulation": "CSV traffic replay simulation",
                "session_id": session_id, "filename": csv_replay["filename"],
                "batch_size": batch_size, "processed": 0,
                "detector_mode": mode, "threshold": threshold,
                "note": "Source CSV records are replayed through V3; this is not live capture. Labels, if present, are display-only.",
            }
        except HTTPException:
            raise
        except pd.errors.EmptyDataError as error:
            raise HTTPException(status_code=400, detail="CSV has no header or data rows.") from error
        except Exception as error:
            raise HTTPException(status_code=400, detail=f"Unable to read CSV: {error}") from error
        finally:
            file.file.close()
            if temp_path:
                try:
                    os.unlink(temp_path)
                except FileNotFoundError:
                    pass


@app.post("/api/stream/replay/next")
def advance_csv_replay():
    with csv_replay_lock:
        state = csv_replay
        if not state:
            raise HTTPException(status_code=409, detail="No CSV replay session exists.")
        if state["status"] != "running":
            return {
                "status": state["status"], "processed": state["processed"],
                "mode": state["mode"], "threshold": state["threshold"], "events": [],
            }
        try:
            chunk = state.pop("pending_chunk", None)
            if chunk is None:
                chunk = next(state["reader"])
        except StopIteration:
            state["status"] = "completed"
            _close_csv_replay(state)
            return {
                "status": "completed", "processed": state["processed"],
                "mode": state["mode"], "threshold": state["threshold"], "events": [],
            }
        except Exception as error:
            state["status"] = "error"
            state["error"] = f"Unable to read CSV replay: {error}"
            _close_csv_replay(state)
            return {
                "status": "error", "processed": state["processed"],
                "mode": state["mode"], "threshold": state["threshold"],
                "events": [], "error": state["error"],
            }

        chunk.columns = chunk.columns.str.strip()
        try:
            validate_model_feature_columns(chunk.columns, state["schema_features"])
            X = chunk[state["feature_names"]].apply(pd.to_numeric, errors="coerce")
            X = X.replace([np.inf, -np.inf], np.nan)
            if X.isna().all(axis=1).any():
                raise ValueError("CSV contains a row with no valid numeric model features.")
            if "Label" in chunk.columns:
                labels = validate_ground_truth_labels(chunk["Label"])
            else:
                labels = None
            probabilities = state["model"].predict_proba_attack(X)
            predictions = (probabilities >= state["threshold"]).astype(int)
            events = []
            for offset, (row_index, prediction, probability) in enumerate(
                zip(chunk.index, predictions, probabilities)
            ):
                numeric_index = state["processed"] + offset + 1
                risk = calibrate_attack_probability(probability) * 100
                prediction_label = "Attack" if prediction == 1 else "Benign"
                explanation = _csv_row_explanation(
                    state, X.iloc[[offset]], int(prediction)
                )
                traffic_timestamp = None
                if "Timestamp" in chunk.columns:
                    value = chunk.iloc[offset]["Timestamp"]
                    traffic_timestamp = None if pd.isna(value) else str(value)
                event = {
                    "prediction": prediction_label,
                    "risk_score": round(risk, 2),
                    "severity": severity_for_risk_score(risk),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source": f"CSV traffic replay simulation: {state['filename']}",
                    "record_index": numeric_index,
                    "traffic_timestamp": traffic_timestamp,
                    "replay_session_id": state["id"],
                    "explanation": explanation,
                    "mode": state["mode"],
                    "threshold": state["threshold"],
                }
                if labels is not None:
                    event["ground_truth"] = "Benign" if labels.iloc[offset] == "BENIGN" else "Attack"
                append_detection(**event)
                events.append(event)
            state["processed"] += len(events)
            state["attacks"] += sum(item["prediction"] == "Attack" for item in events)
            state["benign"] += sum(item["prediction"] == "Benign" for item in events)
            return {
                "status": "running", "processed": state["processed"],
                "predicted_attacks": state["attacks"], "predicted_benign": state["benign"],
                "mode": state["mode"], "threshold": state["threshold"],
                "events": events,
            }
        except HTTPException as error:
            state["status"] = "error"
            state["error"] = error.detail
            _close_csv_replay(state)
            raise
        except Exception as error:
            state["status"] = "error"
            state["error"] = f"CSV replay failed: {error}"
            _close_csv_replay(state)
            raise HTTPException(status_code=400, detail=state["error"]) from error


@app.post("/api/stream/replay/{action}")
def control_csv_replay(action: str):
    global csv_replay
    if action not in {"pause", "resume", "stop", "clear"}:
        raise HTTPException(status_code=404, detail="Unknown replay action.")
    with csv_replay_lock:
        if action == "clear":
            if csv_replay:
                replay_id = csv_replay["id"]
                if csv_replay["status"] in {"running", "paused"}:
                    csv_replay["status"] = "stopped"
                    _close_csv_replay(csv_replay)
                csv_replay = None
                with detection_history_lock:
                    retained = [item for item in detection_records if item.get("replay_session_id") != replay_id]
                    detection_records.clear()
                    detection_records.extend(retained)
                    history_store.remove_replay(replay_id)
            return {"status": "cleared", "processed": 0}
        if not csv_replay:
            raise HTTPException(status_code=409, detail="No CSV replay session exists.")
        if action == "pause" and csv_replay["status"] == "running":
            csv_replay["status"] = "paused"
        elif action == "resume" and csv_replay["status"] == "paused":
            csv_replay["status"] = "running"
        elif action == "stop" and csv_replay["status"] in {"running", "paused"}:
            csv_replay["status"] = "stopped"
            _close_csv_replay(csv_replay)
        return {"status": csv_replay["status"], "processed": csv_replay["processed"]}


@app.post("/api/stream/csv")
async def stream_csv(file: UploadFile = File(...), mode: str = "balanced"):

    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=400,
            detail="Please upload a CSV file.",
        )

    v3 = load_v3_model()
    feature_names = v3.features
    schema_features = load_v2_schema()
    threshold = threshold_for_mode(v3, mode)
    if len(feature_names) != 47 or len(set(feature_names)) != 47:
        raise HTTPException(
            status_code=500,
            detail="Model feature configuration is invalid.",
        )

    total_rows = 0
    attacks = 0
    benign = 0
    batches = []

    try:
        for chunk in pd.read_csv(
            file.file, chunksize=1000, low_memory=False
        ):
            chunk.columns = chunk.columns.str.strip()
            try:
                validate_model_feature_columns(chunk.columns, schema_features)
            except DatasetSchemaError as error:
                raise HTTPException(
                    status_code=400,
                    detail=str(error),
                ) from error

            X = chunk[feature_names].apply(pd.to_numeric, errors="coerce")
            X = X.replace([np.inf, -np.inf], np.nan)

            if X.isna().all(axis=1).any():
                raise HTTPException(
                    status_code=400,
                    detail="CSV contains rows with no valid numeric features.",
                )

            probabilities = v3.predict_proba_attack(X)
            predictions = (probabilities >= threshold).astype(int)
            latest_risk_score = round(calibrate_attack_probability(probabilities[-1]) * 100, 2)

            for prediction, probability in zip(predictions, probabilities):
                risk_score = calibrate_attack_probability(probability) * 100

                severity = severity_for_risk_score(risk_score)
                prediction_label = "Attack" if prediction == 1 else "Benign"

                record_detection(
                    prediction=prediction_label,
                    risk_score=risk_score,
                    severity=severity,
                    source="CSV batch stream",
                )

            batch_attacks = int((predictions == 1).sum())
            batch_benign = int((predictions == 0).sum())

            total_rows += len(chunk)
            attacks += batch_attacks
            benign += batch_benign

            batches.append({
                "batch": len(batches) + 1,
                "rows_processed": total_rows,
                "batch_attacks": batch_attacks,
                "batch_benign": batch_benign,
            })

    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=f"Unable to process CSV: {error}",
        )

    return {
        "status": "completed",
        "mode": mode,
        "simulation": "CSV batch simulation",
        "filename": file.filename,
        "total_rows": total_rows,
        "attacks_detected": attacks,
        "benign_traffic": benign,
        "batch_size": 1000,
        "threshold": threshold,
        "severity_note": "Severity cutoffs are provisional, uncalibrated.",
        "batches": batches,
        "note": "CSV records were processed in batches; this is not live packet capture.",
        "latest_risk_score": latest_risk_score,
    }
