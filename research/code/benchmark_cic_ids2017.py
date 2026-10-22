"""Independent, day-held-out CIC-IDS2017 binary-classification benchmark.

This experiment trains new research models on Monday--Thursday CIC-IDS2017
flows and evaluates them on every valid Friday row. It does not load or call
the frozen Random Forest V2 model.
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET = Path(r"C:\Users\bonus\Desktop\CIC-IDS2017-Benchmark\MachineLearningCVE")
DEFAULT_OUTPUT = ROOT / "research" / "results" / "cic_ids2017_benchmark"
SCHEMA_PATH = ROOT / "model" / "real_model_features_v2.joblib"
V2_MODEL_PATH = ROOT / "model" / "real_model_v2.joblib"
EXPECTED_SCHEMA_SHA256 = "C49933ABE8DF5A693915BD788153BCB7302D75AAB486A65E6B07E0A1ABCC3E28"
EXPECTED_MODEL_SHA256 = "61AF42BE7F2B079E4BF6FE8D766373CD1D2F91966B28E6BF722810DE53F4D9D2"
EXPECTED_FEATURE_COUNT = 78
EXPECTED_DAY_FILE_COUNTS = {"monday": 1, "tuesday": 1, "wednesday": 1, "thursday": 2, "friday": 3}
MISSING_TOKENS = {"", "na", "n/a", "nan", "null", "none"}


class DatasetFormatError(ValueError):
    """Raised when the CSV structure cannot be interpreted safely."""


@dataclass
class FileStats:
    rows_read: int = 0
    malformed_rows: int = 0
    blank_labels: int = 0
    label_counts: Counter = field(default_factory=Counter)
    class_counts: Counter = field(default_factory=Counter)
    missing_by_feature: Counter = field(default_factory=Counter)
    invalid_numeric_by_feature: Counter = field(default_factory=Counter)
    infinite_by_feature: Counter = field(default_factory=Counter)
    all_features_missing_rows: int = 0

    def to_dict(self) -> dict:
        return {
            "rows_read": self.rows_read,
            "malformed_rows_skipped": self.malformed_rows,
            "blank_labels_skipped": self.blank_labels,
            "valid_label_rows": sum(self.label_counts.values()),
            "raw_label_counts": dict(sorted(self.label_counts.items())),
            "binary_class_counts": {
                "BENIGN_0": int(self.class_counts.get(0, 0)),
                "ATTACK_1": int(self.class_counts.get(1, 0)),
            },
            "missing_values_by_feature": dict(sorted(self.missing_by_feature.items())),
            "invalid_numeric_values_by_feature": dict(sorted(self.invalid_numeric_by_feature.items())),
            "infinite_values_by_feature": dict(sorted(self.infinite_by_feature.items())),
            "all_features_missing_rows": self.all_features_missing_rows,
        }


def sha256_file(path: Path, block_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while block := stream.read(block_size):
            digest.update(block)
    return digest.hexdigest().upper()


def unique_column_names(raw_names: list[str]) -> list[str]:
    """Trim headers and suffix repeated names deterministically (name.1, name.2...)."""
    names = [str(name).strip() for name in raw_names]
    reserved = set(names)
    used: set[str] = set()
    occurrences: Counter = Counter()
    result = []
    for name in names:
        occurrence = occurrences[name]
        candidate = name
        if candidate in used:
            suffix = max(1, occurrence)
            candidate = f"{name}.{suffix}"
            while candidate in used or candidate in reserved:
                suffix += 1
                candidate = f"{name}.{suffix}"
        occurrences[name] += 1
        used.add(candidate)
        result.append(candidate)
    return result


def map_label(value: str) -> int | None:
    """Map BENIGN to 0 and every nonblank attack label to 1."""
    normalized = str(value).strip()
    if normalized.casefold() in MISSING_TOKENS:
        return None
    return 0 if normalized.upper() == "BENIGN" else 1


def split_dataset_files(files: list[Path]) -> tuple[list[Path], list[Path]]:
    """Return Monday--Thursday training files and all Friday test files."""
    by_day: dict[str, list[Path]] = {day: [] for day in EXPECTED_DAY_FILE_COUNTS}
    for path in files:
        lowered = path.name.casefold()
        matching = [day for day in by_day if lowered.startswith(day)]
        if len(matching) != 1:
            raise DatasetFormatError(f"Cannot assign CSV to a CIC-IDS2017 weekday: {path.name}")
        by_day[matching[0]].append(path)
    observed = {day: len(paths) for day, paths in by_day.items()}
    if observed != EXPECTED_DAY_FILE_COUNTS:
        raise DatasetFormatError(
            f"Expected CIC-IDS2017 day/file inventory {EXPECTED_DAY_FILE_COUNTS}, found {observed}."
        )
    training = sorted((p for day in ("monday", "tuesday", "wednesday", "thursday") for p in by_day[day]), key=lambda p: p.name.casefold())
    testing = sorted(by_day["friday"], key=lambda p: p.name.casefold())
    if {p.resolve() for p in training} & {p.resolve() for p in testing}:
        raise DatasetFormatError("Training and test file paths overlap.")
    return training, testing


def shared_feature_names(columns: list[str], schema: list[str], expected_count: int = EXPECTED_FEATURE_COUNT) -> tuple[list[str], list[str]]:
    """Select present schema features in V2 order; never fabricate missing fields."""
    available = set(columns)
    selected = [name for name in schema if name in available]
    missing = [name for name in schema if name not in available]
    if len(selected) != expected_count:
        raise DatasetFormatError(
            f"Expected {expected_count} features shared with V2; found {len(selected)}. Missing: {missing}"
        )
    if len(selected) != len(set(selected)):
        raise DatasetFormatError("Selected feature names are not unique.")
    return selected, missing


def read_header(path: Path) -> list[str]:
    try:
        with Path(path).open("r", encoding="utf-8-sig", newline="") as stream:
            raw = next(csv.reader(stream, strict=True))
    except (OSError, StopIteration, csv.Error, UnicodeDecodeError) as error:
        raise DatasetFormatError(f"Unable to read CSV header from {path.name}: {error}") from error
    columns = unique_column_names(raw)
    if len(columns) != len(set(columns)):
        raise DatasetFormatError(f"Unable to disambiguate duplicate columns in {path.name}.")
    if columns.count("Label") != 1:
        raise DatasetFormatError(f"{path.name} must have exactly one Label column.")
    return columns


def _numeric_frame(raw_rows: list[list[str]], features: list[str], stats: FileStats) -> np.ndarray:
    frame = pd.DataFrame(raw_rows, columns=features)
    matrix = np.empty((len(frame), len(features)), dtype=np.float64)
    for column_index, name in enumerate(features):
        raw = frame.iloc[:, column_index].astype("string").str.strip()
        missing_mask = raw.str.casefold().isin(MISSING_TOKENS).to_numpy(dtype=bool)
        numeric = pd.to_numeric(raw, errors="coerce")
        values = numeric.to_numpy(dtype=np.float64, na_value=np.nan)
        invalid_mask = np.isnan(values) & ~missing_mask
        infinite_mask = np.isinf(values)
        stats.missing_by_feature[name] += int(missing_mask.sum())
        stats.invalid_numeric_by_feature[name] += int(invalid_mask.sum())
        stats.infinite_by_feature[name] += int(infinite_mask.sum())
        values[~np.isfinite(values)] = np.nan
        matrix[:, column_index] = values
    stats.all_features_missing_rows += int(np.isnan(matrix).all(axis=1).sum())
    return matrix


def iter_csv_chunks(path: Path, features: list[str], chunk_size: int, stats: FileStats, expected_header: list[str] | None = None):
    """Stream selected raw feature values and labels in bounded chunks.

    Wrong-width records and blank-label records are counted and skipped. CSV
    syntax/encoding errors abort with a clear error instead of silently
    truncating or accepting a partial file.
    """
    columns = read_header(path)
    if expected_header is not None and columns != expected_header:
        raise DatasetFormatError(f"Normalized header/order differs in {path.name}.")
    absent = [name for name in [*features, "Label"] if name not in columns]
    if absent:
        raise DatasetFormatError(f"{path.name} is missing required columns: {absent}")
    indexes = [columns.index(name) for name in features]
    label_index = columns.index("Label")
    raw_rows: list[list[str]] = []
    labels: list[int] = []
    raw_labels: list[str] = []
    row_ids: list[tuple[str, int]] = []
    try:
        with Path(path).open("r", encoding="utf-8-sig", newline="") as stream:
            reader = csv.reader(stream, strict=True)
            next(reader)
            for source_row, row in enumerate(reader, start=1):
                stats.rows_read += 1
                if len(row) != len(columns):
                    stats.malformed_rows += 1
                    continue
                raw_label = row[label_index]
                mapped = map_label(raw_label)
                if mapped is None:
                    stats.blank_labels += 1
                    continue
                stats.label_counts[raw_label] += 1
                stats.class_counts[mapped] += 1
                raw_rows.append([row[index] for index in indexes])
                labels.append(mapped)
                raw_labels.append(raw_label)
                row_ids.append((Path(path).name, source_row))
                if len(raw_rows) >= chunk_size:
                    matrix = _numeric_frame(raw_rows, features, stats)
                    yield matrix, np.asarray(labels, dtype=np.int8), raw_labels, row_ids
                    raw_rows, labels, raw_labels, row_ids = [], [], [], []
    except (csv.Error, UnicodeDecodeError) as error:
        raise DatasetFormatError(f"Malformed CSV syntax or encoding in {path.name}: {error}") from error
    if raw_rows:
        matrix = _numeric_frame(raw_rows, features, stats)
        yield matrix, np.asarray(labels, dtype=np.int8), raw_labels, row_ids


class StratifiedReservoir:
    """Deterministic uniform per-class reservoir using seeded random priorities."""

    def __init__(self, features_count: int, cap_per_class: int, seed: int):
        if cap_per_class < 1:
            raise ValueError("cap_per_class must be positive")
        self.features_count = features_count
        self.cap = cap_per_class
        self.rng = np.random.default_rng(seed)
        self.seen = Counter()
        self.priorities = {0: np.empty(0), 1: np.empty(0)}
        self.values = {0: np.empty((0, features_count)), 1: np.empty((0, features_count))}
        self.row_ids: dict[int, list[tuple[str, int]]] = {0: [], 1: []}

    def add(self, matrix: np.ndarray, labels: np.ndarray, row_ids: list[tuple[str, int]]) -> None:
        priorities = self.rng.random(len(labels))
        for class_id in (0, 1):
            indexes = np.flatnonzero(labels == class_id)
            if not len(indexes):
                continue
            self.seen[class_id] += len(indexes)
            candidates_priority = np.concatenate((self.priorities[class_id], priorities[indexes]))
            candidates_values = np.concatenate((self.values[class_id], matrix[indexes]), axis=0)
            candidate_ids = self.row_ids[class_id] + [row_ids[index] for index in indexes]
            if len(candidates_priority) > self.cap:
                keep = np.argsort(candidates_priority, kind="stable")[-self.cap:]
                candidates_priority = candidates_priority[keep]
                candidates_values = candidates_values[keep]
                candidate_ids = [candidate_ids[index] for index in keep]
            order = np.argsort(candidates_priority, kind="stable")
            self.priorities[class_id] = candidates_priority[order]
            self.values[class_id] = candidates_values[order]
            self.row_ids[class_id] = [candidate_ids[index] for index in order]

    def result(self) -> tuple[np.ndarray, np.ndarray, list[tuple[str, int]]]:
        if not len(self.values[0]) or not len(self.values[1]):
            raise DatasetFormatError(f"Training data must contain both classes; observed {dict(self.seen)}.")
        values = np.concatenate((self.values[0], self.values[1]), axis=0)
        labels = np.concatenate((np.zeros(len(self.values[0]), dtype=np.int8), np.ones(len(self.values[1]), dtype=np.int8)))
        ids = self.row_ids[0] + self.row_ids[1]
        return values, labels, ids


def build_pipeline(name: str, seed: int = 42) -> Pipeline:
    steps = [("imputer", SimpleImputer(strategy="median", keep_empty_features=True))]
    if name == "dummy_majority":
        estimator = DummyClassifier(strategy="most_frequent")
    elif name == "logistic_regression":
        steps.append(("scaler", StandardScaler()))
        estimator = LogisticRegression(class_weight="balanced", max_iter=300, random_state=seed)
    elif name == "random_forest":
        estimator = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=seed, n_jobs=-1)
    elif name == "extra_trees":
        estimator = ExtraTreesClassifier(n_estimators=100, class_weight="balanced", random_state=seed, n_jobs=-1)
    else:
        raise ValueError(f"Unknown benchmark model: {name}")
    steps.append(("classifier", estimator))
    return Pipeline(steps)


def metric_record(name: str, y_true: np.ndarray, y_pred: np.ndarray, training_seconds: float, inference_seconds: float) -> dict:
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = (int(value) for value in matrix.ravel())
    return {
        "model": name,
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_attack": float(precision_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "recall_attack": float(recall_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "f1_attack": float(f1_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "tn": tn, "fp": fp, "fn": fn, "tp": tp,
        "training_seconds": float(training_seconds),
        "test_inference_seconds": float(inference_seconds),
        "test_inference_ms_per_row": float(inference_seconds * 1000 / len(y_true)),
        "test_rows": int(len(y_true)),
        "decision_convention": "sklearn estimator.predict; binary classes 0=BENIGN, 1=ATTACK",
    }


def _aggregate_stats(stats_by_file: dict[str, FileStats]) -> FileStats:
    aggregate = FileStats()
    for stats in stats_by_file.values():
        aggregate.rows_read += stats.rows_read
        aggregate.malformed_rows += stats.malformed_rows
        aggregate.blank_labels += stats.blank_labels
        aggregate.label_counts.update(stats.label_counts)
        aggregate.class_counts.update(stats.class_counts)
        aggregate.missing_by_feature.update(stats.missing_by_feature)
        aggregate.invalid_numeric_by_feature.update(stats.invalid_numeric_by_feature)
        aggregate.infinite_by_feature.update(stats.infinite_by_feature)
        aggregate.all_features_missing_rows += stats.all_features_missing_rows
    return aggregate


def _write_outputs(output_dir: Path, metadata: dict, metrics: list[dict], sample_ids: list[tuple[str, int]], sample_labels: np.ndarray) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    pd.DataFrame([{key: value for key, value in row.items() if key != "confusion_matrix"} | {
        "confusion_matrix": json.dumps(row["confusion_matrix"])
    } for row in metrics]).to_csv(output_dir / "metrics.csv", index=False)
    (output_dir / "run_metadata.json").write_text(json.dumps(metadata, indent=2, ensure_ascii=True), encoding="utf-8")
    with (output_dir / "training_sample_manifest.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["class", "source_file", "source_row_number"])
        for class_id, pair in zip(sample_labels, sample_ids):
            writer.writerow([class_id, pair[0], pair[1]])
    lines = [
        "# CIC-IDS2017 independent benchmark (research-only)", "",
        "This experiment trains new models on CIC-IDS2017. It is not an evaluation of the frozen Random Forest V2 model.", "",
        f"- Training files: {', '.join(Path(p).name for p in metadata['split']['training_files'])}",
        f"- Held-out test files: {', '.join(Path(p).name for p in metadata['split']['test_files'])}",
        f"- Training sample: {metadata['training']['sampled_rows']} rows ({metadata['training']['sampled_class_counts']['BENIGN_0']} benign, {metadata['training']['sampled_class_counts']['ATTACK_1']} attack); cap {metadata['configuration']['training_cap_per_class']:,} per class.",
        f"- Full held-out Friday rows evaluated: {metadata['test']['evaluated_rows']:,} (benign {metadata['test']['class_counts']['BENIGN_0']:,}, attack {metadata['test']['class_counts']['ATTACK_1']:,}).",
        f"- Features: {len(metadata['features'])} CIC-IDS2017 columns shared with the V2 schema, selected in V2 schema order; no missing V2 fields were synthesized.",
        "- Binary labels: BENIGN=0; every nonblank attack label=1. The displayed raw class labels remain available in run metadata.",
        "- Preprocessing: invalid numeric text and infinities become missing; median imputation is fitted within each model pipeline on training rows only. Logistic Regression also scales using training rows only.",
        "- Test data is streamed in chunks and never sampled or used in preprocessing/model selection.",
        "- Metrics use `estimator.predict`; precision, recall, and F1 treat attack (1) as positive.",
        "- Limitations: one held-out collection day; capture/session independence is not asserted; release-copy checksums authenticate these local files only, not their download source.", "",
        "## Results", "",
        "| Model | Accuracy | Attack precision | Attack recall | Attack F1 | TN | FP | FN | TP | Fit s | Test inference s |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in metrics:
        lines.append(
            f"| {row['model']} | {row['accuracy']:.6f} | {row['precision_attack']:.6f} | {row['recall_attack']:.6f} | {row['f1_attack']:.6f} | {row['tn']} | {row['fp']} | {row['fn']} | {row['tp']} | {row['training_seconds']:.3f} | {row['test_inference_seconds']:.3f} |"
        )
    (output_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_benchmark(dataset_dir: Path = DEFAULT_DATASET, output_dir: Path = DEFAULT_OUTPUT, seed: int = 42, cap_per_class: int = 10_000, chunk_size: int = 25_000) -> dict:
    dataset_dir = Path(dataset_dir)
    files = sorted(dataset_dir.glob("*.csv"), key=lambda p: p.name.casefold())
    if not dataset_dir.is_dir():
        raise FileNotFoundError(f"CIC-IDS2017 dataset directory not found: {dataset_dir}")
    train_files, test_files = split_dataset_files(files)
    if {p.resolve() for p in train_files} & {p.resolve() for p in test_files}:
        raise DatasetFormatError("Training and test source paths overlap.")

    schema_hash = sha256_file(SCHEMA_PATH)
    if schema_hash != EXPECTED_SCHEMA_SHA256:
        raise RuntimeError("Protected V2 feature schema SHA-256 does not match the expected value.")
    model_hash_before = sha256_file(V2_MODEL_PATH)
    if model_hash_before != EXPECTED_MODEL_SHA256:
        raise RuntimeError("Protected V2 model SHA-256 does not match the expected value.")
    schema = joblib.load(SCHEMA_PATH)
    if not isinstance(schema, list) or len(schema) != 82 or len(set(schema)) != 82:
        raise DatasetFormatError("Protected V2 feature schema must contain 82 unique ordered names.")

    headers = {path: read_header(path) for path in files}
    canonical_header = headers[files[0]]
    mismatched = [path.name for path in files if headers[path] != canonical_header]
    if mismatched:
        raise DatasetFormatError(f"Normalized CIC-IDS2017 headers/order differ in: {mismatched}")
    features, missing_v2_features = shared_feature_names(canonical_header, schema)
    if missing_v2_features != ["Source Port", "Protocol", "SimillarHTTP", "Inbound"]:
        raise DatasetFormatError(f"Unexpected missing-feature set for this experiment: {missing_v2_features}")
    if "Label" in features:
        raise DatasetFormatError("Label must never be included as a model feature.")

    fingerprints = {}
    for path in files:
        stat_before = path.stat()
        fingerprints[path.name] = {
            "path": str(path.resolve()), "size_bytes": stat_before.st_size,
            "sha256": sha256_file(path), "mtime_ns": stat_before.st_mtime_ns,
        }
    rng_reservoir = StratifiedReservoir(len(features), cap_per_class, seed)
    train_file_stats: dict[str, FileStats] = {}
    for path in train_files:
        stats = FileStats()
        train_file_stats[path.name] = stats
        for matrix, labels, _, row_ids in iter_csv_chunks(path, features, chunk_size, stats, canonical_header):
            rng_reservoir.add(matrix, labels, row_ids)
    X_train, y_train, sampled_ids = rng_reservoir.result()
    sampled_counts = Counter(int(value) for value in y_train)
    train_stats = _aggregate_stats(train_file_stats)
    if set(train_stats.class_counts) != {0, 1} or set(sampled_counts) != {0, 1}:
        raise DatasetFormatError("Both binary classes must be present in all eligible training rows and the training sample.")

    model_names = ["dummy_majority", "logistic_regression", "random_forest", "extra_trees"]
    metrics = []
    test_reference = None
    test_stats_result = None
    for model_name in model_names:
        pipeline = build_pipeline(model_name, seed)
        started = time.perf_counter()
        pipeline.fit(X_train, y_train)
        training_seconds = time.perf_counter() - started
        y_true_parts = []
        y_pred_parts = []
        current_test_stats = {path.name: FileStats() for path in test_files}
        inference_seconds = 0.0
        for path in test_files:
            stats = current_test_stats[path.name]
            for matrix, labels, _, _ in iter_csv_chunks(path, features, chunk_size, stats, canonical_header):
                started = time.perf_counter()
                predictions = pipeline.predict(matrix)
                inference_seconds += time.perf_counter() - started
                y_true_parts.append(labels)
                y_pred_parts.append(np.asarray(predictions, dtype=np.int8))
        y_true = np.concatenate(y_true_parts) if y_true_parts else np.empty(0, dtype=np.int8)
        y_pred = np.concatenate(y_pred_parts) if y_pred_parts else np.empty(0, dtype=np.int8)
        if not len(y_true) or set(np.unique(y_true)) != {0, 1}:
            raise DatasetFormatError("The complete Friday test set must contain both classes and valid labeled rows.")
        result = metric_record(model_name, y_true, y_pred, training_seconds, inference_seconds)
        metrics.append(result)
        summary = {name: stats.to_dict() for name, stats in current_test_stats.items()}
        if test_reference is None:
            test_reference = (len(y_true), Counter(int(value) for value in y_true), summary)
            test_stats_result = current_test_stats
        elif len(y_true) != test_reference[0] or Counter(int(value) for value in y_true) != test_reference[1]:
            raise DatasetFormatError("Test rows or labels changed between model evaluations.")
        del pipeline

    if test_reference is None:
        raise DatasetFormatError("No Friday test data was evaluated.")
    model_hash_after = sha256_file(V2_MODEL_PATH)
    schema_hash_after = sha256_file(SCHEMA_PATH)
    if model_hash_after != model_hash_before or schema_hash_after != schema_hash:
        raise RuntimeError("Protected V2 artifacts changed during the benchmark; aborting output write.")

    test_aggregate = _aggregate_stats(test_stats_result)
    training_ids = [{"class": int(class_id), "source_file": file_name, "source_row_number": int(row_number)}
                    for class_id, (file_name, row_number) in zip(y_train, sampled_ids)]
    metadata = {
        "experiment": "CIC-IDS2017 independent day-held-out binary classification; research-only; not Random Forest V2 evaluation",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "command": "python research\\code\\benchmark_cic_ids2017.py",
        "dataset": {"name": "CIC-IDS2017 MachineLearningCVE", "directory": str(dataset_dir.resolve()), "files": fingerprints},
        "split": {"strategy": "Monday through Thursday training; all three Friday files held out", "training_files": [str(p.resolve()) for p in train_files], "test_files": [str(p.resolve()) for p in test_files], "source_paths_disjoint": True},
        "features": features,
        "missing_v2_features_not_synthesized": missing_v2_features,
        "label_mapping": {"BENIGN (case/whitespace normalized)": 0, "every nonblank other label": 1},
        "training": {"all_eligible_rows": train_stats.to_dict(), "sampled_rows": int(len(y_train)), "sampled_class_counts": {"BENIGN_0": int(sampled_counts[0]), "ATTACK_1": int(sampled_counts[1])}, "sampled_source_row_ids": training_ids},
        "test": {"per_file": {name: stats.to_dict() for name, stats in test_stats_result.items()}, "rows_read": test_aggregate.rows_read, "evaluated_rows": test_reference[0], "malformed_rows_skipped": test_aggregate.malformed_rows, "blank_labels_skipped": test_aggregate.blank_labels, "raw_label_counts": dict(sorted(test_aggregate.label_counts.items())), "class_counts": {"BENIGN_0": int(test_reference[1].get(0, 0)), "ATTACK_1": int(test_reference[1].get(1, 0))}, "numeric_quality": test_aggregate.to_dict()},
        "configuration": {"seed": seed, "training_cap_per_class": cap_per_class, "chunk_size_rows": chunk_size, "models": {"dummy_majority": {"strategy": "most_frequent"}, "logistic_regression": {"class_weight": "balanced", "max_iter": 300, "random_state": seed, "scaling": "StandardScaler fitted on training sample"}, "random_forest": {"n_estimators": 100, "class_weight": "balanced", "random_state": seed, "n_jobs": -1}, "extra_trees": {"n_estimators": 100, "class_weight": "balanced", "random_state": seed, "n_jobs": -1}}, "imputation": "median SimpleImputer fitted per model on training sample; keep_empty_features=True", "metric_positive_class": 1, "test_sampling": "none; all valid labeled Friday rows streamed"},
        "metrics": metrics,
        "software_versions": {"python": __import__("platform").python_version(), "numpy": np.__version__, "pandas": pd.__version__, "scikit_learn": sklearn.__version__, "joblib": joblib.__version__},
        "protected_artifacts": {"model_sha256_before": model_hash_before, "model_sha256_after": model_hash_after, "schema_sha256_before": schema_hash, "schema_sha256_after": schema_hash_after, "model_used_for_prediction": False, "schema_used_only_to_select_shared_feature_names": True},
        "limitations": ["One collection day is held out; capture/session independence within that day is not asserted.", "The experiment trains new CIC-IDS2017 models and does not evaluate or validate frozen Random Forest V2.", "The local copies have per-file checksums, but no download receipt/source archive checksum was supplied.", "The local Web Attack labels contain U+FFFD in the label text; binary mapping preserves the raw spelling in counts."],
    }
    _write_outputs(Path(output_dir), metadata, metrics, sampled_ids, y_train)
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-dir", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--cap-per-class", type=int, default=10_000)
    parser.add_argument("--chunk-size", type=int, default=25_000)
    args = parser.parse_args()
    try:
        metadata = run_benchmark(args.dataset_dir, args.output_dir, args.seed, args.cap_per_class, args.chunk_size)
    except (DatasetFormatError, FileNotFoundError, OSError, RuntimeError, ValueError) as error:
        parser.error(str(error))
    print(f"Completed CIC-IDS2017 research-only benchmark. Results: {args.output_dir.resolve()}")
    for row in metadata["metrics"]:
        print(f"{row['model']}: accuracy={row['accuracy']:.6f}, precision={row['precision_attack']:.6f}, recall={row['recall_attack']:.6f}, f1={row['f1_attack']:.6f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
