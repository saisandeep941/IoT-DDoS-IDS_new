"""Leakage-conscious benchmark of shared-training baselines on held-out UDPLag.

Reads original source CSVs and the saved V2 model. It never writes model
artifacts. Training is sampled after time-gap and tuple-overlap purging; the
complete natural-prevalence UDPLag file is used for evaluation.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import shap
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from research_eval_protocol import (
    META_COLUMNS,
    RunManifest,
    benchmark_api_latency,
    benchmark_model,
    canonical_tuple_keys,
    file_fingerprint,
    git_metadata,
    hardware_metadata,
    load_or_create_checkpoint,
    load_or_create_holdout_memmap,
    load_or_create_probability_memmap,
    package_versions,
    sample_purged_training,
    sha256_file,
    stratified_bootstrap_ci,
    tuple_cluster_bootstrap_ci,
)


ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = ROOT / "backend" / "real_model_v2.joblib"
FEATURE_PATH = ROOT / "backend" / "real_model_features_v2.joblib"
SOURCE_DIR = ROOT / "dataset" / "01-12"
TEST_PATH = SOURCE_DIR / "UDPLag.csv"
TRAIN_PATHS = sorted(
    (path for path in SOURCE_DIR.glob("*.csv") if path.name.lower() != "udplag.csv"),
    key=lambda path: path.name.lower(),
)
OUTPUT_ROOT = ROOT / "ml" / "research_results"
SEED = 42
CHUNK_SIZE = 50_000
ACTIVE_MANIFEST = None


def read_header(path: Path) -> list[str]:
    return list(pd.read_csv(path, nrows=0, low_memory=False).columns)


def class_reservoir(
    path: Path, features: list[str], cap: int, seed: int
) -> tuple[pd.DataFrame, np.ndarray, dict[int, int], int]:
    """Collect a uniform per-class sample with vectorized priority reservoirs."""
    raw_header = read_header(path)
    normalized_to_raw = {name.strip(): name for name in raw_header}
    needed = ["Label", *features]
    missing = [name for name in needed if name not in normalized_to_raw]
    if missing:
        raise ValueError(f"{path.name} is missing required columns: {missing}")
    usecols = [normalized_to_raw[name] for name in needed]
    rng = np.random.default_rng(seed)
    samples = {0: np.empty((0, len(features)), dtype=np.float64), 1: np.empty((0, len(features)), dtype=np.float64)}
    priorities = {0: np.empty(0), 1: np.empty(0)}
    counts = {0: 0, 1: 0}
    rows_read = 0

    for chunk in pd.read_csv(
        path, usecols=usecols, chunksize=CHUNK_SIZE, low_memory=False
    ):
        chunk.columns = chunk.columns.str.strip()
        labels = chunk["Label"].astype("string").str.strip().str.upper()
        valid = labels.notna() & labels.ne("")
        y = labels.ne("BENIGN").astype(np.int8)
        X = chunk.reindex(columns=features).apply(pd.to_numeric, errors="coerce")
        X = X.replace([np.inf, -np.inf], np.nan).to_numpy(dtype=np.float64)
        rows_read += int(valid.sum())

        for cls in (0, 1):
            class_rows = X[(y.to_numpy() == cls) & valid.to_numpy()]
            if not len(class_rows):
                continue
            counts[cls] += len(class_rows)
            new_priorities = rng.random(len(class_rows))
            candidates_x = np.concatenate((samples[cls], class_rows), axis=0)
            candidates_p = np.concatenate((priorities[cls], new_priorities))
            keep = min(cap, len(candidates_p))
            chosen = np.argpartition(candidates_p, -keep)[-keep:]
            samples[cls] = candidates_x[chosen]
            priorities[cls] = candidates_p[chosen]

    if not len(samples[0]) or not len(samples[1]):
        raise ValueError(f"{path.name} must contain both BENIGN and attack rows")
    # Enforce equal class counts even when the minority class has fewer rows
    # than the configured cap. This keeps the evaluation balanced by design.
    balanced_count = min(len(samples[0]), len(samples[1]))
    for cls in (0, 1):
        if len(samples[cls]) > balanced_count:
            chosen = rng.choice(len(samples[cls]), size=balanced_count, replace=False)
            samples[cls] = samples[cls][chosen]
    X_sample = pd.DataFrame(
        np.concatenate((samples[0], samples[1])), columns=features
    )
    y_sample = np.concatenate((np.zeros(len(samples[0]), dtype=np.int8), np.ones(len(samples[1]), dtype=np.int8)))
    order = np.random.default_rng(seed + 1).permutation(len(y_sample))
    return X_sample.iloc[order].reset_index(drop=True), y_sample[order], counts, rows_read


def metric_record(name: str, y_true: np.ndarray, y_pred: np.ndarray, y_prob: np.ndarray) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "model": name,
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "roc_auc": roc_auc_score(y_true, y_prob),
        "average_precision": average_precision_score(y_true, y_prob),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


def write_result_tables(baseline_records: list[dict], reference_record: dict, output_dir: Path) -> None:
    """Persist ranked matched baselines and the deployed V2 reference separately."""
    columns = [
        "model", "accuracy", "precision", "recall", "f1", "roc_auc",
        "average_precision", "tn", "fp", "fn", "tp", "training_seconds",
    ]
    pd.DataFrame(baseline_records, columns=columns).to_csv(
        output_dir / "baseline_results.csv", index=False
    )
    pd.DataFrame([reference_record], columns=columns).to_csv(
        output_dir / "deployed_v2_reference.csv", index=False
    )


def svg_start(width: int, height: int, title: str) -> list[str]:
    return [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        '<style>text{font-family:Arial,Helvetica,sans-serif;fill:#182230}.muted{fill:#667085;font-size:13px}.title{font-size:22px;font-weight:700}.label{font-size:14px}</style>',
        f'<text x="{width/2:.0f}" y="34" text-anchor="middle" class="title">{html.escape(title)}</text>',
    ]


def save_confusion_svg(record: dict, path: Path) -> None:
    cells = [[record["tn"], record["fp"]], [record["fn"], record["tp"]]]
    width, height, x0, y0, cell = 520, 380, 170, 105, 130
    svg = svg_start(width, height, f"Confusion matrix — {record['model']}")
    svg += ['<text x="300" y="78" text-anchor="middle" class="muted">Predicted label</text>',
            '<text x="92" y="237" text-anchor="middle" class="muted" transform="rotate(-90 92 237)">Actual label</text>']
    for col, label in enumerate(("BENIGN", "ATTACK")):
        svg.append(f'<text x="{x0+col*cell+cell/2}" y="98" text-anchor="middle" class="label">{label}</text>')
    for row, label in enumerate(("BENIGN", "ATTACK")):
        svg.append(f'<text x="{x0-12}" y="{y0+row*cell+cell/2+5}" text-anchor="end" class="label">{label}</text>')
        for col in range(2):
            value = cells[row][col]
            shade = 245 - int(90 * value / max(1, max(map(max, cells))))
            svg.append(f'<rect x="{x0+col*cell}" y="{y0+row*cell}" width="{cell}" height="{cell}" fill="rgb({shade},{min(255,shade+5)},{min(255,shade+8)})" stroke="#d0d5dd"/>')
            svg.append(f'<text x="{x0+col*cell+cell/2}" y="{y0+row*cell+cell/2+8}" text-anchor="middle" font-size="25" font-weight="700">{value:,}</text>')
    sample_note = record.get("sample_note", "Natural-prevalence held-out data")
    svg += [f'<text x="{width/2}" y="{height-20}" text-anchor="middle" class="muted">{html.escape(sample_note)} · n={sum(map(sum,cells)):,}</text>', '</svg>']
    path.write_text("\n".join(svg), encoding="utf-8")


def save_comparison_svg(records: list[dict], path: Path) -> None:
    metrics = [("F1", "f1"), ("Recall", "recall"), ("Precision", "precision"), ("ROC AUC", "roc_auc")]
    colors = ["#2855a6", "#168a76", "#bb6b1c", "#7b61a8", "#7d8795"]
    width, height = 1120, max(360, 125 + len(records) * 68)
    svg = svg_start(width, height, "Held-out model comparison")
    left, top, plotw, rowh = 235, 93, 570, 62
    for tick in range(0, 11):
        x = left + plotw * tick / 10
        svg.append(f'<line x1="{x}" y1="{top-9}" x2="{x}" y2="{top+len(records)*rowh-8}" stroke="#eaecf0"/>')
        svg.append(f'<text x="{x}" y="{top+len(records)*rowh+16}" text-anchor="middle" class="muted">{tick/10:.1f}</text>')
    for index, record in enumerate(records):
        y = top + index * rowh
        svg.append(f'<text x="{left-12}" y="{y+19}" text-anchor="end" class="label">{html.escape(record["model"])}</text>')
        for j, (label, key) in enumerate(metrics):
            by = y + j * 11
            val = max(0.0, min(1.0, float(record[key])))
            svg.append(f'<rect x="{left}" y="{by}" width="{plotw*val:.2f}" height="8" rx="3" fill="{colors[j]}"/>')
    legend_y = height - 24
    for i, (label, _) in enumerate(metrics):
        x = left + i * 150
        svg.extend([f'<rect x="{x}" y="{legend_y-12}" width="12" height="12" fill="{colors[i]}"/>',
                    f'<text x="{x+18}" y="{legend_y-1}" class="muted">{label}</text>'])
    svg.append('</svg>')
    path.write_text("\n".join(svg), encoding="utf-8")


def save_shap_svgs(
    features: list[str], shap_values: np.ndarray, feature_values: np.ndarray,
    output_dir: Path,
) -> None:
    mean_abs = np.abs(shap_values).mean(axis=0)
    order = np.argsort(mean_abs)[-15:][::-1]
    width, rowh, height = 950, 31, 100 + 15 * 31
    svg = svg_start(width, height, "Random Forest V2 — global SHAP importance")
    max_value = max(float(mean_abs[order].max()), 1e-12)
    for i, fi in enumerate(order):
        y = 75 + i * rowh
        label = html.escape(features[fi])
        value = float(mean_abs[fi])
        svg.append(f'<text x="300" y="{y+14}" text-anchor="end" class="label">{label}</text>')
        svg.append(f'<rect x="320" y="{y}" width="{500*value/max_value:.2f}" height="18" rx="4" fill="#2855a6"/>')
        svg.append(f'<text x="832" y="{y+14}" class="muted">{value:.5g}</text>')
    svg.append('</svg>')
    (output_dir / "shap_global_importance.svg").write_text("\n".join(svg), encoding="utf-8")

    # Compact SHAP beeswarm-style point plot for the same top features.
    width, height, x0, plotw = 1050, 100 + 15 * 34, 420, 500
    svg = svg_start(width, height, "Random Forest V2 — SHAP impact on held-out flows")
    svg.append(f'<line x1="{x0+plotw/2}" y1="65" x2="{x0+plotw/2}" y2="{height-25}" stroke="#98a2b3"/>')
    all_abs = float(np.percentile(np.abs(shap_values[:, order]), 98)) or 1.0
    n = min(len(shap_values), 300)
    for rank, fi in enumerate(order):
        y = 82 + rank * 34
        svg.append(f'<text x="405" y="{y+5}" text-anchor="end" class="label">{html.escape(features[fi])}</text>')
        values = shap_values[:n, fi]
        raw_values = np.asarray(feature_values[:n, fi])
        low, high = np.nanpercentile(raw_values, [5, 95])
        span = float(high - low) or 1.0
        for j, impact in enumerate(values):
            x = x0 + plotw / 2 + float(np.clip(impact / all_abs, -1, 1)) * (plotw / 2)
            jitter = ((j * 37 + rank * 13) % 17) - 8
            color_value = float(np.clip((raw_values[j] - low) / span, 0, 1))
            red = int(49 + 180 * color_value)
            blue = int(190 - 120 * color_value)
            svg.append(f'<circle cx="{x:.1f}" cy="{y+jitter:.1f}" r="2.3" fill="rgb({red},90,{blue})" opacity="0.7"/>')
    svg += [f'<text x="{x0+plotw/2}" y="{height-20}" text-anchor="middle" class="muted">Lower impact ← SHAP value → Higher impact</text>',
            f'<text x="{x0}" y="{height-4}" class="muted">Low feature value</text>',
            f'<text x="{x0+plotw}" y="{height-4}" text-anchor="end" class="muted">High feature value</text>', '</svg>']
    (output_dir / "shap_beeswarm.svg").write_text("\n".join(svg), encoding="utf-8")


def positive_probability(model, X: pd.DataFrame) -> np.ndarray:
    classes = list(model.classes_)
    return model.predict_proba(X)[:, classes.index(1)]


def positive_probability_chunked(
    model, X: pd.DataFrame, checkpoint_path: Path, context: dict, chunk_rows: int = 8_192,
) -> np.memmap:
    return load_or_create_probability_memmap(model, X, checkpoint_path, context, chunk_rows)


def evaluate_baseline_stage(name, model_factory, X_train, y_train, X_test, y_test,
                            tuple_keys, args, probability_checkpoint, probability_context):
    """Fit and finish one baseline so its compact results can be checkpointed."""
    model = model_factory()
    started = time.perf_counter()
    model.fit(X_train, y_train)
    fit_seconds = time.perf_counter() - started
    probabilities = positive_probability_chunked(
        model, X_test, probability_checkpoint, probability_context
    )
    record = metric_record(name, y_test, (probabilities >= 0.5).astype(np.int8), probabilities)
    record["training_seconds"] = fit_seconds
    record["sample_note"] = "Natural-prevalence held-out data"
    confidence = _confidence_rows(
        name, y_test, probabilities, tuple_keys, args.bootstrap_replicates,
        args.cluster_bootstrap_replicates, args.bootstrap_seed,
    )
    efficiency = benchmark_model(
        model, X_test, warmups=args.latency_warmups,
        latency_repeats=args.latency_repeats, batch_repeats=args.batch_repeats,
    )
    return {
        "record": record, "confidence_records": confidence,
        "efficiency_record": {"model": name, "training_seconds": fit_seconds, **efficiency},
    }


def evaluate_reference_stage(v2, X_test, y_test, tuple_keys, args,
                             probability_checkpoint, probability_context):
    probabilities = positive_probability_chunked(
        v2, X_test, probability_checkpoint, probability_context
    )
    record = metric_record(
        "Deployed Random Forest V2 (reference only)", y_test,
        (probabilities >= 0.5).astype(np.int8), probabilities,
    )
    record["training_seconds"] = "existing artifact"
    record["sample_note"] = "Natural-prevalence data · reference only"
    confidence = _confidence_rows(
        record["model"], y_test, probabilities, tuple_keys,
        args.bootstrap_replicates, args.cluster_bootstrap_replicates, args.bootstrap_seed,
    )
    efficiency = benchmark_model(
        v2, X_test, warmups=args.latency_warmups,
        latency_repeats=args.latency_repeats, batch_repeats=args.batch_repeats,
    )
    return {"record": record, "confidence_records": confidence,
            "efficiency_record": {"model": record["model"], "training_seconds": "existing artifact", **efficiency}}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-per-class", type=int, default=10_000,
                        help="Maximum past-only training rows retained per class (default: 10000)")
    parser.add_argument("--output-dir", type=Path, default=None,
                        help="Output folder; default creates a new timestamped folder under ml/research_results")
    parser.add_argument("--resume", action="store_true",
                        help="Resume only from a compatible run manifest in --output-dir")
    parser.add_argument("--bootstrap-replicates", type=int, default=500)
    parser.add_argument("--cluster-bootstrap-replicates", type=int, default=250)
    parser.add_argument("--bootstrap-seed", type=int, default=2026)
    parser.add_argument("--api-url", type=str, default=None,
                        help="Optional running deployed API endpoint, e.g. http://127.0.0.1:8000/api/predict")
    parser.add_argument("--latency-warmups", type=int, default=20)
    parser.add_argument("--latency-repeats", type=int, default=500)
    parser.add_argument("--batch-repeats", type=int, default=3)
    args = parser.parse_args()
    if args.output_dir is None:
        args.output_dir = OUTPUT_ROOT / f"evaluation_{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
    if args.max_per_class < 100:
        parser.error("--max-per-class must be at least 100")
    if args.bootstrap_replicates < 100 or args.cluster_bootstrap_replicates < 100:
        parser.error("Bootstrap replicate counts must be at least 100")
    if not TRAIN_PATHS or not TEST_PATH.exists():
        raise FileNotFoundError("Expected original training CSVs and dataset/01-12/UDPLag.csv")
    if not MODEL_PATH.exists() or not FEATURE_PATH.exists():
        raise FileNotFoundError("Saved V2 model and 82-feature list must exist")

    features = joblib.load(FEATURE_PATH)
    v2 = joblib.load(MODEL_PATH)
    if len(features) != 82 or len(set(features)) != 82 or v2.n_features_in_ != 82:
        raise ValueError("Saved V2 model and 82-feature schema do not match")
    model_hash = sha256_file(MODEL_PATH)
    feature_hash = sha256_file(FEATURE_PATH)
    code_paths = [Path(__file__), Path(__file__).with_name("research_eval_protocol.py")]
    code_hashes = {path.name: sha256_file(path) for path in code_paths}
    git_start = git_metadata(ROOT)
    input_fingerprints = {
        path.name: file_fingerprint(path) for path in [*TRAIN_PATHS, TEST_PATH]
    }
    run_context = {
        "configuration": {
            "seed": SEED, "bootstrap_seed": args.bootstrap_seed,
            "bootstrap_replicates": args.bootstrap_replicates,
            "cluster_bootstrap_replicates": args.cluster_bootstrap_replicates,
            "chunk_size": CHUNK_SIZE, "max_per_class": args.max_per_class,
            "gap_seconds": 60, "latency_warmups": args.latency_warmups,
            "latency_repeats": args.latency_repeats, "batch_repeats": args.batch_repeats,
            "api_url": args.api_url,
        },
        "feature_schema": list(features), "feature_count": len(features),
        "git_revision": git_start["revision"], "git_branch": git_start["branch"],
        "model_sha256": model_hash, "feature_file_sha256": feature_hash,
        "code_sha256": code_hashes, "input_fingerprints": input_fingerprints,
    }
    manifest = RunManifest.start(args.output_dir, run_context, resume=args.resume)
    global ACTIVE_MANIFEST
    ACTIVE_MANIFEST = manifest
    checkpoint_dir = args.output_dir / "checkpoints"
    partial_dir = args.output_dir / "partial"
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    partial_dir.mkdir(parents=True, exist_ok=True)
    final_dir = args.output_dir / "results"

    holdout_checkpoint = checkpoint_dir / "holdout_memmap"
    holdout_data_context = {"run_context": run_context, "stage": "holdout", "format": "holdout_memmap_v1"}
    test_data, holdout_reused = load_or_create_holdout_memmap(
        TEST_PATH, features, CHUNK_SIZE, holdout_checkpoint, holdout_data_context,
    )
    manifest.mark_stage_complete("holdout", str(holdout_checkpoint.relative_to(args.output_dir)) + "/")
    print(f"Holdout stage: {'reused checkpoint' if holdout_reused else 'read and checkpointed'}", flush=True)
    test_groups = set(test_data["tuple_keys"])
    test_start_ns = test_data["timestamp_start_ns"]
    test_end_ns = test_data["timestamp_end_ns"]
    print(f"Holdout: {test_data['rows_read']:,} rows; labels={test_data['counts']}; tuple groups={len(test_groups):,}", flush=True)

    training_checkpoint = checkpoint_dir / "training_sample.pkl"
    sampling_checkpoint = checkpoint_dir / "training_sampling_state.pkl"
    sampling_context = {"run_context": run_context, "stage": "training_sampling"}
    train_data, training_reused = load_or_create_checkpoint(
        training_checkpoint, {"run_context": run_context, "stage": "training_sample"},
        lambda: sample_purged_training(
            TRAIN_PATHS, features, test_groups, test_start_ns,
            cap=args.max_per_class, seed=SEED, chunk_size=CHUNK_SIZE, gap_seconds=60,
            checkpoint_path=sampling_checkpoint, checkpoint_context=sampling_context,
        ),
    )
    manifest.mark_stage_complete("training_sampling", str(training_checkpoint.relative_to(args.output_dir)))
    print(f"Training sample stage: {'reused checkpoint' if training_reused else 'completed and checkpointed'}", flush=True)
    X_train, y_train = train_data["X"], train_data["y"]
    X_test, y_test = test_data["X"], test_data["y"]
    print(
        f"Retained training sample: {len(y_train):,}; eligible class counts={train_data['source_class_counts']}; "
        f"retained labels={train_data['sampled_class_counts']}; filtered rows={train_data['metadata']}", flush=True
    )

    model_factories = [
        ("Random Forest (matched research refit)", lambda: Pipeline([
            ("imputer", SimpleImputer(strategy="median", keep_empty_features=True)),
            ("model", RandomForestClassifier(n_estimators=100, random_state=SEED, n_jobs=1, class_weight="balanced")),
        ])),
        ("Extra Trees", lambda: Pipeline([
            ("imputer", SimpleImputer(strategy="median", keep_empty_features=True)),
            ("model", ExtraTreesClassifier(n_estimators=200, random_state=SEED, n_jobs=1, class_weight="balanced")),
        ])),
        ("Histogram Gradient Boosting", lambda: Pipeline([
            ("imputer", SimpleImputer(strategy="median", keep_empty_features=True)),
            ("model", HistGradientBoostingClassifier(max_iter=150, learning_rate=0.1, random_state=SEED, class_weight="balanced")),
        ])),
        ("Logistic Regression", lambda: Pipeline([
            ("imputer", SimpleImputer(strategy="median", keep_empty_features=True)),
            ("scale", StandardScaler()),
            ("model", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=SEED)),
        ])),
    ]
    baseline_records, confidence_records, efficiency_records = [], [], []
    for name, model_factory in model_factories:
        slug = "".join(ch.lower() if ch.isalnum() else "_" for ch in name).strip("_")
        stage_name = f"baseline_{slug}"
        stage_path = checkpoint_dir / f"{stage_name}.pkl"
        result, reused = load_or_create_checkpoint(
            stage_path, {"run_context": run_context, "stage": stage_name},
            lambda name=name, factory=model_factory, stage_name=stage_name: evaluate_baseline_stage(
                name, factory, X_train, y_train, X_test, y_test,
                test_data["tuple_keys"], args,
                checkpoint_dir / f"{stage_name}_probabilities",
                {"run_context": run_context, "stage": stage_name, "artifact": "probabilities"},
            ),
        )
        manifest.mark_stage_complete(stage_name, str(stage_path.relative_to(args.output_dir)))
        baseline_records.append(result["record"])
        confidence_records.extend(result["confidence_records"])
        efficiency_records.append(result["efficiency_record"])
        state = "reused completed stage" if reused else "fit/evaluated and checkpointed"
        print(f"{state}: {name}; F1={result['record']['f1']:.4f}", flush=True)

    # V2 is a deployed reference only: it includes training flows after the test
    # block and neighboring/reused tuple groups, so it is not a split-independent score.
    reference_path = checkpoint_dir / "deployed_v2_reference.pkl"
    reference_result, reference_reused = load_or_create_checkpoint(
        reference_path, {"run_context": run_context, "stage": "deployed_v2_reference"},
        lambda: evaluate_reference_stage(
            v2, X_test, y_test, test_data["tuple_keys"], args,
            checkpoint_dir / "deployed_v2_reference_probabilities",
            {"run_context": run_context, "stage": "deployed_v2_reference", "artifact": "probabilities"},
        ),
    )
    manifest.mark_stage_complete("deployed_v2_reference", str(reference_path.relative_to(args.output_dir)))
    v2_record = reference_result["record"]
    confidence_records.extend(reference_result["confidence_records"])
    efficiency_records.append(reference_result["efficiency_record"])
    print(f"V2 reference stage: {'reused completed stage' if reference_reused else 'evaluated and checkpointed'}", flush=True)

    api_path = checkpoint_dir / "api_efficiency.pkl"
    api_efficiency, api_reused = load_or_create_checkpoint(
        api_path, {"run_context": run_context, "stage": "api_efficiency"},
        lambda: benchmark_api_latency(
            args.api_url,
            np.nan_to_num(X_test.iloc[0].to_numpy(dtype=np.float64), nan=0.0, posinf=0.0, neginf=0.0).tolist(),
        ) if args.api_url else {
            "status": "NOT RUN: provide --api-url for a separately running backend",
            "scope": "API latency is not inferred from model-only timing or batch throughput",
        },
    )
    manifest.mark_stage_complete("api_efficiency", str(api_path.relative_to(args.output_dir)))

    matched = baseline_records
    all_records = [*baseline_records, v2_record]
    save_comparison_svg(matched, partial_dir / "baseline_comparison.svg")
    for record in all_records:
        safe = "".join(ch.lower() if ch.isalnum() else "_" for ch in record["model"]).strip("_")
        save_confusion_svg(record, partial_dir / f"confusion_{safe}.svg")

    shap_path = checkpoint_dir / "shap_values.pkl"
    def calculate_shap():
        explain_n = min(250, len(X_test))
        X_explain = X_test.iloc[:explain_n]
        imputed_values = v2.named_steps["imputer"].transform(X_explain)
        explainer = shap.TreeExplainer(v2.named_steps["model"])
        shap_output = explainer.shap_values(imputed_values)
        if isinstance(shap_output, list):
            values = np.asarray(shap_output[list(v2.named_steps["model"].classes_).index(1)])
        elif hasattr(shap_output, "values"):
            values = np.asarray(shap_output.values)
            if values.ndim == 3:
                values = values[:, :, list(v2.named_steps["model"].classes_).index(1)]
        else:
            values = np.asarray(shap_output)
            if values.ndim == 3:
                values = values[:, :, list(v2.named_steps["model"].classes_).index(1)]
        return {"values": values, "features": np.asarray(imputed_values)}
    shap_data, shap_reused = load_or_create_checkpoint(
        shap_path, {"run_context": run_context, "stage": "shap"}, calculate_shap,
    )
    manifest.mark_stage_complete("shap", str(shap_path.relative_to(args.output_dir)))
    attack_shap, imputed = shap_data["values"], shap_data["features"]
    save_shap_svgs(features, attack_shap, imputed, partial_dir)
    pd.DataFrame({"feature": features, "mean_abs_shap": np.abs(attack_shap).mean(axis=0)}).sort_values(
        "mean_abs_shap", ascending=False
    ).to_csv(partial_dir / "shap_importance.csv", index=False)

    write_result_tables(baseline_records, v2_record, partial_dir)
    pd.DataFrame(confidence_records).to_csv(partial_dir / "confidence_intervals.csv", index=False)
    pd.DataFrame(efficiency_records).to_csv(partial_dir / "efficiency.csv", index=False)
    (partial_dir / "api_efficiency.json").write_text(json.dumps(api_efficiency, indent=2), encoding="utf-8")

    benign = int((y_test == 0).sum()); attack = int((y_test == 1).sum())
    test_start = pd.Timestamp(test_start_ns, unit="ns", tz="UTC").isoformat()
    test_end = pd.Timestamp(test_end_ns, unit="ns", tz="UTC").isoformat()
    report = [
        "# Purged time-blocked research evaluation", "",
        "The complete UDPLag file is the natural-prevalence test block. Training uses only original source CSV rows earlier than the test start by at least 60 seconds, and removes every training row whose canonical bidirectional IP/port/protocol tuple appears anywhere in the test block. Later source files are excluded. No processed 21 GB CSV is rebuilt.", "",
        f"- Test interval (naive source timestamps localized to UTC): {test_start} to {test_end}",
        f"- Test rows: {len(y_test):,} (BENIGN {benign:,}; ATTACK {attack:,}); metrics use natural prevalence.",
        f"- Training source rows scanned: {train_data['metadata']['rows_scanned']:,}; past-only/group-purged eligible rows by class: {train_data['source_class_counts']}; retained balanced training sample: {len(y_train):,}.",
        f"- Gap: 60 seconds before test start. Tuple groups purged from training: {train_data['metadata']['rows_removed_for_tuple_overlap']:,} rows in the past-time candidate set.",
        "- Timestamps are ISO strings parsed to UTC nanoseconds. Source values have no timezone marker; UTC is a comparison convention, not verified capture-local timezone metadata.",
        "- Confidence intervals: 95% class-stratified row bootstrap and tuple-cluster bootstrap; predictions stay fixed across replicates. Row bootstrap does not model tuple dependence. Cluster intervals resample observed tuple groups stratified by each group’s label composition; this does not recover missing capture/session IDs.",
        "- Baseline ranking compares the research-only Random Forest refit, Extra Trees, Histogram Gradient Boosting, and Logistic Regression on identical filtered training and full test rows. No hyperparameter search was performed.",
        "- Deployed V2 is reported in a separate reference file only. It was trained on later and neighboring source periods, and its score is not an independent time-block result. Its saved model and feature file are read-only inputs.",
        "- Model-only latency, full-test batch throughput, and optional end-to-end API latency are separate. The API measurement requires --api-url and includes endpoint artifact loading, request parsing, prediction, and JSON response; loopback measurements exclude external network effects.",
        "- SHA-256 hashes for every source CSV are computed from the bytes consumed during the same pandas read. Model, feature, and code artifacts are hashed separately. No second full dataset read is used for hashing.",
        "- This split is time- and tuple-disjoint within the available CSV records, not capture/session-disjoint. The source data contains no explicit session/capture identifier or packet captures.", "",
        "## Matched-baseline results", "",
        "| Model | Accuracy | Precision | Recall | F1 | ROC AUC | Average precision |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for record in baseline_records:
        report.append(f"| {record['model']} | {record['accuracy']:.4f} | {record['precision']:.4f} | {record['recall']:.4f} | {record['f1']:.4f} | {record['roc_auc']:.4f} | {record['average_precision']:.4f} |")
    report += ["", "## Deployed V2 reference (not ranked)", "",
               "| Model | Accuracy | Precision | Recall | F1 | ROC AUC | Average precision |",
               "|---|---:|---:|---:|---:|---:|---:|",
               f"| {v2_record['model']} | {v2_record['accuracy']:.4f} | {v2_record['precision']:.4f} | {v2_record['recall']:.4f} | {v2_record['f1']:.4f} | {v2_record['roc_auc']:.4f} | {v2_record['average_precision']:.4f} |",
               "", "## Confidence intervals", "",
               "See `confidence_intervals.csv` for row-stratified and tuple-cluster 95% intervals.", "",
               "## Efficiency", "", "See `efficiency.csv` for fit time, repeated model-only latency, and repeated full-batch throughput. `api_efficiency.json` is either a separate endpoint measurement or an explicit NOT RUN status.", ""]
    (partial_dir / "report.md").write_text("\n".join(report), encoding="utf-8")

    metadata = {
        "seed": SEED, "bootstrap_seed": args.bootstrap_seed,
        "bootstrap_replicates": args.bootstrap_replicates,
        "tuple_cluster_bootstrap_replicates": args.cluster_bootstrap_replicates,
        "chunk_size": CHUNK_SIZE, "max_training_rows_per_class": args.max_per_class,
        "feature_count": len(features),
        "git": git_metadata(ROOT), "software_versions": package_versions(),
        "hardware": hardware_metadata(),
        "dataset_sha256": {**train_data["metadata"]["files"], TEST_PATH.name: {"sha256": test_data["sha256"], "rows": test_data["rows_read"], "invalid_timestamps": test_data["invalid_timestamps"], "invalid_tuple_keys": test_data["invalid_tuple_keys"], "start_utc": test_start, "end_utc": test_end}},
        "model_sha256": model_hash, "feature_file_sha256": feature_hash,
        "code_sha256": code_hashes, "input_fingerprints": input_fingerprints,
        "split": {"strategy": "forward time block plus 60-second pre-test gap and global canonical 5-tuple purge", "tuple_id_storage": "SHA-256 hex of the direction-independent canonical IP/port/protocol tuple", "test_file": str(TEST_PATH.relative_to(ROOT)), "training_files": [str(path.relative_to(ROOT)) for path in TRAIN_PATHS], "test_start_utc_assumption": test_start, "test_end_utc_assumption": test_end, "training_cutoff_utc_assumption": pd.Timestamp(test_start_ns - 60_000_000_000, unit="ns", tz="UTC").isoformat(), "later_training_rows_used": False, "tuple_disjoint": True},
        "training": {"rows_scanned": train_data["metadata"]["rows_scanned"], "eligible_class_counts": train_data["source_class_counts"], "sampled_class_counts": train_data["sampled_class_counts"], **{k: v for k, v in train_data["metadata"].items() if k != "files"}},
        "holdout": {"rows": len(y_test), "class_counts": {"BENIGN": benign, "ATTACK": attack}, "natural_prevalence": True},
        "benchmark": {"warmup_calls": args.latency_warmups, "single_row_repeats": args.latency_repeats, "full_test_batch_repeats": args.batch_repeats, "api_url": args.api_url, "api_result": api_efficiency},
        "limitations": ["No capture/session IDs or PCAPs are available.", "Source timestamps are timezone-naive; UTC is assumed for comparable intervals.", "Global tuple purging can exclude legitimate later reuse of a 5-tuple.", "Tuple-cluster bootstrap is a proxy and cannot represent capture-level uncertainty."],
        "saved_v2_model_modified": False, "saved_v2_feature_file_modified": False,
        "resume_used": args.resume, "reused_holdout_checkpoint": holdout_reused,
        "reused_training_checkpoint": training_reused,
        "reused_v2_reference_checkpoint": reference_reused,
        "reused_api_checkpoint": api_reused, "reused_shap_checkpoint": shap_reused,
    }
    (partial_dir / "run_metadata.json").write_text(json.dumps(metadata, indent=2, default=str), encoding="utf-8")
    required_outputs = [
        "baseline_results.csv", "deployed_v2_reference.csv", "confidence_intervals.csv",
        "efficiency.csv", "api_efficiency.json", "report.md", "run_metadata.json",
        "baseline_comparison.svg", "shap_global_importance.svg", "shap_beeswarm.svg",
        "shap_importance.csv", "confusion_random_forest__matched_research_refit.svg",
        "confusion_extra_trees.svg", "confusion_histogram_gradient_boosting.svg",
        "confusion_logistic_regression.svg", "confusion_deployed_random_forest_v2__reference_only.svg",
    ]
    manifest.mark_stage_complete("final_artifacts_written", "partial/")
    manifest.mark_complete(partial_dir, final_dir, required_outputs)
    print(f"\nResearch outputs COMPLETE: {final_dir}", flush=True)


def _confidence_rows(name, y_true, probabilities, tuple_keys, row_replicates, cluster_replicates, seed):
    rows = []
    for ci_type, intervals in (
        ("stratified_row_bootstrap", stratified_bootstrap_ci(y_true, probabilities, row_replicates, seed)),
        ("tuple_cluster_bootstrap", tuple_cluster_bootstrap_ci(y_true, probabilities, tuple_keys, cluster_replicates, seed + 1)),
    ):
        for metric, interval in intervals.items():
            rows.append({"model": name, "ci_type": ci_type, "metric": metric,
                         "lower_95": interval["lower_95"], "upper_95": interval["upper_95"],
                         "replicates": row_replicates if ci_type == "stratified_row_bootstrap" else cluster_replicates})
    return rows


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        if ACTIVE_MANIFEST is not None:
            try:
                ACTIVE_MANIFEST.mark_failed(error)
            except Exception:
                pass
        raise
