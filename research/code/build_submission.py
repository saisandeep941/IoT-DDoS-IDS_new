"""Build the curated, reproducible project submission archive."""
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo
import hashlib
import json
import os

ROOT = Path(__file__).resolve().parents[2]
ARCHIVE = ROOT / "IoT-DDoS-IDS-Submission.zip"
MANIFEST = ROOT / "IoT-DDoS-IDS-Submission.manifest.json"
EXPECTED = {
    "model/real_model_v2.joblib": "61AF42BE7F2B079E4BF6FE8D766373CD1D2F91966B28E6BF722810DE53F4D9D2",
    "model/real_model_features_v2.joblib": "C49933ABE8DF5A693915BD788153BCB7302D75AAB486A65E6B07E0A1ABCC3E28",
    "application/backend/real_model_v2.joblib": "61AF42BE7F2B079E4BF6FE8D766373CD1D2F91966B28E6BF722810DE53F4D9D2",
    "application/backend/real_model_features_v2.joblib": "C49933ABE8DF5A693915BD788153BCB7302D75AAB486A65E6B07E0A1ABCC3E28",
}
FILES = (
    "application/capture-requirements.txt",
    "application/requirements.txt",
    "application/backend/capture_routes.py",
    "application/backend/capture_telemetry.py",
    "application/backend/capture_worker.py",
    "application/backend/dataset_validation.py",
    "application/backend/flow_telemetry.py",
    "application/backend/main.py",
    "application/backend/real_model_features_v2.joblib",
    "application/backend/real_model_v2.joblib",
    "application/frontend/.gitignore",
    "application/frontend/.oxlintrc.json",
    "application/frontend/index.html",
    "application/frontend/package-lock.json",
    "application/frontend/package.json",
    "application/frontend/vite.config.js",
    "application/frontend/public/favicon.svg",
    "application/frontend/public/icons.svg",
    "application/frontend/src/App.css",
    "application/frontend/src/App.jsx",
    "application/frontend/src/flowTelemetry.js",
    "application/frontend/src/flowTelemetry.test.js",
    "application/frontend/src/index.css",
    "application/frontend/src/LiveCapturePanel.css",
    "application/frontend/src/LiveCapturePanel.jsx",
    "application/frontend/src/main.jsx",
    "application/frontend/src/uploadWorkflow.js",
    "application/frontend/src/uploadWorkflow.test.js",
    "application/ml/test_capture_flow_integration.py",
    "application/ml/test_capture_telemetry.py",
    "application/ml/test_csv_prediction_endpoint.py",
    "application/ml/test_csv_replay.py",
    "application/ml/test_research_evaluation_api.py",
    "application/ml/test_dataset_analysis.py",
    "application/ml/test_detection_history.py",
    "application/ml/test_flow_telemetry.py",
    "application/ml/test_stream_severity.py",
    "application/ml/test_risk_explainability.py",
    "docs/research_evaluation.md",
    "docs/limitation1_independent_evaluation.md",
    "docs/submission_manifest.md",
    "model/real_model_features_v2.joblib",
    "model/real_model_v2.joblib",
    "research/run_manifest.json",
    "research/code/build_submission.py",
    "research/code/benchmark_v2_resource_usage.py",
    "research/code/evaluate_research.py",
    "research/code/research_eval_protocol.py",
    "research/code/test_research_evaluation.py",
    "research/code/validate_dataset.py",
    "research/code/test_validate_dataset.py",
    "research/results/api_efficiency.json",
    "research/results/baseline_comparison.svg",
    "research/results/baseline_results.csv",
    "research/results/confidence_intervals.csv",
    "research/results/confusion_deployed_random_forest_v2__reference_only.svg",
    "research/results/confusion_extra_trees.svg",
    "research/results/confusion_histogram_gradient_boosting.svg",
    "research/results/confusion_logistic_regression.svg",
    "research/results/confusion_random_forest__matched_research_refit.svg",
    "research/results/deployed_v2_reference.csv",
    "research/results/efficiency.csv",
    "research/results/inference_resource_benchmark.md",
    "research/results/report.md",
    "research/results/run_metadata.json",
    "research/results/run_metadata_submission.json",
    "research/results/shap_beeswarm.svg",
    "research/results/shap_global_importance.svg",
    "research/results/shap_importance.csv",
    "docs/final_year_research_evaluation.md",
    "README.md",
)

# Keep the curated archive explicit: this additional inventory contains only
# project code, model exports, documentation, and machine-readable research
# results. It never walks source data or frontend dependency directories.
V3_FILES = (
    "application/backend/detection_history.py",
    "application/ml/test_v3_model.py",
    "application/ml/test_detection_history_persistence.py",
    "model_v3/v3_xgb_model.json",
    "model_v3/v3_features.json",
    "model_v3/v3_imputer_medians.json",
    "model_v3/v3_metadata.json",
    "model_v3/v3_loader.py",
    "docs/final_v31_report.md",
)
RESULT_FILES = tuple(
    path.relative_to(ROOT).as_posix()
    for path in sorted((ROOT / "research" / "results_v31").rglob("*"))
    if path.is_file() and path.suffix.lower() in {".py", ".json", ".csv", ".md", ".txt"}
)
PROMOTED_FILES = tuple(
    path.relative_to(ROOT).as_posix()
    for path in sorted((ROOT / "model_v3_1").rglob("*"))
    if path.is_file() and path.suffix.lower() in {".json", ".py"}
) if (ROOT / "model_v3_1").is_dir() else ()
FILES = tuple(dict.fromkeys((*FILES, *V3_FILES, *RESULT_FILES, *PROMOTED_FILES)))


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def build() -> None:
    for relative, expected in EXPECTED.items():
        source = ROOT / Path(relative.replace("/", os.sep))
        if sha256(source.read_bytes()) != expected:
            raise SystemExit(f"Protected model artifact hash mismatch: {relative}")

    temp = ROOT / ".IoT-DDoS-IDS-Submission.zip.tmp"
    try:
        with ZipFile(temp, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
            for relative in FILES:
                source = ROOT / Path(relative.replace("/", os.sep))
                if not source.is_file():
                    raise SystemExit(f"Required submission file is missing: {relative}")
                data = source.read_bytes()
                info = ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                archive.writestr(info, data, compress_type=ZIP_DEFLATED, compresslevel=9)

        with ZipFile(temp, "r") as archive:
            if archive.namelist() != list(FILES):
                raise SystemExit("Submission archive inventory verification failed.")
            for relative in FILES:
                if archive.read(relative) != (ROOT / Path(relative.replace("/", os.sep))).read_bytes():
                    raise SystemExit(f"Submission archive content mismatch: {relative}")
        os.replace(temp, ARCHIVE)
    finally:
        if temp.exists():
            temp.unlink()

    print(f"Built and verified {ARCHIVE.name} ({len(FILES)} files).")
    print(f"Archive SHA-256: {sha256(ARCHIVE.read_bytes())}")
    with ZipFile(ARCHIVE, "r") as archive:
        manifest = {
            "archive": ARCHIVE.name,
            "archive_sha256": sha256(ARCHIVE.read_bytes()),
            "files": [
                {
                    "path": name,
                    "size_bytes": len(data := archive.read(name)),
                    "sha256": sha256(data),
                }
                for name in FILES
            ],
        }
    MANIFEST.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"File inventory and SHA-256 manifest: {MANIFEST.name}")


if __name__ == "__main__":
    build()
