# Submission package manifest

The submission archive is `IoT-DDoS-IDS-Submission.zip` in the working-copy root. It contains the inventory below and excludes datasets, virtual environments, `node_modules`, caches, frontend build output, captures, secrets, and machine-specific settings. Research results and source code are packaged from the working copy; the protected original backup is not included.

## Rebuild the archive

Run `python research\code\build_submission.py` from the working-copy root. The builder uses an explicit allowlist and fixed ZIP timestamps, checks the protected model/schema hashes, and verifies the archive inventory and file contents. It also writes `IoT-DDoS-IDS-Submission.manifest.json` beside the archive with the ZIP SHA-256 and each included file's size and SHA-256. Repeated builds with the same source files and Python/zlib environment produce the same archive bytes and manifest.

## Application (`application/`)

- Backend application source: `backend/main.py`, `backend/dataset_validation.py`, `backend/capture_routes.py`, `backend/capture_worker.py`, `backend/capture_telemetry.py`, and `backend/flow_telemetry.py`.
- Runtime V2 model/schema copies beside the backend.
- `frontend/src/` application source, including the live capture panel and flow telemetry client; frontend build configuration, `package.json`, and `package-lock.json`.
- `requirements.txt` for core backend dependencies and `capture-requirements.txt` for optional capture support.
- Backend validation helper for ground-truth CSV labels, plus regression tests for CSV prediction validation and dataset analysis, risk scoring and SHAP failure paths, detection history, risk/severity mapping, capture telemetry, capture-flow integration, and flow telemetry.
- Controlled CSV traffic replay endpoints and focused replay validation/control tests. Replay is a stored-data simulation; it does not infer from live packets or establish independent-dataset compatibility.
- Saved evaluation-results API and regression test; the dashboard reads recorded research metrics and does not calculate new model results.
- Frontend tests for CSV upload workflow and flow telemetry.

## Model (`model/`)

- `real_model_v2.joblib`
- `real_model_features_v2.joblib` (82-feature schema)

The application runtime copies are byte-identical to these authoritative model files. SHA-256 values are recorded in the sanitized research metadata.

## Research (`research/`)

- `results/report.md`, matched-baseline and deployed V2 reference tables, confidence intervals, efficiency outputs, the CPU/memory benchmark report, figures, SHAP figures/table, and sanitized run metadata.
- `run_manifest.json`, sanitized to remove local absolute dataset paths while retaining the `COMPLETE` state and verified-output list.
- `code/build_submission.py`, `code/benchmark_v2_resource_usage.py`, `code/evaluate_research.py`, `code/research_eval_protocol.py`, `code/test_research_evaluation.py`, and `code/validate_dataset.py` with its regression tests.

The run manifest's `verified_outputs` preserves the canonical 16-result names; the packaged sanitized metadata is available as both `run_metadata.json` (to match that list) and `run_metadata_submission.json`.

## Documentation (`docs/`)

- `final_year_research_evaluation.md` (concise submission summary and claim guidance)
- `research_evaluation.md`
- `limitation1_independent_evaluation.md`
- `submission_manifest.md` (this file)

## Excluded and preserved locally

No source or processed datasets, evaluation checkpoints, superseded root-level research outputs, secrets, machine-specific environment files, build output, or `node_modules` are included. These remain untouched in the source project.
The working-copy `docs/final_limitation_resolution_report.md` is retained locally as a completion audit and is excluded from the archive because it records the archive's own SHA-256.

## Limitations

Capture/session independence has not been established. The deployed V2 result is a reference score, not an independent time-block evaluation. Matched-baseline recall at threshold 0.5 is about 13.3%, and probability calibration was not evaluated. End-to-end API latency was not measured. Windows live packet capture and observational TCP/UDP flow telemetry have been implemented and manually verified in tested scenarios; they do not produce live ML predictions. Live Random Forest V2 inference remains blocked pending verified 82-feature extraction parity, and automatic attack blocking is not implemented. The dedicated queue consumer has passing automated tests, but its specific running Windows backend revision has not been independently confirmed. Source datasets are excluded from the submission package; dataset preview and the application's runtime SHAP endpoint need separately available dataset files.

No compatible independent evaluation dataset is established by the available evidence. UDPLag was used for prior evaluation and threshold comparisons. A CSV header passing the included validator establishes names and order only; the documented definitions and extraction methodology for `SimillarHTTP`, `Inbound`, `CWE Flag Count`, and `Fwd Header Length.1` are still required to claim compatibility. Dataset provenance, licensing, labels, and overlap with V2 training data must also be established before making an independent-evaluation claim.
