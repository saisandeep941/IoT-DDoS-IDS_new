# Research evaluation: completed run

## Status and canonical artifacts

The full research evaluation completed on 2026-10-17. The canonical detailed report and evaluation outputs are in [`research/results/`](../research/results/). The run manifest at [`research/run_manifest.json`](../research/run_manifest.json) is `COMPLETE` and records verification of all 16 required outputs. Use [`final_year_research_evaluation.md`](final_year_research_evaluation.md) as the concise final-year summary and claim guidance; it reuses the saved outputs without rerunning the experiment.

Older root-level balanced-sample outputs remain preserved in the source checkout, are excluded from this package, and are superseded. They must not be cited as the completed result.

The evaluator read the original source CSVs. It did not rebuild the 21 GB processed CSV. The saved Random Forest V2 model and its feature file were read-only inputs; the research-only Random Forest baseline was separately fit and did not replace V2.

## Evaluation design

- **Test block:** all 370,605 rows of `dataset/01-12/UDPLag.csv`, evaluated at natural prevalence: 3,705 BENIGN and 366,900 ATTACK rows.
- **Timestamps:** source timestamps are timezone-naive ISO strings parsed as UTC and converted to Unix nanoseconds. UTC is a comparison convention; the capture-local timezone was not verified.
- **Training eligibility:** only original training-source rows at least 60 seconds before the earliest UDPLag timestamp were eligible. Training rows were also purged if their direction-independent canonical source IP/port, destination IP/port, and protocol tuple appeared anywhere in the complete holdout. The scan covered 49,692,507 source rows; 12,071 past-time candidate rows were removed for tuple overlap. Later rows were excluded.
- **Training sample:** a seeded, class-balanced sample of 10,000 BENIGN and 10,000 ATTACK rows was retained. All matched baselines used that same sample, ordered 82-feature schema, full natural-prevalence test block, and a 0.5 classification threshold. No hyperparameter search was performed.
- **Comparators:** matched research-only Random Forest, Extra Trees, Histogram Gradient Boosting, and Logistic Regression. The saved deployed V2 model is a separate reference row, not part of the matched-baseline ranking.
- **Intervals:** 95% class-stratified row-bootstrap intervals (500 replicates) and tuple-cluster bootstrap intervals (250 replicates). Predictions were held fixed during resampling.

## Canonical performance results

Metrics below are copied from the canonical report and results tables. Threshold-dependent measures use a 0.5 classification threshold; ROC AUC and average precision summarize ranking over thresholds.

| Matched baseline | Accuracy | Precision | Recall | F1 | ROC AUC | Average precision |
|---|---:|---:|---:|---:|---:|---:|
| Random Forest (matched research refit) | 0.1417 | 0.9998 | 0.1330 | 0.2348 | 0.9837 | 0.9997 |
| Extra Trees | 0.1424 | 0.9999 | 0.1337 | 0.2359 | 0.9935 | 0.9999 |
| Histogram Gradient Boosting | 0.1424 | 0.9998 | 0.1338 | 0.2360 | 0.9344 | 0.9991 |
| Logistic Regression | 0.1417 | 1.0000 | 0.1331 | 0.2349 | 0.8789 | 0.9987 |

### Deployed V2 reference — not an independent time-block result

| Reference | Accuracy | Precision | Recall | F1 | ROC AUC | Average precision |
|---|---:|---:|---:|---:|---:|---:|
| Deployed Random Forest V2 (reference only) | 0.9985 | 1.0000 | 0.9985 | 0.9992 | 1.0000 | 1.0000 |

The inspected V2 trainer is configured to use a merged source CSV that excludes the file named `UDPLag.csv`, but no contemporaneous run record or saved row membership ties that procedure to this artifact. Its score is a descriptive reference on UDPLag, not evidence of independent forward-time generalization and not a fair matched-baseline comparison.

At threshold 0.5, matched-baseline recall is approximately **13.3%** while precision is near 1.0. High average precision indicates strong score ranking on this test block, but it does not explain threshold selection or establish calibrated probabilities. No probability-calibration study is reported; do not describe model scores as calibrated. The complete row and tuple interval values are in `confidence_intervals.csv`.

## Efficiency results and scope

The evaluator used 20 warmup calls, 500 repeated one-row calls, and three repeated full-test batches. These measurements are model-only and batch processing measurements; they are not end-to-end service latency.

| Model | One-row model-only p50 (ms) | p95 (ms) | Full-test batch throughput (rows/s) |
|---|---:|---:|---:|
| Random Forest (matched research refit) | 4.846 | 8.556 | 276,875 |
| Extra Trees | 8.888 | 19.174 | 146,330 |
| Histogram Gradient Boosting | 3.357 | 5.174 | 360,768 |
| Logistic Regression | 1.030 | 2.512 | 976,227 |
| Deployed Random Forest V2 (reference only) | 30.152 | 54.968 | 205,657 |

The endpoint/API benchmark was **NOT RUN** (`api_url` was not supplied). Do not infer endpoint latency from the model-only or batch results. Hardware and software details are in `run_metadata.json`; physical memory and physical-core count were unavailable in the recorded environment metadata.

## Research limitations and claim boundaries

- This is time-blocked and tuple-purged only within the available CSV records. **Capture/session independence has not been established:** no capture/session IDs or PCAPs are available, and the timestamp timezone is unverified.
- Original V2 provenance remains incomplete: the exact training-row identities and original extractor version/settings are not recorded in the available project artifacts. The generation definitions for `SimillarHTTP`, `Inbound`, `CWE Flag Count`, and `Fwd Header Length.1` remain unresolved; this prevents establishing live-to-V2 feature parity.
- Global tuple purging can remove legitimate later reuse of a tuple. The time gap and purge do not recover unavailable capture provenance.
- Row bootstrap treats rows as independent. Tuple-cluster bootstrap is only a tuple-level proxy, not a capture/session-level uncertainty estimate. Both condition on fixed fitted models and predictions; they do not include retraining or model-selection variation.
- These scores describe this dataset and split. They do not independently establish production or deployment performance. The V2 reference has the additional training-period overlap described above.
- The report contains no calibration analysis. **Do not claim calibrated probabilities.** Baseline recall at the stated 0.5 threshold is about 13.3%.
- The application supports CSV-based ML analysis and CSV traffic replay simulation using frozen V2. Windows live packet capture and a React dashboard for observational TCP/UDP flow telemetry are implemented and were manually verified in tested scenarios. This live telemetry is not live ML attack classification.
- CSV-based V2 inference was successfully verified on `UDPLag.csv` (370,605 rows): 366,325 predicted attacks and 4,280 predicted benign. Recorded metrics were 99.8448% accuracy, 100% precision, 99.8433% recall, and 99.9216% F1. These predictions are model outputs, not independently verified ground truth.
- The dedicated capture-queue consumer is implemented and its automated tests have passed; the specific backend revision running during Windows capture has not been independently confirmed.
- Live Random Forest V2 inference remains blocked because feature-extraction parity with its original 82-feature training pipeline is unverified. Automatic attack blocking is not implemented.
- SHAP artifacts explain the saved V2 model on the selected holdout sample; they do not establish causal feature effects.

## Submission files versus internal run data

Recommended research deliverables are the canonical report, matched-baseline and V2-reference tables, confidence intervals, efficiency measurements and API status, comparison/confusion figures, SHAP figures and importance table, and run metadata, all from `research/results/`. The run manifest can be included as provenance.

The source project's `evaluation_lowmem_20261017/checkpoints/` directory contains internal recovery/intermediate data (including disk-backed arrays and serialized model stages), not a publication deliverable. It remains in the source project and is excluded from this package. Do not load checkpoint pickle files from untrusted sources. No datasets or model artifacts need to be included to submit the report.

For provenance, the completed run records Git revision `dcadb000727a74836f2877dd7a7aa80afa4ccd66`, dirty-tree state, dataset hashes, model and feature-file hashes, code hashes, versions, seeds, and split rules. The original metadata contains local input paths and remains in the source project; this package includes sanitized copies of the metadata and run manifest.




## Application verification

- CSV prediction endpoint: successfully processed `UDPLag.csv` (370,605 rows); results and metrics are recorded above.
- Frontend production build: previously completed successfully; one JavaScript bundle-size warning remains. The build was not rerun during this completion pass.
- Automated tests: 47 passed, 0 failed; two FastAPI `on_event` deprecation warnings.
- Streaming smoke checks: simulated stream returned HTTP 200; non-CSV upload validation returned HTTP 400.

## Final completion pass (2026-10-21)

The 2026-10-21 completion pass replaced the all-zero synthetic stream with controlled CSV traffic replay, enforced exact feature-name/order validation for CSV inference, fixed risk-score class lookup and severity threshold handling, and aligned static SHAP output with the predicted class for its selected UDPLag example. Replay and live capture are distinct: replay uses stored rows, while capture remains observational. The saved V2 model and ordered schema were not changed.

- Backend and research tests: `74 passed, 2 warnings, 6 subtests passed`; warnings are FastAPI `on_event` deprecations. Command from the working-copy root: `$env:PYTHONPATH = (Join-Path (Get-Location).Path 'application'); $env:TEMP = (Join-Path (Get-Location).Path '.test-tmp'); $env:TMP = $env:TEMP; .\.venv\Scripts\python.exe -m pytest application\ml research\code -q`.
- Frontend tests: `7 passed, 0 failed`; command from `application/frontend`: `npm test` (`node --test src/*.test.js`).
- Frontend production build: succeeded with Vite 8.3.4. The 666.39 kB minified JavaScript chunk exceeds Vite's 500 kB advisory threshold; build did not fail.
- Frontend lint completed with two hook warnings in `LiveCapturePanel.jsx` (synchronous effect state updates and a missing `headers` dependency); no lint errors were reported.
- A direct FastAPI `TestClient` smoke attempt loaded the app and model/schema, but endpoint requests did not return within the bounded wait and were interrupted. Endpoint-level runtime behavior is therefore not claimed as newly verified here. Unit tests and previous recorded tests remain the available evidence.
- Dataset validation utility regression tests cover exact order, missing names, duplicates, surrounding header whitespace, and a trailing label. UDPLag passes the structural header check after the same whitespace trimming used by production CSV prediction. This does not establish semantic feature compatibility.
- The workspace contains UDPLag as the only local candidate dataset found. It is already used for historical evaluation. No independent compatible dataset was established; the four unresolved feature definitions and missing training extractor provenance remain blockers.

## Follow-up reliability pass (2026-10-21)

- Dataset analysis now rejects blank or missing ground-truth labels before producing counts. Focused tests exercise the endpoint handler with temporary CSV uploads; complete labels return the expected counts and invalid labels raise HTTP 400 with a clear detail. Full HTTP transport could not be verified here: Python's Windows asyncio event-loop initialization blocked while creating its self-pipe, before the request reached the handler.
- A Windows regression-test cleanup now closes a borrowed holdout memmap reference before temporary-directory removal.
- Backend and research tests: 82 passed, 2 FastAPI `on_event` deprecation warnings, 12 subtests passed. Frontend tests: 7 passed. Frontend lint: no warnings. Production build succeeded; the 666.45 kB minified JavaScript chunk remains above Vite's 500 kB advisory threshold.
- The model and ordered 82-feature schema remain unchanged. Independent evaluation and live packet-to-V2 inference remain blocked by the feature-provenance and overlap evidence gaps recorded above; live capture continues to provide observational telemetry only.


