# Purged time-blocked research evaluation

The complete UDPLag file is the natural-prevalence test block. Training uses only original source CSV rows earlier than the test start by at least 60 seconds, and removes every training row whose canonical bidirectional IP/port/protocol tuple appears anywhere in the test block. Later source files are excluded. No processed 21 GB CSV is rebuilt.

- Test interval (naive source timestamps localized to UTC): 2018-12-01T13:04:45.928673+00:00 to 2018-12-01T13:30:30.740425+00:00
- Test rows: 370,605 (BENIGN 3,705; ATTACK 366,900); metrics use natural prevalence.
- Training source rows scanned: 49,692,507; past-only/group-purged eligible rows by class: {0: 25949, 1: 27585958}; retained balanced training sample: 20,000.
- Gap: 60 seconds before test start. Tuple groups purged from training: 12,071 rows in the past-time candidate set.
- Timestamps are ISO strings parsed to UTC nanoseconds. Source values have no timezone marker; UTC is a comparison convention, not verified capture-local timezone metadata.
- Confidence intervals: 95% class-stratified row bootstrap and tuple-cluster bootstrap; predictions stay fixed across replicates. Row bootstrap does not model tuple dependence. Cluster intervals resample observed tuple groups stratified by each group’s label composition; this does not recover missing capture/session IDs.
- Baseline ranking compares the research-only Random Forest refit, Extra Trees, Histogram Gradient Boosting, and Logistic Regression on identical filtered training and full test rows. No hyperparameter search was performed.
- Deployed V2 is reported in a separate reference file only. It was trained on later and neighboring source periods, and its score is not an independent time-block result. Its saved model and feature file are read-only inputs.
- Original V2 provenance remains incomplete: the exact training-row identities and original extractor version/settings are not recorded in the available project artifacts. The generation definitions for `SimillarHTTP`, `Inbound`, `CWE Flag Count`, and `Fwd Header Length.1` remain unresolved; this prevents establishing live-to-V2 feature parity.
- Model-only latency, full-test batch throughput, and optional end-to-end API latency are separate. The API measurement requires --api-url and includes endpoint artifact loading, request parsing, prediction, and JSON response; loopback measurements exclude external network effects.
- SHA-256 hashes for every source CSV are computed from the bytes consumed during the same pandas read. Model, feature, and code artifacts are hashed separately. No second full dataset read is used for hashing.
- This split is time- and tuple-disjoint within the available CSV records, not capture/session-disjoint. The source data contains no explicit session/capture identifier or packet captures.

## Matched-baseline results

| Model | Accuracy | Precision | Recall | F1 | ROC AUC | Average precision |
|---|---:|---:|---:|---:|---:|---:|
| Random Forest (matched research refit) | 0.1417 | 0.9998 | 0.1330 | 0.2348 | 0.9837 | 0.9997 |
| Extra Trees | 0.1424 | 0.9999 | 0.1337 | 0.2359 | 0.9935 | 0.9999 |
| Histogram Gradient Boosting | 0.1424 | 0.9998 | 0.1338 | 0.2360 | 0.9344 | 0.9991 |
| Logistic Regression | 0.1417 | 1.0000 | 0.1331 | 0.2349 | 0.8789 | 0.9987 |

## Deployed V2 reference (not ranked)

| Model | Accuracy | Precision | Recall | F1 | ROC AUC | Average precision |
|---|---:|---:|---:|---:|---:|---:|
| Deployed Random Forest V2 (reference only) | 0.9985 | 1.0000 | 0.9985 | 0.9992 | 1.0000 | 1.0000 |

## Confidence intervals

See `confidence_intervals.csv` for row-stratified and tuple-cluster 95% intervals.

## Efficiency

See `efficiency.csv` for fit time, repeated model-only latency, and repeated full-batch throughput. `api_efficiency.json` is either a separate endpoint measurement or an explicit NOT RUN status.

## Current application implementation status

Windows live packet capture and a React dashboard for observational TCP/UDP flow telemetry have been implemented and manually verified in tested scenarios. This telemetry is separate from model inference and does not classify live traffic as attacks.

Live Random Forest V2 inference remains blocked because feature-extraction parity with the original 82-feature training pipeline has not been verified. The saved model and feature schema are preserved.

CSV-based V2 inference was successfully verified on `UDPLag.csv` (370,605 rows); the recorded evaluation reports 366,325 predicted attacks and 4,280 predicted benign. These are model outputs, not independently verified ground truth.

The dedicated capture-queue consumer is implemented and its automated tests have passed. The specific backend revision running during Windows capture has not been independently confirmed.
