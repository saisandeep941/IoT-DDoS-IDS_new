# Research evaluation for the final-year project

## Evaluation scope and protocol

The saved experiment evaluates the complete CIC-DDoS2019-derived
`UDPLag.csv` block (370,605 records) at its natural label prevalence:
3,705 BENIGN and 366,900 ATTACK. The run records a SHA-256 for the dataset and
the evaluated model/schema artifacts. Metrics below are against the CSV's
provided labels.

The **research-only matched models** were newly fitted for this experiment on
a balanced sample of 10,000 BENIGN and 10,000 ATTACK rows. Training used only
source rows at least 60 seconds before the test block began. It removed every
past-time training row whose direction-independent canonical IP/port/protocol
5-tuple occurred anywhere in the complete holdout: 12,071 candidate rows were
purged. Later source rows were excluded. All matched models used the same
ordered 82-feature input, full UDPLag test block, and 0.5 decision threshold;
no hyperparameter search was performed.

This is a **same-source, forward-time, tuple-purged experiment**, not a test on
an independent dataset. Capture/session independence is unverified: there are
no PCAPs or capture/session IDs, and the timezone of the source timestamps is
not recorded (UTC was assumed for comparison). Tuple purging cannot establish
session separation.

## Research-only matched model results

Positive class is ATTACK. Confusion matrices are `[[TN, FP], [FN, TP]]`.
Metrics are shown to four decimal places from `research/results/baseline_results.csv`.

| Research-only model | Accuracy | Precision | Recall | F1 | ROC AUC | Average precision | Confusion matrix |
|---|---:|---:|---:|---:|---:|---:|---|
| Random Forest refit | 0.1417 | 0.9998 | 0.1330 | 0.2348 | 0.9837 | 0.9997 | `[[3696, 9], [318085, 48815]]` |
| Extra Trees | 0.1424 | 0.9999 | 0.1337 | 0.2359 | 0.9935 | 0.9999 | `[[3702, 3], [317830, 49070]]` |
| Histogram Gradient Boosting | 0.1424 | 0.9998 | 0.1338 | 0.2360 | 0.9344 | 0.9991 | `[[3695, 10], [317812, 49088]]` |
| Logistic Regression | 0.1417 | 1.0000 | 0.1331 | 0.2349 | 0.8789 | 0.9987 | `[[3703, 2], [318081, 48819]]` |

At the fixed 0.5 threshold, the matched models have high precision but low
ATTACK recall. The high average-precision values summarize ranking across
thresholds and do not change the fixed-threshold recall result. No calibration
study was performed; do not call the scores calibrated probabilities. The
saved confidence intervals use fixed predictions and do not account for model
selection or missing capture/session grouping.

For the research Random Forest refit, the saved 95% intervals are:

| Metric | Stratified row bootstrap (500 replicates) | Tuple-cluster bootstrap (250 replicates) |
|---|---:|---:|
| Accuracy | 0.14061–0.14283 | 0.14062–0.14290 |
| Precision | 0.99969–0.99994 | 0.99949–1.00000 |
| Recall | 0.13195–0.13419 | 0.13198–0.13419 |
| F1 | 0.23313–0.23662 | 0.23318–0.23662 |
| ROC AUC | 0.98157–0.98543 | 0.97987–0.98661 |
| Average precision | 0.99964–0.99971 | 0.99959–0.99974 |

The saved CSV contains intervals for every comparator and the V2 reference.
Both bootstrap methods resample the saved predictions; the tuple-cluster
interval is only a tuple-level proxy, not capture/session-level uncertainty.

## Frozen Random Forest V2 reference only

The protected Random Forest V2 was applied to the same UDPLag block, but it is
**not** a matched-model result and **not** an independent evaluation. The inspected trainer is configured to read a merged source CSV that excludes the file named `UDPLag.csv`, but no contemporaneous run record or saved row membership ties that procedure to this model artifact. Its score is therefore shown only as a descriptive reference:

| Model | Accuracy | Precision | Recall | F1 | ROC AUC | Average precision | Confusion matrix |
|---|---:|---:|---:|---:|---:|---:|---|
| Frozen Random Forest V2 (reference only) | 0.9985 | 1.0000 | 0.9985 | 0.9992 | 1.0000 | 1.0000 | `[[3705, 0], [563, 366337]]` |

These values are taken from `research/results/deployed_v2_reference.csv`.
They must not be described as independent-dataset validation, forward-time
generalization, or a fair comparison with the research-only refits. V2 feature
generation parity and historical training-row membership remain unresolved.

## Recommended wording

**Report/presentation:** “We conducted a same-source, forward-time evaluation
on the CIC-DDoS2019-derived UDPLag block. Research-only models were trained on
earlier records with a 60-second gap and direction-independent 5-tuple overlap
purging. The test block contained 370,605 labeled flows. This protocol reduces
temporal and tuple overlap, but capture/session independence is not established.
The frozen Random Forest V2 score is included only as a reference: its exact historical training membership and feature-generation parity are unverified. No independent-dataset evaluation of V2 has been established.”

Do not label this experiment “independent dataset evaluation.” A genuinely
external evaluation requires a compatible, independently sourced dataset;
the available evidence does not establish one for the protected V2 schema.

## Reproducibility artifacts and integrity

The exact saved evidence is in [`research/results/report.md`](../research/results/report.md),
`baseline_results.csv`, `deployed_v2_reference.csv`, `confidence_intervals.csv`,
`run_metadata.json`, and [`research/run_manifest.json`](../research/run_manifest.json).
The manifest marks the run complete. No training or prediction was rerun to
prepare this document. The protected working-copy hashes remain:

- V2 model: `61AF42BE7F2B079E4BF6FE8D766373CD1D2F91966B28E6BF722810DE53F4D9D2`
- Ordered 82-feature schema: `C49933ABE8DF5A693915BD788153BCB7302D75AAB486A65E6B07E0A1ABCC3E28`

The application AI Insights page exposes the saved matched-refit and V2
reference tables through `/api/research/evaluation`; it reads these saved
artifacts and does not run evaluation or calculate new metrics.


