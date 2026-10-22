# Final implementation and limitation-resolution report

## Outcome

The misleading repeated all-zero stream has been removed from the dashboard.
Threat Detection now offers **CSV Traffic Replay Simulation**, which sends
ordered source records through the frozen Random Forest V2 pipeline in small
configurable batches. Pause, resume, stop, and clear controls are available.
Replay predictions are added to detection history with processing time,
optional source timestamp, filename, row number, class, model risk score,
severity, and per-row SHAP contributions when SHAP succeeds. Missing SHAP
output is reported as unavailable with its reason. A supplied `Label` is
validated for blanks and displayed only as ground-truth context; it is never
used to derive a model prediction or replay metric.

The replay endpoint checks that each of the 82 saved feature names appears
once, in the exact saved order. It accepts extra metadata columns, rejects
missing, duplicate, or reordered feature columns, malformed/empty inputs,
and rows with no usable numeric model features. Partial nonnumeric values are
handled by the frozen pipeline's existing fitted imputer. This structural
check does not establish semantic feature parity between datasets.

The legacy `/api/stream/start` zero-vector endpoint now returns HTTP 410 and
does not load or invoke the model. Live packet capture remains separate and
observational; no packet-to-V2 feature extraction or live ML inference is
claimed.

## Final targeted limitation status

| Task | Status | Evidence-based result |
|---|---|---|
| Evaluation visibility | **RESOLVED** | AI Insights loads saved baseline, V2-reference, interval, and efficiency artifacts through `/api/research/evaluation`. It separates research refits from frozen V2 and shows saved accuracy, precision, recall, F1, ROC-AUC, average precision, confusion matrices, class counts, and protocol details. It does not calculate new metrics. |
| Independent-dataset evaluation | **BLOCKED** | Existing reports identify UDPLag as previously used and document no fresh compatible dataset. Unresolved V2 feature semantics and missing provenance prevent defensible cross-dataset mapping. |
| Live packet-to-model inference | **BLOCKED** | Capture/telemetry provides observational flow summaries, not a verified generator for the exact 82 V2 inputs. No prediction path was added. |
| Four feature definitions | **PARTIALLY RESOLVED** | Original script behavior and inspected values are documented, but generation semantics remain unverified: `SimillarHTTP` meaning/encoding, `Inbound` direction reference, CWE/CWR bit/count rule, and full provenance/intent for `Fwd Header Length.1`. |
| Historical training membership | **PARTIALLY RESOLVED** | The seeded reservoir and split method are documented, but exact rows cannot be verified without a training-time input checksum/runtime record and saved sample/split identities. Replaying the algorithm without that anchor would be reconstruction, not proof; no replay or training was run. |

## Other verified corrections

- CSV prediction and batch-stream endpoints now reject a missing, duplicated,
  or reordered saved feature schema instead of silently reordering columns.
- `/api/risk-score` maps severity using the unrounded risk value and reports
  the class returned by the model. A risk of 24.6 displays as 25 but remains
  Low under the existing provisional 25-point threshold.
- Static SHAP output now selects the class actually predicted for its first
  UDPLag example and labels itself as that saved example, not the latest
  dashboard prediction. Replay explanations are computed from each replayed
  row and its predicted class when available.
- Saved research results are served from the canonical baseline, frozen-
  reference, confidence-interval, efficiency, and sanitized metadata files.
  The dashboard labels the 60-second gap, 12,071 tuple purges, natural
  prevalence, and evaluation limitations.
- The temporary upload endpoint is a synchronous FastAPI route so file reads
  use the server's worker thread and the handler tests do not require creating
  a Windows asyncio self-pipe. A separate HTTP transport smoke test was not
  completed because the Python 3.14 loop initialization in this environment
  blocked in `socket.accept()` while creating that self-pipe.

## Remaining limitations

- **Independent evaluation is not established.** The compatible local UDPLag
  data has already been used in the project's research evaluation. The
  definitions/generation provenance of `SimillarHTTP`, `Inbound`,
  `CWE Flag Count`, and `Fwd Header Length.1`, and historical V2 training-row
  membership remain unresolved. CSV replay demonstrates inference only; it
  does not create external validation evidence.
- The previously saved same-source, 60-second-gap and tuple-purged research
  experiment remains the research result. Capture/session independence is
  unverified. The frozen V2 score remains reference-only.
- Live capture provides observational telemetry, not V2 classification.
- Risk/severity cutoffs remain provisional and are not calibrated.
- Static SHAP needs the local UDPLag CSV. Per-row replay SHAP can be
  unavailable if the dependency or explainer fails; in that case the UI shows
  an explicit unavailable state.
- Automatic blocking is not implemented.

## Verification performed

- Focused regression command (after the final backend changes):
  `python -m pytest application\ml\test_csv_replay.py application\ml\test_risk_explainability.py application\ml\test_stream_severity.py application\ml\test_csv_prediction_endpoint.py -q`
  — **16 passed**, 2 existing FastAPI lifecycle deprecation warnings, 10
  subtests passed.
- Final backend/research regression command:
  `python -m pytest application\ml research\code -q` — **89 passed**, 2
  existing FastAPI lifecycle deprecation warnings, 14 subtests passed.
- Saved evaluation API regression:
  `python -m pytest application\ml\test_research_evaluation_api.py -q` —
  **1 passed**, 2 existing FastAPI lifecycle deprecation warnings.
- Frontend `npm test` — **7 passed**.
- Frontend `npm run lint` — completed with no lint findings.
- Frontend `npm run build` — succeeded with Vite 8.3.4. The minified JS chunk
  is 672.35 kB and exceeds Vite's 500 kB advisory threshold; this is a warning,
  not a failed build.
- One-row backend endpoint-handler smoke check using the existing local
  `UDPLag.csv` record and actual frozen model: one record was replayed,
  predicted, explained by SHAP, and the session completed. No evaluation
  metrics were calculated. A separate HTTP transport smoke test was not run;
  the Windows event-loop initialization issue above remains an environment
  limitation.
- `research/code/build_submission.py` rebuilt and verified the curated archive
  with 71 allowlisted entries. The sidecar manifest matches every archived
  entry to its current working-copy source.

## Changed files

- `application/backend/main.py` — replay API and controls, strict CSV schema
  checks, risk threshold correction, prediction-matched SHAP output, and
  read-only endpoint for saved evaluation artifacts.
- `application/backend/dataset_validation.py` — efficient duplicate-header
  detection used by exact schema validation.
- `application/frontend/src/App.jsx`, `application/frontend/src/App.css` —
  controlled CSV replay UI, prediction history details, truthful explanation
  labels.
- `application/ml/test_csv_replay.py` — new replay, schema, labels, lifecycle,
  and disabled-zero-vector regression tests.
- `application/ml/test_risk_explainability.py` and
  `application/ml/test_csv_prediction_endpoint.py` — focused boundary,
  predicted-class, and updated schema-error checks.
- `application/ml/test_research_evaluation_api.py` — compares the saved-results
  API payload directly with the existing artifacts.
- `README.md`, `docs/research_evaluation.md`,
  `docs/final_year_research_evaluation.md`, and
  `docs/submission_manifest.md` — aligned replay instructions and claim
  boundaries and saved-result dashboard visibility.
- `research/code/build_submission.py` — packages the replay and evaluation API
  regression tests. This completion report remains local and is excluded from
  the ZIP because it records that ZIP's own hash.

## Integrity and package

The frozen model and ordered 82-feature schema are read-only. Required SHA-256
values:

- Model: `61AF42BE7F2B079E4BF6FE8D766373CD1D2F91966B28E6BF722810DE53F4D9D2`
- Schema: `C49933ABE8DF5A693915BD788153BCB7302D75AAB486A65E6B07E0A1ABCC3E28`

Final model/schema and ZIP hashes are recorded after the curated package is
rebuilt and verified:

- Final model SHA-256: `61AF42BE7F2B079E4BF6FE8D766373CD1D2F91966B28E6BF722810DE53F4D9D2`
- Final schema SHA-256: `C49933ABE8DF5A693915BD788153BCB7302D75AAB486A65E6B07E0A1ABCC3E28`
- ZIP: `IoT-DDoS-IDS-Submission.zip`
- ZIP SHA-256: `88C50F8F25459EEBF460FE72C9D0DFBE039141EA0EFB8672902EA17C2E435E8B`
