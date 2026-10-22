# V3.1 Evaluation and Integration Report

Status: partial, work paused at the user's request to conserve remaining usage, as of 2026-10-22. Detailed phase outputs and executable
scripts are in [`research/results_v31/`](../research/results_v31/). The source
CSV files were read locally in chunks; no dataset was uploaded.

## Completed evaluation

Phase A evaluated frozen V3 on the full 03-11 UDPLag CSV and on CIC-IDS2017
Friday DDoS plus benign Friday morning. Confidence intervals and per-label
counts are in `phase_a_raw.json`.

| Test set | Rows (BENIGN / ATTACK) | AUC | Balanced recall / FPR | Strict recall / FPR |
|---|---:|---:|---:|---:|
| CIC-DDoS2019 03-11 UDPLag | 725,165 (4,068 / 721,097) | 0.9900 | 0.9318 / 0.0737 | 0.8899 / 0.0076 |
| CIC-IDS2017 Friday DDoS + benign morning | 414,812 (286,785 / 128,027) | 0.4228 | 0.3483 / 0.3369 | 0.0063 / 0.0658 |

The CIC-IDS2017 result is poor at both operating points. It is direct evidence
against cross-dataset reliability; no new model should be promoted on this
evidence.

Phase C fit isotonic calibration only on the first time half of 03-11 UDPLag.
It was evaluated on the second half and CIC-IDS2017 Friday. Brier / 15-bin ECE
changed from 0.0603 / 0.0696 to 0.0627 / 0.0711 on the 03-11 second half, and
from 0.4182 / 0.4205 to 0.3855 / 0.3724 on CIC-IDS2017. The mapped probability
is used for risk score × 100; the balanced/strict classification decisions
continue to use metadata thresholds against the raw model probability. The
existing severity cutoffs remain provisional and uncalibrated.

## Integration and checks

The backend uses the native V3 loader and retains strict 82-column CSV input
validation before selecting the ordered 47 V3 features. SHAP uses the V3
XGBoost model and prepared features. V2 remains reference-only. A bounded SQLite
history store, optional API-key middleware (`SENTINEL_API_KEY`), and FastAPI
lifespan shutdown are included. The AI Insights page displays metadata
operating points, limitations, and saved calibration results.

Frontend tests passed: 7/7. The production build passed and emitted split
JavaScript chunks of about 306 KB and 368 KB. The focused Python run last had
22 passes, 10 subtests, and one expected-value precision failure; its assertion
was fixed but not rerun. The final full Python suite was interrupted to
conserve remaining usage and has no final result.

## Remaining work / limitations

- Phase B completed the timestamp-bound scan for the 11 original 01-12 source
  CSVs and saved `phase_b_scan_checkpoint.json`; the next vectorized count pass
  was interrupted before results. No B1/B2 evaluation or promotion comparison
  is complete. See `V31_WORK_STATUS.md` for resume instructions.
- Phase D model/API resource benchmark has not run yet.
- Phase E needs its final full test pass and a review of the submission archive
  builder. Phase F live traffic work is optional and has not been started.
- No calibrated severity cutoffs were fitted; severity remains explicitly
  provisional and uncalibrated.
