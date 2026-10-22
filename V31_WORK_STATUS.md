# V3.1 Work Handoff

Updated: 2026-10-22 (Asia/Calcutta)
Project: `C:\Users\bonus\Desktop\IoT-DDoS-IDS-Working`

## User constraints

- Do not modify or delete `model/`, `model_v3/`, or any file under `research/results/`.
- New research artifacts belong under `research/results_v31/`; no data is uploaded.
- Keep the run efficient. Phase B is the long full-source scan; do not restart it unless needed.

## Completed

- Phase A: `research/results_v31/phase_a_evaluate_v3.py` processed the frozen V3 model against full 03-11 UDPLag and a selected CIC-IDS2017 Friday set in chunks. Raw results: `phase_a_raw.json`, `phase_a_stdout.txt`. The external CIC-IDS2017 scores are poor; do not describe this as generalization success.
- Phase C: `phase_c_calibrate.py` fit isotonic calibration on first time half of 03-11 UDPLag and evaluated the second half plus CIC-IDS2017 Friday. Results are in `phase_c_calibration.json`, mapping in `isotonic_calibrator.json`. Calibration worsened 03-11 Brier/ECE (0.0603→0.0627; 0.0696→0.0711) and improved but remained poor on CIC Friday (0.4182→0.3855; 0.4205→0.3724).
- Phase A commit exists: `8664794 Record frozen V3 full data evaluation`.
- Frontend `npm test` passes (7 tests). `npm run build` passes; chunks split to ~306 KB and ~368 KB.
- V3 backend already loads the native V3 export via `model_v3/v3_loader.py`; no V3 joblib is used. XGBoost dependency is pinned in `application/requirements.txt`.
- E changes in progress: SQLite bounded history, configurable `SENTINEL_API_KEY` on non-health routes, app lifespan cleanup, `.gitignore` for SQLite runtime data. README API-key/history notes were added previously.

## In progress / latest state

- Phase B training script: `research/results_v31/phase_b_train.py`.
- Inputs are `C:\Users\bonus\Desktop\IoT-DDoS-IDS\dataset\01-12\` (DrDoS_DNS, DrDoS_LDAP, DrDoS_MSSQL, DrDoS_NetBIOS, DrDoS_NTP, DrDoS_SNMP, DrDoS_SSDP, DrDoS_UDP, Syn, TFTP, UDPLag). The scan checkpoint stores timestamp bounds and source fingerprints for all 11; it does not copy or alter source data.
- The first 250,000-row scan completed all 11 sources; its timestamp bounds are saved in `phase_b_scan_checkpoint.json` with size/mtime fingerprints. That run was stopped before slow Python-per-row counting completed.
- Phase B scan session `95338` was stopped at the user's request to conserve usage. It had reused the timestamp checkpoint and entered vectorized group counting. No group-count summary, training sample, B1/B2 model, or Phase B metrics were produced. Resume by rerunning `research/results_v31/phase_b_train.py`; it will reuse the source-fingerprinted timestamp checkpoint if unchanged.
- An earlier slower run was stopped after a partial third pass; it produced no training outputs.
- API risk outputs now apply the saved isotonic mapping to risk scores while keeping raw V3 probabilities for balanced/strict label decisions (metadata operating thresholds were measured on raw output). `/api/model/status` includes calibration evaluation.
- `application/frontend/src/App.jsx`, `application/backend/main.py`, `README.md`, `docs/research_evaluation.md`, and risk/replay tests have been edited in this turn. Focused tests last reported 22 passed, 10 subtests, 1 failure due to test expected-value precision; that assertion has now been corrected but not rerun. The full Python suite session `58213` was interrupted to conserve usage after partial progress; there is no final test result.
- `research/code/benchmark_v3_resources.py` defaults to 100 repetitions and includes a Windows job-object memory-cap attempt. Phase D has not been run.

## Remaining work

1. Resume Phase B if usage permits. It still needs vectorized per-label/minute counts, sampled/purged data, B1 and B2 training/evaluation, and promotion comparison. Current script does not yet evaluate B1/B2 or compare promotion criteria.
2. Finish E: verify history/auth changes; keep the builder manifest/archive changes coherent and include only approved outputs. Do not touch protected folders.
3. Run the model/API resource benchmark once with 100 repeats (Phase D), if time permits.
4. Run one final Python suite: set `PYTHONPATH=application`, `TEMP`/`TMP` to `$PWD\.test-tmp`, then `.venv\Scripts\python.exe -m pytest application\ml research\code -q --tb=short`; run frontend tests/build only if needed (they passed after current UI edit).
5. Create `docs/final_v31_report.md` with evidence-backed results, explicit limitations/incomplete phases, changed files, and exact test outputs. Add any compact report metrics to the UI/docs only from saved result artifacts.
6. Review `git status`, verify protected `model/`, `model_v3/`, and `research/results/` stayed untouched, and commit phase changes if feasible. Explicit user authorization for commits was previously given; Git mutations may require sandbox approval.

## Important cautions

- No Phase B promotion decision exists yet. Phase A clearly shows a strong failure on the selected CIC-IDS2017 set.
- Do not create a promoted `model_v3_1` artifact unless the stated promotion criterion is met on both test sets.
- Phase F live packet work was optional and should be skipped unless all earlier phases finish and time remains.
