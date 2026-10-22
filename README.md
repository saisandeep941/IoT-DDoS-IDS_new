# Intelligent Machine Learning-Based Intrusion Detection System for DDoS Attacks in IoT Networks

This package contains the application, the saved Random Forest V2 model and its 82-feature schema, and the canonical completed research evaluation. Research-only baseline models are not substituted for the deployed V2 model.

## Package layout

- `application/` — FastAPI backend, React frontend, dependency manifests, and focused regression tests.
- `model/` — authoritative copies of the deployed V2 model and feature schema. Identical runtime copies are beside the backend because the existing model loader resolves them relative to `backend/main.py`.
- `research/results/` — canonical evaluation tables, confidence intervals, figures, SHAP artifacts, report, the CPU/memory benchmark, sanitized provenance metadata, and sanitized COMPLETE run manifest.
- `research/code/` — evaluator, protocol helpers, CPU/memory benchmark, deterministic submission builder, and research regression tests.
- `docs/` — evaluation documentation and this package manifest.

## CSV traffic replay demonstration

In **Threat Detection**, choose a CSV containing the frozen model's 82 feature
columns in the exact saved order, then start **CSV Traffic Replay Simulation**.
Optional non-feature columns such as `Label` and `Timestamp` may accompany the
ordered features. Replay advances in small, configurable batches and supports
pause, resume, stop, and clearing replay records. Model predictions are
recorded in dashboard history; supplied labels are displayed only as
ground-truth context and are never prediction inputs. Rows pass through the
frozen V2 pipeline's existing preprocessing. Per-record SHAP contributions are
shown when available; otherwise the dashboard states why they are unavailable.

This replays stored CSV records and is not live network inference. Passing the
feature-name/order check does not prove semantic feature-generation parity or
independent-dataset validity. Live packet capture remains observational.

The **AI Insights** page also displays the saved same-source research
evaluation: matched research-only refits and the frozen V2 reference are
separated and labeled. It includes saved confusion matrices, ROC-AUC,
confidence intervals, and model-only efficiency with the split protocol and
known limitations. The V2 row is reference-only; it is not independent
validation. These values are read from the existing research result files.

## Prerequisites

- Windows 10/11 or a compatible Python/Node environment.
- Python 3.14 and pip; backend dependencies are listed in `application/requirements.txt`.
- Node.js and npm; frontend versions are locked in `application/frontend/package-lock.json`.

## Run the backend

From the package root:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r application\requirements.txt
Set-Location application
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

The app's CORS configuration allows the Vite development origin at `http://localhost:5173`.

## Run the frontend

In a second terminal from the package root:

```powershell
Set-Location application\frontend
npm ci
npm run dev
```

Open the local URL printed by Vite (normally `http://localhost:5173`).

## Rebuild the submission archive

From the package root, regenerate and verify the curated ZIP with deterministic file ordering and timestamps:

```powershell
python research\code\build_submission.py
```

The builder uses an explicit file allowlist, excludes datasets and generated or local-only files, verifies the protected model/schema hashes, and checks archived contents.

## Focused regression checks

From the package root, run the complete backend and research regression suites. The temporary directory is kept under the package root so the tests do not rely on the machine's protected system temp directory:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location).Path 'application')
$env:TEMP = (Join-Path (Get-Location).Path '.test-tmp')
$env:TMP = $env:TEMP
New-Item -ItemType Directory -Path $env:TEMP -Force | Out-Null
.\.venv\Scripts\python.exe -m pytest application\ml research\code -q
```

Run the frontend tests and production build from `application/frontend`:

```powershell
Set-Location application\frontend
npm test
npm run build
```

To check a CSV header against the frozen schema without loading the data rows, run from the package root:

```powershell
.\.venv\Scripts\python.exe research\code\validate_dataset.py path\to\candidate.csv
```

This only confirms that all 82 feature names appear once and in saved-schema order. It does not establish feature-definition parity, label validity, provenance, or data independence.

## Limitations

- Capture/session independence has not been established for the research evaluation.
- The deployed V2 result is a reference score, not an independent time-block evaluation.
- Original V2 provenance remains incomplete: the exact training-row identities and original extractor version/settings are not recorded in the available project artifacts. The generation definitions for `SimillarHTTP`, `Inbound`, `CWE Flag Count`, and `Fwd Header Length.1` remain unresolved; this prevents establishing live-to-V2 feature parity.
- Matched-baseline recall at threshold 0.5 is about 13.3%; probability calibration was not evaluated.
- End-to-end API latency was not measured.
- Live V2 inference and automatic attack blocking are not implemented; live capture is optional metadata telemetry only.
- Source datasets are intentionally excluded. Dataset preview and the application's SHAP explanation endpoint expect source dataset files; those functions require the dataset separately. Canonical research SHAP outputs are included under `research/results/`.
- No compatible independent dataset has been established. `UDPLag.csv` has already been used for evaluation and threshold comparisons. `SimillarHTTP`, `Inbound`, `CWE Flag Count`, and `Fwd Header Length.1` still lack verified generation definitions and extraction provenance for cross-dataset parity. The V2 result on UDPLag is descriptive, not independent evidence.
- Research metrics describe the documented UDPLag evaluation and matched baselines, not independent-test or end-to-end API results. Probability calibration was not evaluated; risk/severity thresholds remain provisional.


## Live capture telemetry prototype

Live capture is an optional, separate metadata telemetry prototype. It does not call Random Forest V2, change the 82-feature schema, contribute to detection history or dashboard prediction totals, or affect CSV traffic replay. The telemetry is observational and is not an attack prediction.

Install its optional dependency only if you choose to enable capture: python -m pip install -r application/capture-requirements.txt. This is a separate opt-in step; the core application does not require Scapy or Npcap.

On Windows, install a current Npcap driver using its official installer before capture. Capturing generally requires an elevated process or the Npcap service configured with suitable access. Select an interface reported by the application; arbitrary interface names are rejected. The backend command above binds to IPv4 loopback only, and the capture API additionally checks loopback client/host, the Vite browser origin, and a per-process request token. Keep the frontend on http://localhost:5173; do not expose the backend through a LAN bind, reverse proxy, or port forward.

The worker keeps packet objects transiently while Scapy parses them, but does not store packet payloads or write capture files. Only bounded metadata history is returned from memory. Automated tests exercise mocked packets; a manual Windows capture verification is described in prior project notes but was not repeated during this completion pass. Packet capture remains observational telemetry and does not demonstrate live packet-to-feature-to-model inference.
