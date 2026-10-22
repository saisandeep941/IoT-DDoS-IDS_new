# Random Forest V2 inference CPU and memory benchmark

## Run details

- Run time: 2026-10-20T22:43:19+05:30
- Platform: Windows-11-10.0.26300-SP0
- Processor: 12th Gen Intel(R) Core(TM) i5-12500H
- Logical processors: 16
- Installed physical memory: 16069 MiB
- Python: 3.14.6; NumPy: 2.5.4; pandas: 3.0.6; scikit-learn: 1.9.1; joblib: 1.6.0
- Model: `application/backend/real_model_v2.joblib` (SHA-256 `61af42be7f2b079e4bf6fe8d766373cd1d2f91966b28e6bf722810de53f4d9d2`)
- Schema: `application/backend/real_model_features_v2.joblib` (SHA-256 `c49933abe8df5a693915bd788153bcb7302d75aab486a65e6b07e0a1abcc3e28`)
- Input: `application/dataset/01-12/UDPLag.csv` (SHA-256 `f67708a8462509932759ffed7eb92dca0f423267609d1be38a461708d4ea5b7e`)
- Ordered model features: 82

## Method

Loaded the existing saved V2 pipeline and its ordered feature schema without writing either artifact. Read the first 100,000 real rows from the existing UDPLag CSV fixture, selected the 82 schema columns in saved order, stripped header whitespace, converted columns to numeric values, and replaced infinities with missing values as in the existing CSV inference path. The pipeline's fitted preprocessing remains part of each inference call.

Ran 3 warm-up calls on 10,000 fixture rows each. After warm-up, ran 20 measured calls on the same 100,000 rows (2,000,000 total row predictions). CPU time is the Python process CPU-time delta; elapsed time is wall-clock time. CPU percentages are reported both as one logical processor capacity and as a fraction of the machine's 16 logical-processor capacity.

Memory was measured with Windows `GetProcessMemoryInfo` current working-set and private-commit counters. A monitor thread sampled them every 10 ms during the measured calls (203 samples); baseline values were read after model/data loading and warm-up. The input feature frame occupies 62.56 MiB. The benchmark does not include CSV read time, model load time, HTTP handling, or JSON serialization.

## Results

| Measure | Result |
|---|---:|
| Measured inference calls | 20 |
| Predictions evaluated | 2,000,000 |
| Inference wall time | 3.584 s |
| Process CPU time | 9.891 s |
| Average process CPU, one logical processor = 100% | 276.0% |
| Average process CPU, total logical capacity = 100% | 17.2% |
| Inference throughput | 558,034 rows/s |
| Baseline process working set (post-warm-up) | 223.67 MiB |
| Peak sampled process working set during inference | 347.44 MiB |
| Peak sampled working-set increase over baseline | 123.77 MiB |
| Baseline private commit (post-warm-up) | 1157.16 MiB |
| Peak sampled private commit during inference | 1285.50 MiB |
| Peak sampled private-commit increase over baseline | 128.34 MiB |

## Limitations

- This is one controlled process-level run on one Windows machine. It is not a system-wide CPU utilization measurement and does not establish between-run variability.
- Windows current memory counters are sampled every 10 ms; shorter-lived peaks between samples may be missed. These process-level values do not attribute memory to individual pipeline stages.
- Repeatedly evaluating the same fixture rows estimates steady-state throughput and resource use, not performance on independent samples.
- The measured path is model-pipeline inference only. It excludes endpoint overhead and should not be reported as end-to-end API performance.
- The V2 feature-extraction provenance and live-packet feature parity remain unverified; this benchmark does not validate live inference or model generalization.
- Dataset labels were not used to calculate performance metrics in this resource benchmark.
