"""Measure process CPU and memory while the saved Random Forest V2 predicts.

Run from any directory with the project's virtual environment:
    python research/code/benchmark_v2_resource_usage.py

The benchmark uses rows from the canonical UDPLag CSV, leaves the saved model
and schema read-only, and writes a Markdown report under research/results/.
"""

import argparse
import ctypes
import hashlib
import os
import platform
import sys
import threading
import time
import winreg
from ctypes import wintypes
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


EXPECTED_MODEL_SHA256 = "61af42be7f2b079e4bf6fe8d766373cd1d2f91966b28e6bf722810de53f4d9d2"
EXPECTED_SCHEMA_SHA256 = "c49933abe8df5a693915bd788153bcb7302d75aab486a65e6b07e0a1abcc3e28"
MIB = 1024 * 1024


class MemoryStatusEx(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


class ProcessMemoryCountersEx(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
    ]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def windows_hardware():
    if sys.platform != "win32":
        raise RuntimeError("This focused resource benchmark requires Windows.")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MemoryStatusEx)]
    kernel32.GlobalMemoryStatusEx.restype = wintypes.BOOL
    memory_status = MemoryStatusEx()
    memory_status.dwLength = ctypes.sizeof(MemoryStatusEx)
    if not kernel32.GlobalMemoryStatusEx(ctypes.byref(memory_status)):
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
        ) as key:
            cpu_model = winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
    except OSError:
        cpu_model = platform.processor() or "Unavailable from Windows registry"

    return {
        "os": platform.platform(),
        "cpu_model": cpu_model,
        "logical_processors": os.cpu_count(),
        "total_physical_memory_bytes": int(memory_status.ullTotalPhys),
    }


def process_memory_counters():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    psapi.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(ProcessMemoryCountersEx),
        wintypes.DWORD,
    ]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

    counters = ProcessMemoryCountersEx()
    counters.cb = ctypes.sizeof(ProcessMemoryCountersEx)
    if not psapi.GetProcessMemoryInfo(
        kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    return {
        "working_set_bytes": int(counters.WorkingSetSize),
        "private_bytes": int(counters.PrivateUsage),
    }


def mib(value):
    return value / MIB


def sample_process_resources(stop_event, samples, errors, interval_seconds):
    while not stop_event.is_set():
        try:
            samples.append(process_memory_counters())
        except Exception as error:  # Propagate monitor failures to the caller.
            errors.append(error)
            stop_event.set()
            return
        stop_event.wait(interval_seconds)


def run_benchmark(sample_rows: int, warmups: int, repeats: int):
    root = Path(__file__).resolve().parents[2]
    model_path = root / "application" / "backend" / "real_model_v2.joblib"
    schema_path = root / "application" / "backend" / "real_model_features_v2.joblib"
    dataset_path = root / "application" / "dataset" / "01-12" / "UDPLag.csv"

    if not dataset_path.is_file():
        raise FileNotFoundError(f"Canonical input fixture not found: {dataset_path}")
    if sha256_file(model_path) != EXPECTED_MODEL_SHA256:
        raise RuntimeError("Saved model hash does not match the recorded original.")
    if sha256_file(schema_path) != EXPECTED_SCHEMA_SHA256:
        raise RuntimeError("Saved feature-schema hash does not match the recorded original.")

    hardware = windows_hardware()
    dataset_sha256 = sha256_file(dataset_path)
    feature_names = joblib.load(schema_path)
    if len(feature_names) != 82 or len(set(feature_names)) != 82:
        raise RuntimeError("Saved schema is not 82 unique feature names.")

    header = pd.read_csv(dataset_path, nrows=0, low_memory=False)
    header.columns = header.columns.str.strip()
    missing = [name for name in feature_names if name not in header.columns]
    if missing:
        raise RuntimeError(f"Fixture is missing model features: {missing}")

    selected = set(feature_names)
    raw = pd.read_csv(
        dataset_path,
        nrows=sample_rows,
        low_memory=False,
        usecols=lambda column: column.strip() in selected,
    )
    raw.columns = raw.columns.str.strip()
    X = raw.reindex(columns=feature_names).apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    if len(X) != sample_rows:
        raise RuntimeError(
            f"Requested {sample_rows} fixture rows, but read {len(X)}."
        )
    if X.isna().all(axis=1).any():
        raise RuntimeError("Fixture contains a row with no valid numeric features.")
    input_frame_bytes = int(X.memory_usage(index=True, deep=True).sum())
    del raw, header

    pipeline = joblib.load(model_path)
    if not hasattr(pipeline, "predict_proba"):
        raise RuntimeError("Saved V2 pipeline does not expose predict_proba.")

    warmup_X = X.iloc[: min(10_000, len(X))]
    for _ in range(warmups):
        pipeline.predict_proba(warmup_X)

    baseline_memory = process_memory_counters()
    stop_sampling = threading.Event()
    memory_samples = []
    sampler_errors = []
    sampler_interval_seconds = 0.01
    sampler = threading.Thread(
        target=sample_process_resources,
        args=(stop_sampling, memory_samples, sampler_errors, sampler_interval_seconds),
        name="windows-process-resource-sampler",
        daemon=True,
    )
    sampler.start()
    cpu_before = time.process_time()
    wall_before = time.perf_counter()
    output_rows = 0
    try:
        for _ in range(repeats):
            probabilities = pipeline.predict_proba(X)
            if probabilities.shape[0] != sample_rows:
                raise RuntimeError("V2 returned an unexpected prediction row count.")
            output_rows += probabilities.shape[0]
            del probabilities
    finally:
        stop_sampling.set()
        sampler.join(timeout=5)
    wall_seconds = time.perf_counter() - wall_before
    process_cpu_seconds = time.process_time() - cpu_before
    if sampler.is_alive():
        raise RuntimeError("Windows process-resource sampler did not stop cleanly.")
    if sampler_errors:
        raise RuntimeError(f"Windows process-resource sampling failed: {sampler_errors[0]}")
    memory_samples.append(process_memory_counters())
    peak_working_set_bytes = max(
        item["working_set_bytes"] for item in memory_samples
    )
    peak_private_bytes = max(item["private_bytes"] for item in memory_samples)

    model_after = sha256_file(model_path)
    schema_after = sha256_file(schema_path)
    if model_after != EXPECTED_MODEL_SHA256 or schema_after != EXPECTED_SCHEMA_SHA256:
        raise RuntimeError("Model or schema hash changed during the benchmark.")

    logical_processors = hardware["logical_processors"] or 1
    return {
        "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
        "root": root,
        "model_path": model_path,
        "schema_path": schema_path,
        "dataset_path": dataset_path,
        "model_sha256": model_after,
        "schema_sha256": schema_after,
        "dataset_sha256": dataset_sha256,
        "feature_count": len(feature_names),
        "unique_fixture_rows": sample_rows,
        "warmup_calls": warmups,
        "warmup_rows_per_call": len(warmup_X),
        "measured_calls": repeats,
        "measured_rows": output_rows,
        "wall_seconds": wall_seconds,
        "process_cpu_seconds": process_cpu_seconds,
        "cpu_one_logical_processor_percent": 100 * process_cpu_seconds / wall_seconds,
        "cpu_total_logical_capacity_percent": (
            100 * process_cpu_seconds / (wall_seconds * logical_processors)
        ),
        "throughput_rows_per_second": output_rows / wall_seconds,
        "hardware": hardware,
        "baseline_memory": baseline_memory,
        "peak_working_set_bytes": peak_working_set_bytes,
        "peak_private_bytes": peak_private_bytes,
        "peak_working_set_delta_bytes": max(
            0, peak_working_set_bytes - baseline_memory["working_set_bytes"]
        ),
        "peak_private_delta_bytes": max(
            0, peak_private_bytes - baseline_memory["private_bytes"]
        ),
        "memory_sample_count": len(memory_samples),
        "memory_sample_interval_ms": sampler_interval_seconds * 1_000,
        "input_frame_bytes": input_frame_bytes,
        "python": platform.python_version(),
        "numpy": np.__version__,
        "pandas": pd.__version__,
        "scikit_learn": __import__("sklearn").__version__,
        "joblib": joblib.__version__,
    }


def render_report(result):
    hw = result["hardware"]
    baseline = result["baseline_memory"]
    root = Path(result["root"]).resolve()

    def relative_path(key):
        return Path(result[key]).resolve().relative_to(root).as_posix()

    return f"""# Random Forest V2 inference CPU and memory benchmark

## Run details

- Run time: {result['timestamp']}
- Platform: {hw['os']}
- Processor: {hw['cpu_model']}
- Logical processors: {hw['logical_processors']}
- Installed physical memory: {mib(hw['total_physical_memory_bytes']):.0f} MiB
- Python: {result['python']}; NumPy: {result['numpy']}; pandas: {result['pandas']}; scikit-learn: {result['scikit_learn']}; joblib: {result['joblib']}
- Model: `{relative_path('model_path')}` (SHA-256 `{result['model_sha256']}`)
- Schema: `{relative_path('schema_path')}` (SHA-256 `{result['schema_sha256']}`)
- Input: `{relative_path('dataset_path')}` (SHA-256 `{result['dataset_sha256']}`)
- Ordered model features: {result['feature_count']}

## Method

Loaded the existing saved V2 pipeline and its ordered feature schema without writing either artifact. Read the first {result['unique_fixture_rows']:,} real rows from the existing UDPLag CSV fixture, selected the 82 schema columns in saved order, stripped header whitespace, converted columns to numeric values, and replaced infinities with missing values as in the existing CSV inference path. The pipeline's fitted preprocessing remains part of each inference call.

Ran {result['warmup_calls']} warm-up calls on {result['warmup_rows_per_call']:,} fixture rows each. After warm-up, ran {result['measured_calls']} measured calls on the same {result['unique_fixture_rows']:,} rows ({result['measured_rows']:,} total row predictions). CPU time is the Python process CPU-time delta; elapsed time is wall-clock time. CPU percentages are reported both as one logical processor capacity and as a fraction of the machine's {hw['logical_processors']} logical-processor capacity.

Memory was measured with Windows `GetProcessMemoryInfo` current working-set and private-commit counters. A monitor thread sampled them every {result['memory_sample_interval_ms']:.0f} ms during the measured calls ({result['memory_sample_count']} samples); baseline values were read after model/data loading and warm-up. The input feature frame occupies {mib(result['input_frame_bytes']):.2f} MiB. The benchmark does not include CSV read time, model load time, HTTP handling, or JSON serialization.

## Results

| Measure | Result |
|---|---:|
| Measured inference calls | {result['measured_calls']} |
| Predictions evaluated | {result['measured_rows']:,} |
| Inference wall time | {result['wall_seconds']:.3f} s |
| Process CPU time | {result['process_cpu_seconds']:.3f} s |
| Average process CPU, one logical processor = 100% | {result['cpu_one_logical_processor_percent']:.1f}% |
| Average process CPU, total logical capacity = 100% | {result['cpu_total_logical_capacity_percent']:.1f}% |
| Inference throughput | {result['throughput_rows_per_second']:,.0f} rows/s |
| Baseline process working set (post-warm-up) | {mib(baseline['working_set_bytes']):.2f} MiB |
| Peak sampled process working set during inference | {mib(result['peak_working_set_bytes']):.2f} MiB |
| Peak sampled working-set increase over baseline | {mib(result['peak_working_set_delta_bytes']):.2f} MiB |
| Baseline private commit (post-warm-up) | {mib(baseline['private_bytes']):.2f} MiB |
| Peak sampled private commit during inference | {mib(result['peak_private_bytes']):.2f} MiB |
| Peak sampled private-commit increase over baseline | {mib(result['peak_private_delta_bytes']):.2f} MiB |

## Limitations

- This is one controlled process-level run on one Windows machine. It is not a system-wide CPU utilization measurement and does not establish between-run variability.
- Windows current memory counters are sampled every 10 ms; shorter-lived peaks between samples may be missed. These process-level values do not attribute memory to individual pipeline stages.
- Repeatedly evaluating the same fixture rows estimates steady-state throughput and resource use, not performance on independent samples.
- The measured path is model-pipeline inference only. It excludes endpoint overhead and should not be reported as end-to-end API performance.
- The V2 feature-extraction provenance and live-packet feature parity remain unverified; this benchmark does not validate live inference or model generalization.
- Dataset labels were not used to calculate performance metrics in this resource benchmark.
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=100_000)
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--repeats", type=int, default=20)
    args = parser.parse_args()
    if args.samples <= 0 or args.warmups < 0 or args.repeats <= 0:
        parser.error("samples/repeats must be positive and warmups nonnegative")

    result = run_benchmark(args.samples, args.warmups, args.repeats)
    output_path = result["root"] / "research" / "results" / "inference_resource_benchmark.md"
    output_path.write_text(render_report(result), encoding="utf-8")
    print(f"Report written to {output_path}")
    print(
        f"CPU: {result['cpu_total_logical_capacity_percent']:.1f}% of total logical capacity; "
        f"peak working set: {mib(result['peak_working_set_bytes']):.2f} MiB; "
        f"peak private commit: {mib(result['peak_private_bytes']):.2f} MiB"
    )


if __name__ == "__main__":
    main()
