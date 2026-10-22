"""Create deterministic, time-aware samples from CIC-DDoS2019 CSV files.

Usage: python make_small_samples.py <input_folder> <output_folder>
"""
import glob
import os
import sys

import pandas as pd

CHUNK_SIZE = 200_000
CAP = 400


def process_file(path, output_folder):
    print(f"Starting {os.path.basename(path)}", flush=True)
    seen = {}
    parts = []
    chunk_number = 0
    for chunk in pd.read_csv(path, chunksize=CHUNK_SIZE, low_memory=False):
        chunk_number += 1
        chunk.columns = [str(column).strip() for column in chunk.columns]
        if "Timestamp" not in chunk.columns or "Label" not in chunk.columns:
            raise ValueError("CSV must contain Timestamp and Label columns")
        minute = pd.to_datetime(chunk["Timestamp"], errors="coerce").dt.floor("min").astype(str)
        chunk["_sample_minute"] = minute
        keep = []
        for key, group in chunk.groupby(["Label", "_sample_minute"], sort=False, dropna=False):
            label = str(key[0]).strip()
            if label.upper() == "BENIGN":
                keep.append(group)
                continue
            room = CAP - seen.get(key, 0)
            if room > 0:
                selected = group.sample(n=min(room, len(group)), random_state=42)
                seen[key] = seen.get(key, 0) + len(selected)
                keep.append(selected)
        if keep:
            parts.append(pd.concat(keep, ignore_index=True))
        print(f"  {os.path.basename(path)}: read chunk {chunk_number} ({chunk_number * CHUNK_SIZE:,} rows max)", flush=True)

    if not parts:
        raise ValueError("CSV produced no rows")
    result = pd.concat(parts, ignore_index=True)
    result.drop(columns=["_sample_minute"], inplace=True)
    result.sort_values("Timestamp", inplace=True, kind="mergesort")
    output_path = os.path.join(output_folder, os.path.splitext(os.path.basename(path))[0] + "_sample.csv")
    result.to_csv(output_path, index=False)
    print(f"Finished {os.path.basename(path)}: {len(result):,} rows -> {output_path}", flush=True)
    return len(result)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("Usage: python make_small_samples.py <input_folder> <output_folder>")
    input_folder, output_folder = sys.argv[1:]
    os.makedirs(output_folder, exist_ok=True)
    files = sorted(glob.glob(os.path.join(input_folder, "*.csv")))
    if not files:
        raise SystemExit(f"No CSV files found in {input_folder}")
    failures = []
    for path in files:
        try:
            process_file(path, output_folder)
        except Exception as exc:
            failures.append((path, exc))
            print(f"FAILED {path}: {type(exc).__name__}: {exc}", flush=True)
    if failures:
        print(f"Completed with {len(failures)} failed file(s).", flush=True)
        for path, exc in failures:
            print(f"FAILURE SUMMARY: {path}: {type(exc).__name__}: {exc}", flush=True)


if __name__ == "__main__":
    main()
