"""Data preparation, provenance, uncertainty, and timing helpers for research runs."""

from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import pickle
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Iterable
from urllib.request import Request, urlopen

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score


META_COLUMNS = [
    "Label", "Source IP", "Source Port", "Destination IP", "Destination Port",
    "Protocol", "Timestamp",
]
NANOSECONDS_PER_SECOND = 1_000_000_000
TIMESTAMP_GAP_NS = 60 * NANOSECONDS_PER_SECOND
BOOTSTRAP_METRICS = ("accuracy", "precision", "recall", "f1", "roc_auc", "average_precision")


class HashingReader:
    """Sequential binary reader that hashes the exact bytes consumed by pandas."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._raw = self.path.open("rb")
        self._digest = hashlib.sha256()
        self._position = 0
        self._valid = True

    def read(self, size: int = -1) -> bytes:
        data = self._raw.read(size)
        if data:
            position = self._raw.tell() - len(data)
            if position != self._position:
                self._valid = False
            self._digest.update(data)
            self._position = position + len(data)
        return data

    def readinto(self, buffer) -> int:
        data = self._raw.read(len(buffer))
        if not data:
            return 0
        position = self._raw.tell() - len(data)
        if position != self._position:
            self._valid = False
        self._digest.update(data)
        self._position = position + len(data)
        buffer[: len(data)] = data
        return len(data)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        old_position = self._raw.tell()
        position = self._raw.seek(offset, whence)
        if position != old_position:
            if position == 0:
                self._digest = hashlib.sha256()
                self._position = 0
                self._valid = True
            else:
                self._valid = False
                self._position = position
        return position

    def tell(self) -> int:
        return self._raw.tell()

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def fileno(self) -> int:
        return self._raw.fileno()

    def hexdigest(self) -> str:
        if not self._valid or self._position != self.path.stat().st_size:
            raise RuntimeError(f"Could not hash {self.path.name} in one sequential read")
        return self._digest.hexdigest()

    def close(self) -> None:
        self._raw.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


def sha256_file(path: Path, block_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        while block := source.read(block_size):
            digest.update(block)
    return digest.hexdigest()


def file_fingerprint(path: Path) -> dict[str, int | str]:
    """Cheap resume guard; the full SHA-256 is still captured during parsing."""
    path = Path(path).resolve()
    stat = path.stat()
    return {"path": str(path), "size_bytes": stat.st_size, "mtime_ns": stat.st_mtime_ns}


def atomic_pickle_checkpoint(path: Path, payload, context: dict) -> None:
    """Write a local checkpoint atomically so interrupted writes are never reused."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            pickle.dump({"context": context, "payload": payload}, stream, protocol=pickle.HIGHEST_PROTOCOL)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def load_pickle_checkpoint(path: Path, context: dict):
    with Path(path).open("rb") as stream:
        checkpoint = pickle.load(stream)
    if checkpoint.get("context") != context:
        raise ValueError(f"Checkpoint is incompatible with current inputs/configuration: {path.name}")
    return checkpoint["payload"]


def load_or_create_checkpoint(path: Path, context: dict, producer):
    """Reuse a complete checkpoint or compute and atomically persist the stage."""
    path = Path(path)
    if path.exists():
        return load_pickle_checkpoint(path, context), True
    payload = producer()
    atomic_pickle_checkpoint(path, payload, context)
    return payload, False


class RunManifest:
    """Small durable state record; final status is set only after output checks."""

    VALID_STATES = {"IN_PROGRESS", "FAILED", "COMPLETE"}

    def __init__(self, run_dir: Path, data: dict):
        self.run_dir = Path(run_dir)
        self.path = self.run_dir / "run_manifest.json"
        self.data = data

    @classmethod
    def start(cls, run_dir: Path, context: dict, resume: bool = False):
        run_dir = Path(run_dir)
        manifest_path = run_dir / "run_manifest.json"
        if resume:
            if not manifest_path.is_file():
                raise FileNotFoundError("Cannot resume: run_manifest.json is missing")
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            if data.get("state") not in cls.VALID_STATES:
                raise ValueError("Cannot resume: run manifest has an unknown state")
            if data.get("state") == "COMPLETE":
                raise ValueError("Cannot resume a completed run")
            if data.get("context") != context:
                raise ValueError("Run is incompatible with current inputs/configuration; use a new output directory")
            data["state"] = "IN_PROGRESS"
            data["resumed_utc"] = datetime.now(timezone.utc).isoformat()
            data.pop("failure", None)
            instance = cls(run_dir, data)
            instance.save()
            return instance
        if run_dir.exists() and any(run_dir.iterdir()):
            raise FileExistsError(f"Refusing to use non-empty run directory: {run_dir}")
        run_dir.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc).isoformat()
        instance = cls(run_dir, {
            "state": "IN_PROGRESS", "created_utc": now, "updated_utc": now,
            "context": context, "completed_stages": {},
        })
        instance.save()
        return instance

    def save(self) -> None:
        self.data["updated_utc"] = datetime.now(timezone.utc).isoformat()
        self.run_dir.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix="run_manifest.", suffix=".tmp", dir=self.run_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(self.data, stream, indent=2, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        except BaseException:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise

    def stage_complete(self, name: str) -> bool:
        return bool(self.data.get("completed_stages", {}).get(name))

    def mark_stage_complete(self, name: str, checkpoint: str) -> None:
        self.data.setdefault("completed_stages", {})[name] = {
            "checkpoint": checkpoint, "completed_utc": datetime.now(timezone.utc).isoformat()
        }
        self.save()

    def mark_failed(self, error: BaseException) -> None:
        self.data["state"] = "FAILED"
        self.data["failure"] = {"type": type(error).__name__, "message": str(error)}
        self.save()

    def mark_complete(self, staging_dir: Path, final_dir: Path, required_files: Iterable[str]) -> None:
        staging_dir, final_dir = Path(staging_dir), Path(final_dir)
        verify_dir = final_dir if final_dir.exists() else staging_dir
        missing = [name for name in required_files if not (verify_dir / name).is_file() or (verify_dir / name).stat().st_size == 0]
        if missing:
            raise RuntimeError(f"Cannot complete run; required outputs missing/empty: {missing}")
        if not final_dir.exists():
            os.replace(staging_dir, final_dir)
        self.data["results_directory"] = str(final_dir.name)
        self.data["verified_outputs"] = list(required_files)
        self.data["state"] = "COMPLETE"
        self.data.pop("failure", None)
        self.save()


def read_csv_header(path: Path) -> list[str]:
    return list(pd.read_csv(path, nrows=0, low_memory=False).columns)


def normalized_column_map(columns: Iterable[str]) -> dict[str, str]:
    return {str(column).strip(): str(column) for column in columns}


def parse_timestamp_ns(values: pd.Series) -> tuple[np.ndarray, np.ndarray]:
    """Parse ISO timestamp strings and normalize inferred pandas units to ns."""
    parsed = pd.to_datetime(
        values.astype("string").str.strip(), format="ISO8601", utc=True, errors="coerce"
    )
    valid = ~parsed.isna().to_numpy()
    # Pandas preserves subsecond source precision (often datetime64[us]); make the
    # integer unit explicit before treating the values as Unix nanoseconds.
    epoch_ns = parsed.dt.as_unit("ns").astype("int64").to_numpy(dtype=np.int64, copy=False)
    return epoch_ns, valid


def canonical_tuple_keys(frame: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """Return direction-independent IP/port/protocol keys and row-validity flags."""
    src_ip = frame["Source IP"].astype("string").str.strip()
    dst_ip = frame["Destination IP"].astype("string").str.strip()
    src_port = frame["Source Port"].astype("string").str.strip()
    dst_port = frame["Destination Port"].astype("string").str.strip()
    protocol = frame["Protocol"].astype("string").str.strip()
    valid = (
        src_ip.notna() & dst_ip.notna() & src_port.notna() & dst_port.notna()
        & protocol.notna() & src_ip.ne("") & dst_ip.ne("") & src_port.ne("")
        & dst_port.ne("") & protocol.ne("")
    ).to_numpy()
    forward = ((src_ip < dst_ip) | ((src_ip == dst_ip) & (src_port <= dst_port))).fillna(False)
    left_ip = src_ip.where(forward, dst_ip).fillna("")
    right_ip = dst_ip.where(forward, src_ip).fillna("")
    left_port = src_port.where(forward, dst_port).fillna("")
    right_port = dst_port.where(forward, src_port).fillna("")
    key = (left_ip + "|" + left_port + "|" + right_ip + "|" + right_port + "|" + protocol.fillna("")).to_numpy(dtype=object)
    return key, valid


def compact_tuple_ids(tuple_keys: np.ndarray) -> np.ndarray:
    """Encode canonical tuple keys as fixed-size SHA-256 IDs for disk storage."""
    keys = np.asarray(tuple_keys, dtype=object)
    encoded = np.empty(len(keys), dtype="S64")
    for index, key in enumerate(keys):
        encoded[index] = hashlib.sha256(str(key).encode("utf-8")).hexdigest().encode("ascii")
    return encoded


def training_split_mask(
    timestamps_ns: np.ndarray,
    tuple_keys: np.ndarray,
    tuple_valid: np.ndarray,
    test_tuple_keys: set[str],
    test_start_ns: int,
    gap_seconds: int = 60,
) -> tuple[np.ndarray, dict[str, int]]:
    """Keep only past rows beyond the gap and purge every tuple used by test."""
    timestamps_ns = np.asarray(timestamps_ns, dtype=np.int64)
    before_gap = (timestamps_ns != np.iinfo(np.int64).min) & (
        timestamps_ns < (int(test_start_ns) - gap_seconds * NANOSECONDS_PER_SECOND)
    )
    grouped = np.asarray(tuple_valid, dtype=bool)
    # Vectorized membership matters here: the original source files contain
    # nearly 50 million training rows.
    in_test_groups = pd.Index(tuple_keys).isin(test_tuple_keys)
    eligible = before_gap & grouped & ~in_test_groups
    return eligible, {
        "rows_before_gap": int(before_gap.sum()),
        "rows_after_gap_and_group_purge": int(eligible.sum()),
        "rows_removed_for_tuple_overlap": int((before_gap & grouped & in_test_groups).sum()),
        "rows_removed_for_invalid_tuple": int((before_gap & ~grouped).sum()),
    }


def _required_columns(path: Path, feature_names: list[str]) -> tuple[list[str], dict[str, str]]:
    raw_columns = read_csv_header(path)
    column_map = normalized_column_map(raw_columns)
    required = [*META_COLUMNS, *feature_names]
    missing = [name for name in required if name not in column_map]
    if missing:
        raise ValueError(f"{path.name} is missing required columns: {missing}")
    raw = [column_map[name] for name in required]
    return raw, column_map


def _binary_labels(values: pd.Series) -> tuple[np.ndarray, np.ndarray]:
    labels = values.astype("string").str.strip().str.upper()
    valid = labels.notna() & labels.ne("")
    y = labels.ne("BENIGN").astype(np.int8).to_numpy()
    return y, valid.to_numpy()


def load_full_holdout(path: Path, features: list[str], chunk_size: int = 50_000) -> dict:
    """Load all held-out feature rows and collect the hash in the same read."""
    raw_columns, _ = _required_columns(path, features)
    x_parts, y_parts, key_parts, time_parts = [], [], [], []
    counts = {0: 0, 1: 0}
    rows_read = invalid_times = invalid_keys = 0
    with HashingReader(path) as source:
        for chunk in pd.read_csv(source, usecols=raw_columns, chunksize=chunk_size, low_memory=False):
            chunk.columns = chunk.columns.str.strip()
            y, label_valid = _binary_labels(chunk["Label"])
            timestamp_ns, time_valid = parse_timestamp_ns(chunk["Timestamp"])
            tuple_keys, tuple_valid = canonical_tuple_keys(chunk)
            rows_read += len(chunk)
            invalid_times += int((~time_valid).sum())
            invalid_keys += int((~tuple_valid).sum())
            valid = label_valid & time_valid & tuple_valid
            if not valid.all():
                raise ValueError(f"{path.name} has rows without valid labels, timestamps, or tuple keys")
            for cls in (0, 1):
                counts[cls] += int((y == cls).sum())
            x = chunk.reindex(columns=features).apply(pd.to_numeric, errors="coerce")
            x = x.replace([np.inf, -np.inf], np.nan)
            x_parts.append(x.to_numpy(dtype=np.float64, copy=False))
            y_parts.append(y)
            key_parts.append(tuple_keys)
            time_parts.append(timestamp_ns)
        digest = source.hexdigest()
    return {
        "X": pd.DataFrame(np.concatenate(x_parts), columns=features),
        "y": np.concatenate(y_parts),
        "tuple_keys": np.concatenate(key_parts),
        "timestamps_ns": np.concatenate(time_parts),
        "counts": counts,
        "rows_read": rows_read,
        "invalid_timestamps": invalid_times,
        "invalid_tuple_keys": invalid_keys,
        "sha256": digest,
        "timestamp_start_ns": int(min(part.min() for part in time_parts)),
        "timestamp_end_ns": int(max(part.max() for part in time_parts)),
    }


def _checkpoint_manifest(path: Path, context: dict) -> dict:
    manifest_path = path / "checkpoint.json"
    if not manifest_path.is_file():
        raise ValueError(f"Disk checkpoint is incomplete: {path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("complete") is not True or manifest.get("context") != context:
        raise ValueError(f"Disk checkpoint is incompatible with current inputs/configuration: {path.name}")
    for name, expected_size in manifest.get("files", {}).items():
        target = path / name
        if not target.is_file() or target.stat().st_size != expected_size:
            raise ValueError(f"Disk checkpoint artifact is missing or truncated: {target.name}")
    return manifest


def _write_checkpoint_manifest(path: Path, manifest: dict) -> None:
    temporary = path / "checkpoint.json.tmp"
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(manifest, stream, indent=2, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path / "checkpoint.json")


def load_or_create_holdout_memmap(
    source_path: Path, features: list[str], chunk_size: int, checkpoint_path: Path, context: dict,
) -> tuple[dict, bool]:
    """Stream holdout columns into an atomically published, disk-backed checkpoint."""
    checkpoint_path = Path(checkpoint_path)
    if checkpoint_path.exists():
        manifest = _checkpoint_manifest(checkpoint_path, context)
        if manifest.get("format") != "holdout_memmap_v1" or int(manifest["feature_count"]) != len(features):
            raise ValueError(f"Disk checkpoint has an incompatible holdout schema: {checkpoint_path.name}")
        rows = int(manifest["rows"])
        feature_count = int(manifest["feature_count"])
        arrays = {
            "X": np.memmap(checkpoint_path / "X.float64", mode="r", dtype=np.float64, shape=(rows, feature_count)),
            "y": np.memmap(checkpoint_path / "y.int8", mode="r", dtype=np.int8, shape=(rows,)),
            "tuple_keys": np.memmap(checkpoint_path / "tuple_ids.sha256", mode="r", dtype="S64", shape=(rows,)),
            "timestamps_ns": np.memmap(checkpoint_path / "timestamps.int64", mode="r", dtype=np.int64, shape=(rows,)),
        }
        metadata = dict(manifest["metadata"])
        metadata["counts"] = {int(key): value for key, value in metadata["counts"].items()}
        result = {**metadata, **arrays}
        result["X"] = pd.DataFrame(result["X"], columns=features, copy=False)
        return result, True

    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=checkpoint_path.name + ".", suffix=".tmp", dir=checkpoint_path.parent))
    files = {"X.float64": 0, "y.int8": 0, "tuple_ids.sha256": 0, "timestamps.int64": 0}
    counts = {0: 0, 1: 0}
    rows_read = invalid_times = invalid_keys = rows = 0
    timestamp_start = timestamp_end = None
    try:
        raw_columns, _ = _required_columns(source_path, features)
        with (staging / "X.float64").open("wb") as x_out, \
             (staging / "y.int8").open("wb") as y_out, \
             (staging / "tuple_ids.sha256").open("wb") as tuple_out, \
             (staging / "timestamps.int64").open("wb") as time_out, \
             HashingReader(source_path) as source:
            for chunk in pd.read_csv(source, usecols=raw_columns, chunksize=chunk_size, low_memory=False):
                chunk.columns = chunk.columns.str.strip()
                y, label_valid = _binary_labels(chunk["Label"])
                timestamp_ns, time_valid = parse_timestamp_ns(chunk["Timestamp"])
                tuple_keys, tuple_valid = canonical_tuple_keys(chunk)
                valid = label_valid & time_valid & tuple_valid
                if not valid.all():
                    raise ValueError(f"{source_path.name} has rows without valid labels, timestamps, or tuple keys")
                x = chunk.reindex(columns=features).apply(pd.to_numeric, errors="coerce")
                x = x.replace([np.inf, -np.inf], np.nan).to_numpy(dtype=np.float64, copy=False)
                tuple_ids = compact_tuple_ids(tuple_keys)
                x.tofile(x_out); y.tofile(y_out); tuple_ids.tofile(tuple_out); timestamp_ns.tofile(time_out)
                rows_read += len(chunk)
                rows += len(chunk)
                invalid_times += int((~time_valid).sum())
                invalid_keys += int((~tuple_valid).sum())
                for cls in (0, 1):
                    counts[cls] += int((y == cls).sum())
                lo, hi = int(timestamp_ns.min()), int(timestamp_ns.max())
                timestamp_start = lo if timestamp_start is None else min(timestamp_start, lo)
                timestamp_end = hi if timestamp_end is None else max(timestamp_end, hi)
            for output in (x_out, y_out, tuple_out, time_out):
                output.flush()
                os.fsync(output.fileno())
        if not rows:
            raise ValueError(f"{source_path.name} contains no valid rows")
        for name in files:
            files[name] = (staging / name).stat().st_size
        metadata = {
            "counts": counts, "rows_read": rows_read,
            "invalid_timestamps": invalid_times, "invalid_tuple_keys": invalid_keys,
            "sha256": source.hexdigest(), "timestamp_start_ns": timestamp_start,
            "timestamp_end_ns": timestamp_end,
        }
        _write_checkpoint_manifest(staging, {
            "format": "holdout_memmap_v1", "complete": True, "context": context,
            "rows": rows, "feature_count": len(features), "metadata": metadata, "files": files,
        })
        os.replace(staging, checkpoint_path)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return load_or_create_holdout_memmap(source_path, features, chunk_size, checkpoint_path, context)[0], False


def load_or_create_probability_memmap(
    model, X: pd.DataFrame, checkpoint_path: Path, context: dict, chunk_rows: int = 8_192,
) -> np.memmap:
    """Predict in bounded row batches and atomically checkpoint positive probabilities."""
    checkpoint_path = Path(checkpoint_path)
    if checkpoint_path.exists():
        manifest = _checkpoint_manifest(checkpoint_path, context)
        if manifest.get("format") != "probability_memmap_v1" or int(manifest["rows"]) != len(X):
            raise ValueError(f"Probability checkpoint has an incompatible holdout shape: {checkpoint_path.name}")
        rows = int(manifest["rows"])
        return np.memmap(checkpoint_path / "probabilities.float64", mode="r", dtype=np.float64, shape=(rows,))
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=checkpoint_path.name + ".", suffix=".tmp", dir=checkpoint_path.parent))
    probability_path = staging / "probabilities.float64"
    try:
        classes = list(model.classes_)
        positive_index = classes.index(1)
        with probability_path.open("wb") as output:
            for start in range(0, len(X), chunk_rows):
                stop = min(start + chunk_rows, len(X))
                batch = X.iloc[start:stop]
                probabilities = model.predict_proba(batch)[:, positive_index]
                np.asarray(probabilities, dtype=np.float64).tofile(output)
                del probabilities, batch
            output.flush()
            os.fsync(output.fileno())
        _write_checkpoint_manifest(staging, {
            "format": "probability_memmap_v1", "complete": True, "context": context,
            "rows": len(X), "files": {probability_path.name: probability_path.stat().st_size},
        })
        os.replace(staging, checkpoint_path)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return np.memmap(checkpoint_path / "probabilities.float64", mode="r", dtype=np.float64, shape=(len(X),))


def _reservoir_update(samples, priorities, candidate_x, cls: int, cap: int, rng) -> None:
    if len(candidate_x) == 0:
        return
    new_priorities = rng.random(len(candidate_x))
    candidates_x = np.concatenate((samples[cls], candidate_x), axis=0)
    candidates_p = np.concatenate((priorities[cls], new_priorities))
    keep = min(cap, len(candidates_p))
    chosen = np.argpartition(candidates_p, -keep)[-keep:]
    samples[cls] = candidates_x[chosen]
    priorities[cls] = candidates_p[chosen]


def sample_purged_training(
    paths: list[Path],
    features: list[str],
    test_tuple_keys: set[str],
    test_start_ns: int,
    cap: int = 10_000,
    seed: int = 42,
    chunk_size: int = 50_000,
    gap_seconds: int = 60,
    checkpoint_path: Path | None = None,
    checkpoint_context: dict | None = None,
) -> dict:
    """Forward-time sampling; resume safely at completed source-file boundaries."""
    rng = np.random.default_rng(seed)
    samples = {0: np.empty((0, len(features))), 1: np.empty((0, len(features)))}
    priorities = {0: np.empty(0), 1: np.empty(0)}
    class_counts = {0: 0, 1: 0}
    files = {}
    totals = {
        "rows_scanned": 0, "rows_before_gap": 0, "rows_after_gap_and_group_purge": 0,
        "rows_removed_for_tuple_overlap": 0, "rows_removed_for_invalid_tuple": 0,
        "invalid_timestamps": 0, "invalid_tuple_keys": 0,
    }
    completed_files = []
    if checkpoint_path is not None and Path(checkpoint_path).exists():
        if checkpoint_context is None:
            raise ValueError("checkpoint_context is required when resuming training sampling")
        state = load_pickle_checkpoint(checkpoint_path, checkpoint_context)
        completed_files = state["completed_files"]
        names = [path.name for path in paths]
        if names[:len(completed_files)] != completed_files:
            raise ValueError("Training sampling checkpoint file order no longer matches current sources")
        samples, priorities = state["samples"], state["priorities"]
        class_counts, files, totals = state["class_counts"], state["files"], state["totals"]
        rng.bit_generator.state = state["rng_state"]
    for path in paths[len(completed_files):]:
        raw_columns, _ = _required_columns(path, features)
        file_rows = file_invalid_timestamps = file_invalid_keys = 0
        file_start = file_end = None
        with HashingReader(path) as source:
            for chunk in pd.read_csv(source, usecols=raw_columns, chunksize=chunk_size, low_memory=False):
                chunk.columns = chunk.columns.str.strip()
                y, label_valid = _binary_labels(chunk["Label"])
                timestamps_ns, time_valid = parse_timestamp_ns(chunk["Timestamp"])
                keys, tuple_valid = canonical_tuple_keys(chunk)
                tuple_ids = compact_tuple_ids(keys)
                file_rows += len(chunk)
                file_invalid_timestamps += int((~time_valid).sum())
                file_invalid_keys += int((~tuple_valid).sum())
                if not label_valid.all():
                    raise ValueError(f"{path.name} has missing/blank labels")
                valid_times = timestamps_ns[time_valid]
                if len(valid_times):
                    lo, hi = int(valid_times.min()), int(valid_times.max())
                    file_start = lo if file_start is None else min(file_start, lo)
                    file_end = hi if file_end is None else max(file_end, hi)
                mask, counts = training_split_mask(
                    timestamps_ns, tuple_ids, tuple_valid, test_tuple_keys, test_start_ns, gap_seconds
                )
                for name, value in counts.items():
                    totals[name] += value
                totals["rows_scanned"] += len(chunk)
                for cls in (0, 1):
                    selected = mask & (y == cls)
                    class_rows = chunk.loc[selected].reindex(columns=features).apply(pd.to_numeric, errors="coerce")
                    class_rows = class_rows.replace([np.inf, -np.inf], np.nan).to_numpy(dtype=np.float64, copy=False)
                    class_counts[cls] += len(class_rows)
                    _reservoir_update(samples, priorities, class_rows, cls, cap, rng)
            digest = source.hexdigest()
        totals["invalid_timestamps"] += file_invalid_timestamps
        totals["invalid_tuple_keys"] += file_invalid_keys
        files[path.name] = {
            "rows": file_rows, "invalid_timestamps": file_invalid_timestamps,
            "invalid_tuple_keys": file_invalid_keys,
            "start_utc": pd.Timestamp(file_start, unit="ns", tz="UTC").isoformat() if file_start is not None else None,
            "end_utc": pd.Timestamp(file_end, unit="ns", tz="UTC").isoformat() if file_end is not None else None,
            "sha256": digest,
        }
        completed_files.append(path.name)
        if checkpoint_path is not None:
            if checkpoint_context is None:
                raise ValueError("checkpoint_context is required when checkpointing training sampling")
            atomic_pickle_checkpoint(checkpoint_path, {
                "completed_files": completed_files, "samples": samples,
                "priorities": priorities, "class_counts": class_counts,
                "files": files, "totals": totals,
                "rng_state": rng.bit_generator.state,
            }, checkpoint_context)
        print(f"Training source checkpoint: {path.name} ({file_rows:,} rows)", flush=True)
    if totals["invalid_timestamps"] or totals["invalid_tuple_keys"]:
        raise ValueError("Training data contains invalid timestamps or tuple keys; a disjoint split cannot be verified")
    if not len(samples[0]) or not len(samples[1]):
        raise ValueError("The purged, past-only training rows must contain both BENIGN and attack classes")
    balanced_count = min(len(samples[0]), len(samples[1]))
    for cls in (0, 1):
        if len(samples[cls]) > balanced_count:
            chosen = rng.choice(len(samples[cls]), size=balanced_count, replace=False)
            samples[cls] = samples[cls][chosen]
    X = pd.DataFrame(np.concatenate((samples[0], samples[1])), columns=features)
    y = np.concatenate((np.zeros(len(samples[0]), dtype=np.int8), np.ones(len(samples[1]), dtype=np.int8)))
    order = np.random.default_rng(seed + 1).permutation(len(y))
    return {
        "X": X.iloc[order].reset_index(drop=True), "y": y[order],
        "source_class_counts": class_counts, "sampled_class_counts": {0: int((y == 0).sum()), 1: int((y == 1).sum())},
        "metadata": {**totals, "files": files, "gap_seconds": gap_seconds,
                     "test_start_ns": int(test_start_ns),
                     "training_cutoff_ns": int(test_start_ns) - gap_seconds * NANOSECONDS_PER_SECOND},
    }


def _weighted_metrics(y: np.ndarray, probability: np.ndarray, weights: np.ndarray, sorted_state: dict) -> dict[str, float]:
    prediction = probability >= 0.5
    positive = y == 1
    tp = int(np.sum(weights[positive & prediction])); fn = int(np.sum(weights[positive & ~prediction]))
    fp = int(np.sum(weights[~positive & prediction])); tn = int(np.sum(weights[~positive & ~prediction]))
    total = tn + fp + fn + tp
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / total if total else 0.0
    order = sorted_state["order"]
    y_sorted = y[order]
    w_sorted = weights[order].astype(np.float64, copy=False)
    starts = sorted_state["starts"]
    pos_by_score = np.add.reduceat(w_sorted * y_sorted, starts)
    neg_by_score = np.add.reduceat(w_sorted * (1 - y_sorted), starts)
    total_pos = float(pos_by_score.sum()); total_neg = float(neg_by_score.sum())
    if total_pos and total_neg:
        neg_before = np.cumsum(neg_by_score) - neg_by_score
        auc = float(np.sum(pos_by_score * (neg_before + 0.5 * neg_by_score)) / (total_pos * total_neg))
    else:
        auc = float("nan")
    pos_desc = pos_by_score[::-1]; neg_desc = neg_by_score[::-1]
    tp_desc = np.cumsum(pos_desc); all_desc = np.cumsum(pos_desc + neg_desc)
    ap = float(np.sum((pos_desc / total_pos) * (tp_desc / np.maximum(all_desc, 1)))) if total_pos else float("nan")
    return {"accuracy": accuracy, "precision": precision, "recall": recall, "f1": f1, "roc_auc": auc, "average_precision": ap}


def _score_sort_state(y: np.ndarray, probability: np.ndarray) -> dict:
    order = np.argsort(probability, kind="mergesort")
    ordered = probability[order]
    starts = np.r_[0, np.flatnonzero(ordered[1:] != ordered[:-1]) + 1]
    return {"order": order, "starts": starts}


def _intervals(replicates: dict[str, list[float]]) -> dict[str, dict[str, float]]:
    return {
        metric: {"lower_95": float(np.nanpercentile(values, 2.5)), "upper_95": float(np.nanpercentile(values, 97.5))}
        for metric, values in replicates.items() if len(values)
    }


def stratified_bootstrap_ci(
    y: np.ndarray, probability: np.ndarray, replicates: int = 500, seed: int = 42
) -> dict[str, dict[str, float]]:
    """Class-stratified row bootstrap; predictions are fixed across replicates."""
    y = np.asarray(y, dtype=np.int8); probability = np.asarray(probability, dtype=np.float64)
    class_rows = [np.flatnonzero(y == cls) for cls in (0, 1)]
    if not all(len(rows) for rows in class_rows):
        raise ValueError("Bootstrap confidence intervals require both classes")
    state = _score_sort_state(y, probability); rng = np.random.default_rng(seed)
    values = {metric: [] for metric in BOOTSTRAP_METRICS}
    weights = np.zeros(len(y), dtype=np.int32)
    for _ in range(replicates):
        weights.fill(0)
        for rows in class_rows:
            drawn = rng.integers(0, len(rows), size=len(rows))
            weights[rows] = np.bincount(drawn, minlength=len(rows))
        record = _weighted_metrics(y, probability, weights, state)
        for metric in BOOTSTRAP_METRICS:
            values[metric].append(record[metric])
    return _intervals(values)


def tuple_cluster_bootstrap_ci(
    y: np.ndarray, probability: np.ndarray, tuple_keys: np.ndarray,
    replicates: int = 250, seed: int = 43,
) -> dict[str, dict[str, float]]:
    """Tuple-cluster bootstrap, stratified by each tuple's observed label composition."""
    y = np.asarray(y, dtype=np.int8); probability = np.asarray(probability, dtype=np.float64)
    groups, inverse = np.unique(np.asarray(tuple_keys), return_inverse=True)
    group_count = len(groups)
    group_zero = np.bincount(inverse, weights=(y == 0), minlength=group_count)
    group_one = np.bincount(inverse, weights=(y == 1), minlength=group_count)
    composition = (group_zero > 0).astype(np.uint8) * 2 + (group_one > 0).astype(np.uint8)
    strata = [np.flatnonzero(composition == value) for value in (1, 2, 3) if np.any(composition == value)]
    state = _score_sort_state(y, probability); rng = np.random.default_rng(seed)
    values = {metric: [] for metric in BOOTSTRAP_METRICS}
    for _ in range(replicates):
        group_weights = np.zeros(group_count, dtype=np.int32)
        for group_ids in strata:
            chosen = rng.integers(0, len(group_ids), size=len(group_ids))
            group_weights += np.bincount(group_ids[chosen], minlength=group_count)
        row_weights = group_weights[inverse]
        record = _weighted_metrics(y, probability, row_weights, state)
        for metric in BOOTSTRAP_METRICS:
            values[metric].append(record[metric])
    return _intervals(values)


def package_versions() -> dict[str, str | None]:
    packages = ("numpy", "pandas", "scikit-learn", "joblib", "shap", "matplotlib")
    versions = {name: importlib_metadata.version(name) if _installed(name) else None for name in packages}
    versions["python"] = platform.python_version()
    return versions


def _installed(name: str) -> bool:
    try:
        importlib_metadata.version(name)
        return True
    except importlib_metadata.PackageNotFoundError:
        return False


def hardware_metadata() -> dict:
    info = {
        "platform": platform.platform(), "processor": platform.processor() or None,
        "logical_cpu_count": os.cpu_count(),
    }
    try:
        import psutil
        info["physical_memory_bytes"] = int(psutil.virtual_memory().total)
        info["physical_cpu_count"] = psutil.cpu_count(logical=False)
    except ImportError:
        info["physical_memory_bytes"] = None
        info["physical_cpu_count"] = None
    return info


def git_metadata(root: Path) -> dict:
    root = Path(root).resolve()

    def git(*args):
        command = ["git", *args]
        try:
            return subprocess.run(
                command, cwd=root, check=True, capture_output=True, text=True
            ).stdout.strip()
        except (OSError, subprocess.CalledProcessError) as error:
            detail = getattr(error, "stderr", None) or str(error)
            detail = detail.strip()
            raise RuntimeError(
                f"Could not verify Git metadata at {root}: `{' '.join(command)}` failed "
                f"({detail}). The working-tree state is unknown; restore Git worktree "
                "access and rerun the evaluation."
            ) from error

    actual_root = Path(git("rev-parse", "--show-toplevel")).resolve()
    inside_work_tree = git("rev-parse", "--is-inside-work-tree").lower() == "true"
    if (os.path.normcase(os.path.realpath(actual_root)) !=
            os.path.normcase(os.path.realpath(root)) or not inside_work_tree):
        raise RuntimeError(
            f"Git resolved {root} to repository root {actual_root} "
            f"(inside_work_tree={inside_work_tree}); refusing to record provenance "
            "because the requested repository context is not verified."
        )

    revision = git("rev-parse", "HEAD")
    branch = git("branch", "--show-current")
    status = git("status", "--porcelain")
    return {
        "revision": revision,
        "branch": branch,
        "working_tree_dirty": bool(status),
        "working_tree_status": status,
    }


def benchmark_model(
    model, X: pd.DataFrame, warmups: int = 20, latency_repeats: int = 500,
    batch_repeats: int = 3, prediction_chunk_rows: int = 8_192,
) -> dict:
    """Separate one-row latency from full-set repeated batch throughput."""
    one = X.iloc[[0]]
    for _ in range(warmups):
        model.predict_proba(one)
    latency_ms = []
    for _ in range(latency_repeats):
        started = time.perf_counter_ns(); model.predict_proba(one)
        latency_ms.append((time.perf_counter_ns() - started) / 1_000_000)
    batch_times = []
    model.predict_proba(X.iloc[: min(128, len(X))])
    for _ in range(batch_repeats):
        started = time.perf_counter_ns()
        for start in range(0, len(X), prediction_chunk_rows):
            model.predict_proba(X.iloc[start:min(start + prediction_chunk_rows, len(X))])
        batch_times.append((time.perf_counter_ns() - started) / 1_000_000_000)
    p50, p95, p99 = np.percentile(latency_ms, [50, 95, 99])
    batch_p50 = float(np.median(batch_times))
    return {
        "model_only_single_row_warmup_calls": warmups,
        "model_only_single_row_repetitions": latency_repeats,
        "model_only_single_row_p50_ms": float(p50),
        "model_only_single_row_p95_ms": float(p95),
        "model_only_single_row_p99_ms": float(p99),
        "full_test_batch_size": int(len(X)),
        "full_test_batch_repetitions": batch_repeats,
        "full_test_batch_median_seconds": batch_p50,
        "full_test_batch_throughput_rows_per_second": float(len(X) / max(batch_p50, 1e-12)),
        "latency_scope": "model.predict_proba on one-row DataFrame; excludes HTTP, parsing, and serialization",
        "throughput_scope": f"full held-out set in chunks of at most {prediction_chunk_rows} rows; batch throughput, not single-request latency",
    }


def benchmark_api_latency(
    endpoint: str, feature_values: list[float], warmups: int = 10, repeats: int = 100,
    timeout_seconds: float = 30.0,
) -> dict:
    """Measure loopback/HTTP API end-to-end latency separately from model timing."""
    payload = json.dumps({"features": feature_values}).encode("utf-8")
    request = Request(endpoint, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    def call():
        with urlopen(request, timeout=timeout_seconds) as response:
            response.read()
            if response.status != 200:
                raise RuntimeError(f"API returned HTTP {response.status}")
    for _ in range(warmups):
        call()
    times = []
    for _ in range(repeats):
        started = time.perf_counter_ns(); call()
        times.append((time.perf_counter_ns() - started) / 1_000_000)
    p50, p95, p99 = np.percentile(times, [50, 95, 99])
    return {
        "endpoint": endpoint, "warmup_requests": warmups, "measured_requests": repeats,
        "end_to_end_api_p50_ms": float(p50), "end_to_end_api_p95_ms": float(p95),
        "end_to_end_api_p99_ms": float(p99),
        "scope": "HTTP request and response on configured endpoint, including server parsing, artifact loading, prediction, and JSON response; transport is local only if endpoint is loopback",
    }
