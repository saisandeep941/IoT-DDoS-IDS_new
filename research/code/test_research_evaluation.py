import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import subprocess
from types import SimpleNamespace

import numpy as np
import pandas as pd

from evaluate_research import class_reservoir, metric_record, save_confusion_svg, write_result_tables
from research_eval_protocol import (
    NANOSECONDS_PER_SECOND,
    RunManifest,
    load_or_create_checkpoint,
    load_or_create_holdout_memmap,
    load_or_create_probability_memmap,
    canonical_tuple_keys,
    compact_tuple_ids,
    load_full_holdout,
    parse_timestamp_ns,
    stratified_bootstrap_ci,
    training_split_mask,
    tuple_cluster_bootstrap_ci,
    git_metadata,
)


class ResearchEvaluationTests(unittest.TestCase):
    def test_git_metadata_fails_clearly_when_status_cannot_be_verified(self):
        root = Path.cwd()

        def run_git(command, **kwargs):
            args = command[1:]
            if args == ["rev-parse", "--show-toplevel"]:
                return SimpleNamespace(stdout=str(root), stderr="")
            if args == ["rev-parse", "--is-inside-work-tree"]:
                return SimpleNamespace(stdout="true", stderr="")
            if args == ["rev-parse", "HEAD"]:
                return SimpleNamespace(stdout="abc123", stderr="")
            if args == ["branch", "--show-current"]:
                return SimpleNamespace(stdout="feature", stderr="")
            if args == ["status", "--porcelain"]:
                raise subprocess.CalledProcessError(
                    128, command, stderr="this operation must be run in a work tree"
                )
            self.fail(f"Unexpected Git command: {command}")

        with patch("research_eval_protocol.subprocess.run", side_effect=run_git):
            with self.assertRaisesRegex(
                RuntimeError,
                "working-tree state is unknown.*restore Git worktree access",
            ):
                git_metadata(root)

    def close_memmaps(self, *values):
        seen = set()
        pending = list(values)
        while pending:
            value = pending.pop()
            if value is None or id(value) in seen:
                continue
            seen.add(id(value))
            if isinstance(value, np.memmap):
                value._mmap.close()
            elif isinstance(value, pd.DataFrame):
                pending.append(value.to_numpy(copy=False))
            elif isinstance(value, np.ndarray):
                pending.append(value.base)

    def make_csv(self, folder: str) -> Path:
        path = Path(folder) / "tiny.csv"
        pd.DataFrame({
            "f1": [1, 2, 3, 4, 5, 6],
            "f2": [10, np.inf, 30, 40, np.nan, 60],
            "Label": ["BENIGN", "BENIGN", "BENIGN", "UDP-LAG", "UDP-LAG", "UDP-LAG"],
        }).to_csv(path, index=False)
        return path

    def test_class_reservoir_is_balanced_bounded_and_reproducible(self):
        with tempfile.TemporaryDirectory() as folder:
            path = self.make_csv(folder)
            x1, y1, counts1, rows1 = class_reservoir(path, ["f1", "f2"], 2, 7)
            x2, y2, counts2, rows2 = class_reservoir(path, ["f1", "f2"], 2, 7)
            self.assertEqual(len(x1), 4)
            self.assertEqual(np.bincount(y1).tolist(), [2, 2])
            self.assertEqual(counts1, {0: 3, 1: 3})
            self.assertEqual(rows1, 6)
            self.assertEqual(counts1, counts2)
            self.assertEqual(rows1, rows2)
            pd.testing.assert_frame_equal(x1, x2)
            np.testing.assert_array_equal(y1, y2)
            self.assertTrue(np.isinf(x1.to_numpy()).sum() == 0)

    def test_missing_feature_fails_clearly(self):
        with tempfile.TemporaryDirectory() as folder:
            path = self.make_csv(folder)
            with self.assertRaisesRegex(ValueError, "missing required columns"):
                class_reservoir(path, ["not_a_feature"], 2, 7)

    def test_reservoir_balances_when_minority_is_below_cap(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "imbalanced.csv"
            pd.DataFrame({
                "f1": [1, 2, 3, 4, 5, 6],
                "Label": ["BENIGN", "BENIGN", "UDP-LAG", "UDP-LAG", "UDP-LAG", "UDP-LAG"],
            }).to_csv(path, index=False)
            x, y, counts, rows = class_reservoir(path, ["f1"], 3, 11)
            self.assertEqual(counts, {0: 2, 1: 4})
            self.assertEqual(rows, 6)
            self.assertEqual(np.bincount(y).tolist(), [2, 2])
            self.assertEqual(len(x), 4)

    def test_metrics_and_confusion_svg(self):
        record = metric_record(
            "unit model",
            np.array([0, 0, 1, 1]),
            np.array([0, 1, 0, 1]),
            np.array([0.1, 0.8, 0.2, 0.9]),
        )
        self.assertEqual((record["tn"], record["fp"], record["fn"], record["tp"]), (1, 1, 1, 1))
        self.assertEqual(record["f1"], 0.5)
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "confusion.svg"
            save_confusion_svg(record, output)
            self.assertIn("Confusion matrix", output.read_text(encoding="utf-8"))

    def test_iso_timestamp_units_are_normalized_to_unix_nanoseconds(self):
        values = pd.Series(["2018-12-01 13:04:45.928673", "2018-12-01T13:04:45.928673Z"])
        timestamps, valid = parse_timestamp_ns(values)
        self.assertTrue(valid.all())
        self.assertEqual(timestamps[0], timestamps[1])
        self.assertEqual(pd.Timestamp(timestamps[0], unit="ns", tz="UTC").year, 2018)
        self.assertEqual(pd.Timestamp(timestamps[0], unit="ns", tz="UTC").microsecond, 928673)

    def test_canonical_tuple_is_direction_independent(self):
        flows = pd.DataFrame({
            "Source IP": ["10.0.0.1", "10.0.0.2"], "Source Port": ["123", "80"],
            "Destination IP": ["10.0.0.2", "10.0.0.1"], "Destination Port": ["80", "123"],
            "Protocol": ["17", "17"],
        })
        keys, valid = canonical_tuple_keys(flows)
        self.assertTrue(valid.all())
        self.assertEqual(keys[0], keys[1])

    def test_gap_and_tuple_purge_exclude_boundary_and_test_groups(self):
        start = 1_600_000_000 * NANOSECONDS_PER_SECOND
        times = np.array([start - 61 * NANOSECONDS_PER_SECOND,
                          start - 61 * NANOSECONDS_PER_SECOND,
                          start - 60 * NANOSECONDS_PER_SECOND,
                          np.iinfo(np.int64).min], dtype=np.int64)
        keys = np.array(["seen", "other", "other", "invalid"])
        valid = np.array([True, True, True, True])
        mask, counts = training_split_mask(times, keys, valid, {"seen"}, start, 60)
        np.testing.assert_array_equal(mask, [False, True, False, False])
        self.assertEqual(counts["rows_before_gap"], 2)
        self.assertEqual(counts["rows_removed_for_tuple_overlap"], 1)
        self.assertTrue(set(keys[mask]).isdisjoint({"seen"}))

    def test_bootstrap_intervals_repeat_for_fixed_seed(self):
        y = np.array([0, 0, 0, 1, 1, 1], dtype=np.int8)
        probabilities = np.array([0.1, 0.2, 0.4, 0.6, 0.8, 0.9])
        tuples = np.array(["a", "b", "c", "a", "d", "e"])
        row_one = stratified_bootstrap_ci(y, probabilities, replicates=20, seed=77)
        row_two = stratified_bootstrap_ci(y, probabilities, replicates=20, seed=77)
        cluster_one = tuple_cluster_bootstrap_ci(y, probabilities, tuples, replicates=20, seed=78)
        cluster_two = tuple_cluster_bootstrap_ci(y, probabilities, tuples, replicates=20, seed=78)
        self.assertEqual(row_one, row_two)
        self.assertEqual(cluster_one, cluster_two)
        self.assertIn("roc_auc", row_one)
        self.assertIn("average_precision", cluster_one)

    def test_hash_is_collected_during_synthetic_holdout_read(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "tiny_holdout.csv"
            pd.DataFrame({
                "Label": ["BENIGN", "ATTACK"], "Source IP": ["a", "b"],
                "Source Port": [1, 2], "Destination IP": ["b", "a"],
                "Destination Port": [2, 1], "Protocol": [17, 17],
                "Timestamp": ["2018-12-01 13:00:00.000000", "2018-12-01 13:00:01.000000"],
                "f1": [1.0, 2.0],
            }).to_csv(path, index=False)
            import hashlib
            result = load_full_holdout(path, ["f1"], chunk_size=1)
            self.assertEqual(result["rows_read"], 2)
            self.assertEqual(result["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_holdout_disk_checkpoint_is_chunked_reusable_and_context_checked(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / "tiny_holdout.csv"
            pd.DataFrame({
                "Label": ["BENIGN", "ATTACK", "BENIGN"],
                "Source IP": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
                "Source Port": [1, 2, 3], "Destination IP": ["10.0.0.2", "10.0.0.3", "10.0.0.4"],
                "Destination Port": [2, 3, 4], "Protocol": [17, 17, 17],
                "Timestamp": ["2018-12-01 13:00:00", "2018-12-01 13:00:01", "2018-12-01 13:00:02"],
                "f1": [1.0, 2.0, 3.0],
            }).to_csv(path, index=False)
            checkpoint = root / "holdout_memmap"
            context = {"input": {"tiny_holdout.csv": 1}, "features": ["f1"], "gap": 60}
            first, reused = load_or_create_holdout_memmap(path, ["f1"], 2, checkpoint, context)
            self.assertFalse(reused)
            self.assertEqual(first["rows_read"], 3)
            self.assertEqual(first["X"].to_numpy(copy=False).ravel().tolist(), [1.0, 2.0, 3.0])
            backing = first["X"].to_numpy(copy=False)
            while not isinstance(backing, np.memmap) and getattr(backing, "base", None) is not None:
                backing = backing.base
            self.assertIsInstance(backing, np.memmap)
            with patch("research_eval_protocol.pd.read_csv", side_effect=AssertionError("CSV reread")):
                second, reused = load_or_create_holdout_memmap(path, ["f1"], 2, checkpoint, context)
            self.assertTrue(reused)
            pd.testing.assert_frame_equal(first["X"], second["X"])
            np.testing.assert_array_equal(first["tuple_keys"], second["tuple_keys"])
            with self.assertRaisesRegex(ValueError, "incompatible"):
                load_or_create_holdout_memmap(path, ["f1"], 2, checkpoint, {**context, "gap": 30})
            self.close_memmaps(first["X"], first["tuple_keys"], first["timestamps_ns"], first["y"],
                               second["X"], second["tuple_keys"], second["timestamps_ns"], second["y"],
                               backing)

    def test_chunked_prediction_matches_full_prediction_and_resumes_safely(self):
        from unittest.mock import patch

        class TinyProbabilityModel:
            classes_ = np.array([0, 1])

            def predict_proba(self, X):
                p = np.clip(X["f1"].to_numpy(dtype=float) / 10.0, 0.0, 1.0)
                return np.column_stack((1.0 - p, p))

        model = TinyProbabilityModel()
        X = pd.DataFrame({"f1": [1.0, 4.0, 7.0, 9.0, 2.0]})
        with tempfile.TemporaryDirectory() as folder:
            checkpoint = Path(folder) / "probabilities"
            context = {"model": "tiny", "input": "fixture", "features": ["f1"]}
            chunked = load_or_create_probability_memmap(model, X, checkpoint, context, chunk_rows=2)
            np.testing.assert_array_equal(chunked, model.predict_proba(X)[:, 1])
            with patch.object(model, "predict_proba", side_effect=AssertionError("prediction should resume")):
                resumed = load_or_create_probability_memmap(model, X, checkpoint, context, chunk_rows=2)
            np.testing.assert_array_equal(resumed, chunked)
            with self.assertRaisesRegex(ValueError, "incompatible"):
                load_or_create_probability_memmap(model, X, checkpoint, {**context, "model": "other"}, chunk_rows=2)
            self.close_memmaps(chunked, resumed)

    def test_compact_tuple_ids_preserve_tuple_purge_and_metric_results(self):
        from research_eval_protocol import training_split_mask
        keys = np.array(["same", "other", "same"], dtype=object)
        ids = compact_tuple_ids(keys)
        expected_ids = compact_tuple_ids(keys)
        np.testing.assert_array_equal(ids, expected_ids)
        test_groups = {ids[0].tobytes()}
        start = 1_600_000_000 * NANOSECONDS_PER_SECOND
        mask, _ = training_split_mask(
            np.array([start - 61 * NANOSECONDS_PER_SECOND] * 3), ids,
            np.ones(3, dtype=bool), test_groups, start, 60,
        )
        np.testing.assert_array_equal(mask, [False, True, False])
        y = np.array([0, 0, 1, 1], dtype=np.int8)
        probability = np.array([0.1, 0.7, 0.4, 0.9])
        full = metric_record("synthetic", y, probability >= 0.5, probability)
        chunked_equivalent = metric_record("synthetic", y, probability.copy() >= 0.5, probability.copy())
        self.assertEqual(full, chunked_equivalent)

    def test_baseline_and_deployed_reference_tables_are_separate(self):
        with tempfile.TemporaryDirectory() as folder:
            baseline = {"model": "Research RF", "f1": 0.8}
            reference = {"model": "Deployed RF V2", "f1": 0.9}
            write_result_tables([baseline], reference, Path(folder))
            baseline_names = pd.read_csv(Path(folder) / "baseline_results.csv")["model"].tolist()
            reference_names = pd.read_csv(Path(folder) / "deployed_v2_reference.csv")["model"].tolist()
            self.assertEqual(baseline_names, ["Research RF"])
            self.assertEqual(reference_names, ["Deployed RF V2"])

    def test_checkpoint_is_reused_and_incompatible_context_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            checkpoint = Path(folder) / "stage.pkl"
            context = {"revision": "abc", "features": ["f1"]}
            calls = []
            first, reused = load_or_create_checkpoint(
                checkpoint, context, lambda: calls.append("computed") or {"value": 7}
            )
            second, reused_again = load_or_create_checkpoint(
                checkpoint, context, lambda: calls.append("unexpected") or None
            )
            self.assertEqual(first, second)
            self.assertFalse(reused)
            self.assertTrue(reused_again)
            self.assertEqual(calls, ["computed"])
            with self.assertRaisesRegex(ValueError, "incompatible"):
                load_or_create_checkpoint(checkpoint, {"revision": "changed"}, lambda: None)

    def test_manifest_recovers_failed_run_and_only_completes_verified_outputs(self):
        with tempfile.TemporaryDirectory() as folder:
            run_dir = Path(folder) / "run"
            context = {"inputs": {"tiny.csv": {"size_bytes": 10}}, "seed": 9}
            manifest = RunManifest.start(run_dir, context)
            manifest.mark_stage_complete("holdout", "checkpoints/holdout.pkl")
            manifest.mark_failed(RuntimeError("synthetic interruption"))
            resumed = RunManifest.start(run_dir, context, resume=True)
            self.assertEqual(resumed.data["state"], "IN_PROGRESS")
            self.assertTrue(resumed.stage_complete("holdout"))
            staging = run_dir / "partial"
            staging.mkdir()
            with self.assertRaisesRegex(RuntimeError, "missing/empty"):
                resumed.mark_complete(staging, run_dir / "results", ["report.md"])
            (staging / "report.md").write_text("complete", encoding="utf-8")
            resumed.mark_complete(staging, run_dir / "results", ["report.md"])
            saved = json.loads((run_dir / "run_manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["state"], "COMPLETE")
            self.assertEqual((run_dir / "results" / "report.md").read_text(encoding="utf-8"), "complete")

    def test_training_sampling_resumes_from_completed_file_checkpoint(self):
        from research_eval_protocol import sample_purged_training
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "source.csv"
            pd.DataFrame({
                "Label": ["BENIGN", "UDP-LAG"], "Source IP": ["10.0.0.1", "10.0.0.2"],
                "Source Port": [1, 2], "Destination IP": ["10.0.0.3", "10.0.0.4"],
                "Destination Port": [3, 4], "Protocol": [17, 17],
                "Timestamp": ["2018-12-01 12:00:00", "2018-12-01 12:00:01"],
                "f1": [1.0, 2.0],
            }).to_csv(path, index=False)
            checkpoint = Path(folder) / "training_state.pkl"
            context = {"seed": 42, "input": {"source.csv": 1}}
            first = sample_purged_training(
                [path], ["f1"], set(), 1_600_000_000 * NANOSECONDS_PER_SECOND,
                cap=10, seed=42, checkpoint_path=checkpoint, checkpoint_context=context,
            )
            with patch("research_eval_protocol.pd.read_csv", side_effect=AssertionError("source reread")):
                resumed = sample_purged_training(
                    [path], ["f1"], set(), 1_600_000_000 * NANOSECONDS_PER_SECOND,
                    cap=10, seed=42, checkpoint_path=checkpoint, checkpoint_context=context,
                )
            pd.testing.assert_frame_equal(first["X"], resumed["X"])
            np.testing.assert_array_equal(first["y"], resumed["y"])
            self.assertEqual(first["metadata"]["files"], resumed["metadata"]["files"])

    def test_training_sampler_purges_matching_compact_tuple_ids(self):
        from research_eval_protocol import sample_purged_training
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "source.csv"
            data = pd.DataFrame({
                "Label": ["BENIGN", "BENIGN", "UDP-LAG", "UDP-LAG"],
                "Source IP": ["10.0.0.1", "10.0.0.5", "10.0.0.6", "10.0.0.7"],
                "Source Port": [1001, 1005, 1006, 1007],
                "Destination IP": ["10.0.0.2", "10.0.0.8", "10.0.0.9", "10.0.0.10"],
                "Destination Port": [2001, 2005, 2006, 2007], "Protocol": [17, 17, 17, 17],
                "Timestamp": ["2018-12-01 12:00:00"] * 4,
                "f1": [1.0, 2.0, 3.0, 4.0],
            })
            data.to_csv(path, index=False)
            holdout_row = data.iloc[[0]][["Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol"]]
            canonical, valid = canonical_tuple_keys(holdout_row)
            self.assertTrue(valid.all())
            test_groups = {compact_tuple_ids(canonical)[0].tobytes()}
            sampled = sample_purged_training(
                [path], ["f1"], test_groups, 1_600_000_000 * NANOSECONDS_PER_SECOND,
                cap=10, seed=42, chunk_size=2,
            )
            self.assertEqual(sampled["metadata"]["rows_removed_for_tuple_overlap"], 1)
            self.assertEqual(sampled["metadata"]["rows_after_gap_and_group_purge"], 3)

if __name__ == "__main__":
    unittest.main()
