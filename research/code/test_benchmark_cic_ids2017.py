import csv

import numpy as np
import pytest

from benchmark_cic_ids2017 import (
    DatasetFormatError,
    FileStats,
    StratifiedReservoir,
    build_pipeline,
    iter_csv_chunks,
    map_label,
    metric_record,
    shared_feature_names,
    split_dataset_files,
    unique_column_names,
    _write_outputs,
)


def test_label_mapping_binary_and_blank_labels():
    assert map_label(" BENIGN ") == 0
    assert map_label("DDoS") == 1
    assert map_label("Web Attack � Brute Force") == 1
    assert map_label("") is None
    assert map_label(" NaN ") is None


def test_duplicate_headers_are_trimmed_and_deterministic():
    assert unique_column_names([" Feature ", "Feature", "Feature.1"]) == [
        "Feature", "Feature.2", "Feature.1"
    ]


def test_shared_features_follow_schema_order_and_reject_missing_features():
    selected, missing = shared_feature_names(["b", "a", "Label"], ["a", "b", "c"], expected_count=2)
    assert selected == ["a", "b"]
    assert missing == ["c"]
    with pytest.raises(DatasetFormatError, match="Expected 2 features"):
        shared_feature_names(["a"], ["a", "b"], expected_count=2)


def test_weekday_split_is_disjoint_and_uses_all_fridays(tmp_path):
    names = [
        "Monday-WorkingHours.csv", "Tuesday-WorkingHours.csv", "Wednesday-workingHours.csv",
        "Thursday-WorkingHours-Morning.csv", "Thursday-WorkingHours-Afternoon.csv",
        "Friday-WorkingHours-Morning.csv", "Friday-WorkingHours-Afternoon-DDos.csv",
        "Friday-WorkingHours-Afternoon-PortScan.csv",
    ]
    paths = [tmp_path / name for name in names]
    training, testing = split_dataset_files(paths)
    assert len(training) == 5
    assert len(testing) == 3
    assert {path.name for path in testing} == set(names[-3:])
    assert set(training).isdisjoint(testing)


def test_streaming_skips_malformed_and_blank_labels_and_counts_bad_numbers(tmp_path):
    path = tmp_path / "Monday-WorkingHours.csv"
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow([" x ", "x", "Label"])
        writer.writerow(["1", "2", "BENIGN"])
        writer.writerow(["bad", "inf", "DDoS"])
        writer.writerow(["3", "4", "  "])
        writer.writerow(["5", "DDoS"])  # wrong width
    stats = FileStats()
    chunks = list(iter_csv_chunks(path, ["x", "x.1"], chunk_size=1, stats=stats))
    assert len(chunks) == 2
    X = np.vstack([chunk[0] for chunk in chunks])
    y = np.concatenate([chunk[1] for chunk in chunks])
    ids = [row for chunk in chunks for row in chunk[3]]
    assert X.shape == (2, 2)
    assert np.isnan(X[1, 0]) and np.isnan(X[1, 1])
    assert y.tolist() == [0, 1]
    assert ids == [(path.name, 1), (path.name, 2)]
    assert stats.malformed_rows == 1
    assert stats.blank_labels == 1
    assert stats.label_counts == {"BENIGN": 1, "DDoS": 1}
    assert stats.invalid_numeric_by_feature["x"] == 1
    assert stats.infinite_by_feature["x.1"] == 1


def test_seeded_per_class_reservoir_is_reproducible_and_tracks_labels():
    X = np.arange(24, dtype=float).reshape(12, 2)
    y = np.array([0] * 8 + [1] * 4, dtype=np.int8)
    ids = [(f"f{i // 6}.csv", i) for i in range(len(y))]
    def sample():
        reservoir = StratifiedReservoir(2, cap_per_class=3, seed=71)
        reservoir.add(X, y, ids)
        return reservoir.result()
    first = sample()
    second = sample()
    np.testing.assert_array_equal(first[0], second[0])
    np.testing.assert_array_equal(first[1], second[1])
    assert first[1].tolist() == [0, 0, 0, 1, 1, 1]
    assert first[2] == second[2]
    assert len(set(first[2])) == 6


def test_sample_manifest_keeps_class_ids_aligned_when_class_counts_differ(tmp_path):
    metadata = {
        "split": {"training_files": [], "test_files": []},
        "training": {"sampled_rows": 3, "sampled_class_counts": {"BENIGN_0": 2, "ATTACK_1": 1}},
        "configuration": {"training_cap_per_class": 10},
        "test": {"evaluated_rows": 2, "class_counts": {"BENIGN_0": 1, "ATTACK_1": 1}},
        "features": ["f1"],
    }
    metric = metric_record("sample", np.array([0, 1]), np.array([0, 1]), 0.1, 0.01)
    ids = [("monday.csv", 1), ("monday.csv", 2), ("tuesday.csv", 3)]
    _write_outputs(tmp_path, metadata, [metric], ids, np.array([0, 0, 1]))
    with (tmp_path / "training_sample_manifest.csv").open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert [row["class"] for row in rows] == ["0", "0", "1"]
    assert [(row["source_file"], row["source_row_number"]) for row in rows] == [
        ("monday.csv", "1"), ("monday.csv", "2"), ("tuesday.csv", "3")
    ]


def test_imputation_and_scaling_are_fitted_only_from_training_data():
    X_train = np.array([[1.0, np.nan], [3.0, 2.0], [5.0, 4.0], [7.0, 6.0]])
    pipeline = build_pipeline("logistic_regression", seed=5)
    pipeline.fit(X_train, np.array([0, 0, 1, 1]))
    imputer = pipeline.named_steps["imputer"]
    scaler = pipeline.named_steps["scaler"]
    np.testing.assert_allclose(imputer.statistics_, [4.0, 4.0])
    imputer_before = imputer.statistics_.copy()
    scaler_before = scaler.mean_.copy()
    transformed = pipeline[:-1].transform(np.array([[1_000_000.0, np.nan]]))
    assert transformed.shape == (1, 2)
    np.testing.assert_array_equal(imputer.statistics_, imputer_before)
    np.testing.assert_array_equal(scaler.mean_, scaler_before)


def test_metrics_use_attack_as_positive_and_fixed_confusion_matrix_order():
    record = metric_record(
        "sample", np.array([0, 0, 1, 1]), np.array([0, 1, 1, 1]), 2.0, 0.5
    )
    assert record["accuracy"] == 0.75
    assert record["precision_attack"] == pytest.approx(2 / 3)
    assert record["recall_attack"] == 1.0
    assert record["f1_attack"] == pytest.approx(0.8)
    assert record["confusion_matrix"] == [[1, 1], [0, 2]]
    assert record["test_inference_ms_per_row"] == 125.0
