"""Regression checks that the API exposes saved evaluation evidence verbatim."""

import csv
from pathlib import Path
import unittest

from backend.main import saved_research_evaluation


RESULTS = Path(__file__).resolve().parents[2] / "research" / "results"


class SavedResearchEvaluationTests(unittest.TestCase):
    def test_api_payload_matches_saved_baseline_and_v2_reference_artifacts(self):
        result = saved_research_evaluation()

        with (RESULTS / "baseline_results.csv").open(encoding="utf-8", newline="") as stream:
            saved_baselines = list(csv.DictReader(stream))
        with (RESULTS / "deployed_v2_reference.csv").open(encoding="utf-8", newline="") as stream:
            saved_reference = next(csv.DictReader(stream))

        self.assertEqual(result["dataset"], "CIC-DDoS2019-derived UDPLag.csv")
        self.assertEqual(result["evaluation_type"], "Same-source forward-time, tuple-purged research refit; frozen V2 is reference only")
        self.assertEqual(result["test_rows"], 370605)
        self.assertEqual(result["actual_class_counts"], {"BENIGN": 3705, "ATTACK": 366900})
        self.assertEqual(len(result["matched_research_refits"]), len(saved_baselines))
        for api_row, csv_row in zip(result["matched_research_refits"], saved_baselines):
            for metric in ("accuracy", "precision", "recall", "f1", "roc_auc", "average_precision"):
                self.assertEqual(api_row[metric], float(csv_row[metric]))
            self.assertEqual(api_row["confusion_matrix"], [
                [int(csv_row["tn"]), int(csv_row["fp"])],
                [int(csv_row["fn"]), int(csv_row["tp"])],
            ])

        reference = result["frozen_v2_reference_only"]
        self.assertEqual(reference["accuracy"], float(saved_reference["accuracy"]))
        self.assertEqual(reference["roc_auc"], float(saved_reference["roc_auc"]))
        self.assertEqual(reference["confusion_matrix"], [[3705, 0], [563, 366337]])
        self.assertEqual(result["protocol"]["gap_seconds"], 60)
        self.assertEqual(result["protocol"]["training_rows_purged_for_tuple_overlap"], 12071)
        self.assertEqual(result["protocol"]["independent_dataset_evaluation"], "not established")
        self.assertTrue(result["confidence_intervals"])
        self.assertTrue(result["efficiency"])


if __name__ == "__main__":
    unittest.main()
