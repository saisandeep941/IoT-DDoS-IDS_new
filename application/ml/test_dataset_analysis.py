"""Focused tests for ground-truth CSV label validation."""

import unittest
from io import BytesIO

import pandas as pd
from fastapi import HTTPException
from starlette.datastructures import UploadFile

from backend.dataset_validation import validate_ground_truth_labels
from backend.main import analyze_dataset


def call_analysis_handler(filename, csv_bytes):
    """Run the current synchronous endpoint body without starting an event loop."""
    coroutine = analyze_dataset(
        UploadFile(filename=filename, file=BytesIO(csv_bytes))
    )
    try:
        coroutine.send(None)
    except StopIteration as completed:
        return completed.value
    raise AssertionError("Dataset analysis endpoint unexpectedly awaited work")


class DatasetLabelValidationTests(unittest.TestCase):
    def test_endpoint_returns_correct_counts_for_complete_labels(self):
        result = call_analysis_handler(
            "complete.csv",
            b"Flow,Label\n1,BENIGN\n2,UDP-FLOOD\n3,SYN\n",
        )

        self.assertEqual(result["total_traffic"], 3)
        self.assertEqual(result["benign_traffic"], 1)
        self.assertEqual(result["attacks_detected"], 2)
        self.assertEqual(result["attack_types"], {"UDP-FLOOD": 1, "SYN": 1})

    def test_endpoint_rejects_blank_or_missing_labels_without_metrics(self):
        for csv_bytes in (
            b"Flow,Label\n1,BENIGN\n2,\n",
            b"Flow,Label\n1,BENIGN\n2,UDP-FLOOD\n3\n",
        ):
            with self.subTest(csv=csv_bytes):
                with self.assertRaises(HTTPException) as raised:
                    call_analysis_handler("incomplete.csv", csv_bytes)
                self.assertEqual(raised.exception.status_code, 400)
                self.assertEqual(
                    raised.exception.detail,
                    "CSV contains missing or empty Label values.",
                )

    def test_rejects_missing_and_empty_labels(self):
        for labels in (
            pd.Series(["BENIGN", ""]),
            pd.Series(["BENIGN", None]),
        ):
            with self.subTest(labels=labels.tolist()):
                with self.assertRaises(HTTPException) as raised:
                    validate_ground_truth_labels(labels)
                self.assertEqual(raised.exception.status_code, 400)
                self.assertEqual(
                    raised.exception.detail,
                    "CSV contains missing or empty Label values.",
                )

    def test_normalizes_complete_labels(self):
        normalized = validate_ground_truth_labels(
            pd.Series([" BENIGN ", "UDP-FLOOD", "SYN"])
        )

        self.assertEqual(
            normalized.tolist(), ["BENIGN", "UDP-FLOOD", "SYN"]
        )


if __name__ == "__main__":
    unittest.main()
