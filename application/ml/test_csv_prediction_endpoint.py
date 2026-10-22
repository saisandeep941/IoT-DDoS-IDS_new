"""Focused validation tests for the real V2 CSV prediction handler."""

from io import BytesIO
from pathlib import Path
import unittest

from fastapi import HTTPException
import joblib
from pandas.errors import ParserError
from starlette.datastructures import UploadFile

from backend.main import predict_csv

FEATURE_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "backend"
    / "real_model_features_v2.joblib"
)


def invoke_handler(filename, content):
    """Run the synchronous body of the async handler without an ASGI client."""
    coroutine = predict_csv(
        UploadFile(filename=filename, file=BytesIO(content))
    )
    try:
        coroutine.send(None)
    except StopIteration as completed:
        return completed.value


class CsvPredictionEndpointTests(unittest.TestCase):
    def test_missing_and_extra_columns_return_clear_schema_error(self):
        with self.assertRaises(HTTPException) as raised:
            invoke_handler("missing.csv", b"Label,Extra\nBENIGN,x\n")
        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn("missing model features", raised.exception.detail)
        self.assertIn("Destination Port", raised.exception.detail)

    def test_extra_column_is_ignored_when_schema_columns_are_present(self):
        features = joblib.load(FEATURE_SCHEMA_PATH)
        self.assertEqual(len(features), 82)
        header = ",".join([*features, "Extra"])
        empty_row = ",".join(['""'] * 83)
        with self.assertRaises(HTTPException) as raised:
            invoke_handler("extra.csv", (header + "\n" + empty_row + "\n").encode())
        self.assertEqual(raised.exception.status_code, 400)
        self.assertEqual(
            raised.exception.detail,
            "CSV contains rows with no valid numeric model features.",
        )

    def test_malformed_csv_returns_client_error(self):
        with self.assertRaises(HTTPException) as raised:
            invoke_handler("malformed.csv", b'"unterminated\n')
        self.assertEqual(raised.exception.status_code, 400)
        self.assertEqual(
            raised.exception.detail, "Unable to parse the uploaded CSV file."
        )

    def test_empty_csv_returns_client_error(self):
        with self.assertRaises(HTTPException) as raised:
            invoke_handler("empty.csv", b"")
        self.assertEqual(raised.exception.status_code, 400)
        self.assertEqual(
            raised.exception.detail, "Unable to parse the uploaded CSV file."
        )

if __name__ == "__main__":
    unittest.main()

