"""Check CSV feature headers against the frozen V2 schema.

This is a structural header check only. Matching names and order do not prove
matching feature definitions, extraction logic, provenance, or independence.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

import joblib
import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = ROOT / "model" / "real_model_features_v2.joblib"


class DatasetSchemaError(ValueError):
    """Raised when CSV feature columns do not match the frozen schema."""


def validate_feature_columns(columns: list[str], feature_names: list[str]) -> None:
    """Require each model feature exactly once and in saved-schema order."""
    columns = [str(name).strip() for name in columns]
    duplicates = sorted({name for name in columns if columns.count(name) > 1})
    missing = [name for name in feature_names if name not in columns]
    present = [name for name in columns if name in set(feature_names)]
    expected_present = [name for name in feature_names if name in columns]
    if duplicates or missing or present != expected_present or len(present) != len(feature_names):
        details = []
        if missing:
            details.append(f"missing model features: {missing}")
        if duplicates:
            details.append(f"duplicate CSV columns: {duplicates}")
        if present != expected_present:
            details.append("model feature columns are not in the saved schema order")
        raise DatasetSchemaError("Incompatible CSV feature schema; " + "; ".join(details))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path, help="CSV file to inspect (header only)")
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA, help="saved ordered feature schema")
    args = parser.parse_args()

    try:
        features = joblib.load(args.schema)
        if not isinstance(features, list) or len(features) != 82 or len(set(features)) != 82:
            raise DatasetSchemaError("Saved feature schema must contain 82 unique ordered names")
        # Match production CSV inference, which strips surrounding header spaces.
        columns = pd.read_csv(args.dataset, nrows=0).columns.str.strip().tolist()
        validate_feature_columns(columns, features)
    except (OSError, ValueError, TypeError, pd.errors.ParserError) as exc:
        print(f"REJECTED: {exc}", file=sys.stderr)
        return 2

    print(f"STRUCTURALLY COMPATIBLE: {args.dataset} contains the 82 saved feature names in order.")
    print("This header check does not establish feature-definition parity, provenance, label validity, or independent evaluation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
