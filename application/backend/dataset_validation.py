"""Validation helpers for labeled dataset uploads."""

import pandas as pd
from collections import Counter
from fastapi import HTTPException


class DatasetSchemaError(ValueError):
    """Raised when model input columns are missing, duplicated, or reordered."""


def validate_model_feature_columns(columns, feature_names):
    """Require the saved model features exactly once and in saved order."""
    normalized = [str(name).strip() for name in columns]
    features = list(feature_names)
    if len(features) != 82 or len(set(features)) != 82:
        raise DatasetSchemaError("Saved model schema must contain 82 unique features.")

    duplicates = sorted(name for name, count in Counter(normalized).items() if count > 1)
    feature_set = set(features)
    present = [name for name in normalized if name in feature_set]
    missing = [name for name in features if name not in normalized]
    if duplicates or missing or present != features:
        details = []
        if missing:
            details.append(f"missing model features: {missing}")
        if duplicates:
            details.append(f"duplicate CSV columns: {duplicates}")
        if present != features:
            details.append("model feature columns are not in the saved schema order")
        raise DatasetSchemaError("Incompatible CSV feature schema; " + "; ".join(details))


def validate_ground_truth_labels(labels):
    """Normalize labels and reject rows without ground-truth labels."""
    normalized = labels.astype("string").str.strip().str.upper()
    if normalized.isna().any() or normalized.eq("").any():
        raise HTTPException(
            status_code=400,
            detail="CSV contains missing or empty Label values.",
        )
    return normalized
