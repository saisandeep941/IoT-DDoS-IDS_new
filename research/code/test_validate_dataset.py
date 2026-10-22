import unittest

from validate_dataset import DatasetSchemaError, validate_feature_columns


class DatasetSchemaValidationTests(unittest.TestCase):
    def setUp(self):
        self.features = ["Source Port", "Destination Port", "Protocol"]

    def test_accepts_exact_order_with_label_column(self):
        validate_feature_columns(self.features + ["Label"], self.features)

    def test_accepts_production_header_whitespace_normalization(self):
        validate_feature_columns([f" {name} " for name in self.features] + [" Label "], self.features)

    def test_rejects_missing_features(self):
        with self.assertRaisesRegex(DatasetSchemaError, "missing model features"):
            validate_feature_columns(["Source Port", "Label"], self.features)

    def test_rejects_reordered_features(self):
        with self.assertRaisesRegex(DatasetSchemaError, "not in the saved schema order"):
            validate_feature_columns(list(reversed(self.features)), self.features)

    def test_rejects_duplicate_feature_columns(self):
        with self.assertRaisesRegex(DatasetSchemaError, "duplicate CSV columns"):
            validate_feature_columns(self.features + ["Protocol"], self.features)


if __name__ == "__main__":
    unittest.main()
