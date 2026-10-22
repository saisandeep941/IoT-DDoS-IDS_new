import unittest
from collections import deque
from unittest.mock import patch

from backend.main import append_detection, detection_records, get_alerts


class DetectionHistoryTests(unittest.TestCase):
    def test_ids_remain_unique_after_history_limit(self):
        starting_ids = {item["id"] for item in detection_records}
        for index in range(505):
            append_detection("Benign", index % 100, "Low", "unit test")
        ids = [item["id"] for item in detection_records]
        self.assertEqual(len(ids), 500)
        self.assertEqual(len(set(ids)), 500)
        self.assertTrue(starting_ids.isdisjoint(ids))

    def test_alerts_only_expose_recorded_attack_predictions(self):
        records = deque([
            {"id": 2, "prediction": "Benign", "severity": "Low", "risk_score": 12.0, "timestamp": "t2", "source": "unit test"},
            {"id": 1, "prediction": "Attack", "severity": "High", "risk_score": 60.0, "timestamp": "t1", "source": "unit test"},
        ])
        with patch("backend.main.detection_records", records):
            result = get_alerts()
        self.assertEqual([item["id"] for item in result["alerts"]], [1])
        self.assertEqual(result["mode"], "recorded_predictions")
        self.assertNotIn("ip", result["alerts"][0])


if __name__ == "__main__":
    unittest.main()
