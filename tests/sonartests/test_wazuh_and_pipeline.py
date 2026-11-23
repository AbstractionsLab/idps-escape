"""
Unit tests for MVADPostProcessor: anomaly document post-processing.

The indexer client is tested in test_indexer_client.py.
"""

import unittest
from datetime import datetime, timezone

import pandas as pd

from sonar.config import FeatureConfig
from sonar.backends.mvad import mvad_results_to_points
from sonar.pipeline import MVADPostProcessor


def _build(processor, timestamps, results, context, **kwargs):
    """Post-process MVAD-style result dicts (converted as the mvad backend does)."""
    return processor.build_wazuh_anomaly_docs(mvad_results_to_points(results), context, **kwargs)


class TestMVADPostProcessor(unittest.TestCase):
    """Test MVADPostProcessor anomaly document generation."""

    def setUp(self):
        """Set up test fixtures."""
        self.cfg = FeatureConfig()
        self.processor = MVADPostProcessor(self.cfg)

    def test_build_wazuh_anomaly_docs_basic(self):
        """Test basic anomaly document generation."""
        timestamps = [
            datetime(2025, 12, 30, 10, 0, tzinfo=timezone.utc),
            datetime(2025, 12, 30, 10, 5, tzinfo=timezone.utc),
            datetime(2025, 12, 30, 10, 10, tzinfo=timezone.utc),
        ]

        results = [
            {"index": pd.Timestamp("2025-12-30 10:00:00+00:00"), "is_anomaly": False, "score": 0.1, "severity": 0.0, "interpretation": []},
            {"index": pd.Timestamp("2025-12-30 10:05:00+00:00"), "is_anomaly": False, "score": 0.2, "severity": 0.0, "interpretation": []},
            {"index": pd.Timestamp("2025-12-30 10:10:00+00:00"), "is_anomaly": True, "score": 0.9, "severity": 0.8, "interpretation": []},
        ]

        context = {
            "bucket_minutes": 5,
            "lookback_minutes": 30,
        }

        docs = _build(self.processor, timestamps, results, context)

        # Should generate one document for the anomaly
        self.assertEqual(len(docs), 1)
        self.assertIn("timestamp", docs[0])
        self.assertNotIn("rule", docs[0])  # documents are not Wazuh alerts; the manager raises those
        self.assertIn("data", docs[0])
        self.assertIn("mvad_score", docs[0]["data"])

    def test_build_wazuh_anomaly_docs_multiple_anomalies(self):
        """Test generation with multiple anomalies."""
        timestamps = [
            datetime(2025, 12, 30, 10, 0, tzinfo=timezone.utc),
            datetime(2025, 12, 30, 10, 5, tzinfo=timezone.utc),
            datetime(2025, 12, 30, 10, 10, tzinfo=timezone.utc),
        ]

        results = [
            {"index": pd.Timestamp("2025-12-30 10:00:00+00:00"), "is_anomaly": True, "score": 0.8, "severity": 0.7, "interpretation": []},
            {"index": pd.Timestamp("2025-12-30 10:05:00+00:00"), "is_anomaly": False, "score": 0.2, "severity": 0.0, "interpretation": []},
            {"index": pd.Timestamp("2025-12-30 10:10:00+00:00"), "is_anomaly": True, "score": 0.9, "severity": 0.8, "interpretation": []},
        ]

        context = {"bucket_minutes": 5}

        docs = _build(self.processor, timestamps, results, context)

        # Should generate two documents
        self.assertEqual(len(docs), 2)

    def test_build_wazuh_anomaly_docs_no_anomalies(self):
        """Test generation with no anomalies detected."""
        timestamps = [
            datetime(2025, 12, 30, 10, 0, tzinfo=timezone.utc),
            datetime(2025, 12, 30, 10, 5, tzinfo=timezone.utc),
        ]

        results = [
            {"index": pd.Timestamp("2025-12-30 10:00:00+00:00"), "is_anomaly": False, "score": 0.1, "severity": 0.0, "interpretation": []},
            {"index": pd.Timestamp("2025-12-30 10:05:00+00:00"), "is_anomaly": False, "score": 0.2, "severity": 0.0, "interpretation": []},
        ]

        context = {"bucket_minutes": 5}

        docs = _build(self.processor, timestamps, results, context)

        # Should generate no documents
        self.assertEqual(len(docs), 0)

    def test_build_wazuh_anomaly_docs_rejects_unexpected_format(self):
        """A result that is not a list of per-bucket dicts is an error, never a fabricated anomaly."""
        with self.assertRaises(ValueError):
            self.processor.build_wazuh_anomaly_docs({}, {"scenario_id": "test"}, threshold=0.8)
        with self.assertRaises(ValueError):  # raw library output must go through a backend first
            self.processor.build_wazuh_anomaly_docs([{"index": pd.Timestamp("2025-12-30T10:00Z"), "is_anomaly": True}], {})

    def test_build_wazuh_anomaly_docs_empty_results(self):
        """An empty result list gives no documents."""
        self.assertEqual(self.processor.build_wazuh_anomaly_docs([], {}), [])

    def test_build_wazuh_anomaly_docs_includes_context(self):
        """Test that context information is included in docs."""
        timestamps = [datetime(2025, 12, 30, 10, 0, tzinfo=timezone.utc)]
        results = [{"index": pd.Timestamp("2025-12-30 10:00:00+00:00"), "is_anomaly": True, "score": 0.9, "severity": 0.8, "interpretation": []}]
        context = {
            "bucket_minutes": 5,
            "lookback_minutes": 60,
            "custom_field": "test_value",
            "scenario_id": "test_scenario",
            "alert_count": 100,
            "model_path": "/path/to/model.pkl",
            "training_samples": 1000,
            "sliding_window": 200,
            "model_name": "model",
            "feature_names": ["alert_count", "rule.level", "is_ssh_event"],
        }

        docs = _build(self.processor, timestamps, results, context, threshold=0.75)

        self.assertEqual(len(docs), 1)

        # Check required top-level fields
        self.assertIn("is_anomaly", docs[0])
        self.assertTrue(docs[0]["is_anomaly"])
        self.assertIn("anomaly_score", docs[0])
        self.assertEqual(docs[0]["anomaly_score"], 0.8)  # severity, 0-1
        self.assertEqual(docs[0]["mvad_score"], 0.9)  # raw MVAD score
        self.assertIn("threshold", docs[0])
        self.assertEqual(docs[0]["threshold"], 0.75)
        self.assertEqual(docs[0]["model_name"], "model")
        self.assertIn("scenario_name", docs[0])
        self.assertEqual(docs[0]["scenario_name"], "test_scenario")
        self.assertIn("detection_timestamp", docs[0])
        self.assertIn("alert_count", docs[0])
        self.assertEqual(docs[0]["alert_count"], 100)
        self.assertEqual(docs[0]["feature_count"], 3)  # every model column, not only numeric_fields
        self.assertEqual(docs[0]["context"]["feature_names"], ["alert_count", "rule.level", "is_ssh_event"])
        self.assertEqual(docs[0]["sliding_window"], 200)

        # Check timestamps
        self.assertIn("@timestamp", docs[0])
        self.assertIn("timestamp", docs[0])

        # Context should be structured object
        self.assertIn("context", docs[0])
        self.assertIn("model_path", docs[0]["context"])
        self.assertEqual(docs[0]["context"]["model_path"], "/path/to/model.pkl")
        self.assertIn("training_samples", docs[0]["context"])
        self.assertEqual(docs[0]["context"]["training_samples"], 1000)

        # Data field should contain MVAD-specific values
        self.assertIn("data", docs[0])
        self.assertIn("mvad_score", docs[0]["data"])
        self.assertEqual(docs[0]["data"]["mvad_score"], 0.9)
        self.assertIn("bucket_minutes", docs[0]["data"])
        self.assertEqual(docs[0]["data"]["bucket_minutes"], 5)

    def test_build_wazuh_anomaly_docs_timestamp_format(self):
        """Test that timestamps are properly formatted."""
        timestamps = [datetime(2025, 12, 30, 10, 0, tzinfo=timezone.utc)]
        results = [{"index": pd.Timestamp("2025-12-30 10:00:00+00:00"), "is_anomaly": True, "score": 0.9, "severity": 0.8, "interpretation": []}]
        context = {}

        docs = _build(self.processor, timestamps, results, context)

        # Timestamp should be ISO format string
        self.assertIsInstance(docs[0]["timestamp"], str)
        self.assertIn("2025-12-30", docs[0]["timestamp"])


class TestThresholdAndMinConsecutive(unittest.TestCase):
    """threshold and min_consecutive filter MVAD's anomalies (sonar/pipeline.py)."""

    def setUp(self):
        self.processor = MVADPostProcessor(FeatureConfig())
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.ts = [base + pd.Timedelta(minutes=5 * i) for i in range(8)]

    def _results(self, flags_severities):
        # The raw score is deliberately unrelated to the severity: the threshold must use severity.
        return [{"index": self.ts[i], "is_anomaly": a, "score": 1.5, "severity": sev} for i, (a, sev) in enumerate(flags_severities)]

    def test_no_threshold_keeps_every_mvad_anomaly(self):
        results = self._results([(True, 0.1), (False, 0.9), (True, 0.5)])
        docs = _build(self.processor, self.ts, results, {})
        self.assertEqual(len(docs), 2)
        self.assertIsNone(docs[0]["threshold"])

    def test_threshold_is_a_minimum_severity(self):
        results = self._results([(True, 0.69), (True, 0.7), (False, 0.99), (True, 0.95)])
        docs = _build(self.processor, self.ts, results, {}, threshold=0.7)
        self.assertEqual([d["anomaly_score"] for d in docs], [0.7, 0.95])
        self.assertTrue(all(d["mvad_score"] == 1.5 for d in docs))

    def test_threshold_outside_0_1_rejected(self):
        with self.assertRaises(ValueError):
            _build(self.processor, self.ts, self._results([(True, 0.5)]), {}, threshold=1.2)

    def test_contributors_carry_the_bucket_value(self):
        frame = pd.DataFrame({"alert_count": [3.0, 212.0]}, index=pd.DatetimeIndex(self.ts[:2]))
        results = [{"index": self.ts[1], "is_anomaly": True, "score": 1.0, "severity": 0.6, "interpretation": [{"variable_name": "alert_count", "contribution_score": 0.61}, {"variable_name": "gone", "contribution_score": 0.1}]}]
        docs = _build(self.processor, self.ts[:2], results, {}, feature_values=frame)
        self.assertEqual(docs[0]["mvad_interpretation"], [{"variable": "alert_count", "contribution": 0.61, "value": 212.0}, {"variable": "gone", "contribution": 0.1, "value": None}])

    def test_min_consecutive_keeps_only_long_enough_runs(self):
        # runs of qualifying points: [0,1] (len 2), [3] (len 1), [5,6,7] (len 3)
        flags = [(True, 0.9), (True, 0.9), (False, 0.9), (True, 0.9), (True, 0.1), (True, 0.9), (True, 0.9), (True, 0.9)]
        docs = _build(self.processor, self.ts, self._results(flags), {}, threshold=0.5, min_consecutive=2)
        self.assertEqual([d["timestamp"] for d in docs], [self.ts[i].isoformat() for i in (0, 1, 5, 6, 7)])

        docs = _build(self.processor, self.ts, self._results(flags), {}, threshold=0.5, min_consecutive=3)
        self.assertEqual(len(docs), 3)

    def test_library_result_without_index_is_an_error(self):
        # Every PointResult carries its bucket; a library entry without one is not guessed.
        with self.assertRaises(ValueError):
            mvad_results_to_points([{"is_anomaly": True, "score": 0.9}])


if __name__ == "__main__":
    unittest.main()
