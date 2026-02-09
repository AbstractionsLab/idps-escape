"""
Unit tests for WazuhIndexerClient and MVADPostProcessor.

Tests Wazuh Indexer API interactions and anomaly document post-processing.
"""

import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pandas as pd

from sonar.config import WazuhIndexerConfig, FeatureConfig
from sonar.wazuh_client import WazuhIndexerClient
from sonar.pipeline import MVADPostProcessor


class TestWazuhIndexerClient(unittest.TestCase):
    """Test WazuhIndexerClient API operations."""

    def setUp(self):
        """Set up test fixtures."""
        self.cfg = WazuhIndexerConfig()

    @patch("sonar.wazuh_client.requests.Session")
    def test_initialization(self, mock_session_cls):
        """Test client initialization with config."""
        client = WazuhIndexerClient(self.cfg)
        
        self.assertEqual(client.cfg, self.cfg)
        mock_session_cls.assert_called_once()

    @patch("sonar.wazuh_client.requests.Session")
    def test_search_alerts_success(self, mock_session_cls):
        """Test successful alert search."""
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "hits": {
                "hits": [
                    {
                        "_id": "1",
                        "_source": {
                            "timestamp": "2025-12-30T10:00:00Z",
                            "rule": {"level": 5, "id": "5710"},
                        },
                    },
                    {
                        "_id": "2",
                        "_source": {
                            "timestamp": "2025-12-30T10:05:00Z",
                            "rule": {"level": 10, "id": "5711"},
                        },
                    },
                ]
            }
        }
        mock_session.post.return_value = mock_resp

        client = WazuhIndexerClient(self.cfg)
        start = datetime(2025, 12, 30, 10, 0, 0, tzinfo=timezone.utc)
        end = datetime(2025, 12, 30, 11, 0, 0, tzinfo=timezone.utc)

        alerts = client.search_alerts(start, end)

        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[0]["rule"]["level"], 5)
        self.assertEqual(alerts[1]["rule"]["level"], 10)
        mock_session.post.assert_called_once()

    @patch("sonar.wazuh_client.requests.Session")
    def test_search_alerts_with_query(self, mock_session_cls):
        """Test alert search with custom query filter."""
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"hits": {"hits": []}}
        mock_session.post.return_value = mock_resp

        client = WazuhIndexerClient(self.cfg)
        start = datetime(2025, 12, 30, 10, 0, 0, tzinfo=timezone.utc)
        end = datetime(2025, 12, 30, 11, 0, 0, tzinfo=timezone.utc)
        query = {"query": {"term": {"rule.id": "5710"}}}

        client.search_alerts(start, end, query=query)

        # Verify query was included in request
        call_args = mock_session.post.call_args
        request_body = call_args[1]["json"]
        self.assertIn("must", request_body["query"]["bool"])

    @patch("sonar.wazuh_client.requests.Session")
    def test_search_alerts_empty_results(self, mock_session_cls):
        """Test search with no results."""
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"hits": {"hits": []}}
        mock_session.post.return_value = mock_resp

        client = WazuhIndexerClient(self.cfg)
        start = datetime(2025, 12, 30, 10, 0, 0, tzinfo=timezone.utc)
        end = datetime(2025, 12, 30, 11, 0, 0, tzinfo=timezone.utc)

        alerts = client.search_alerts(start, end)

        self.assertEqual(len(alerts), 0)

    @patch("sonar.wazuh_client.requests.Session")
    def test_search_alerts_with_size_limit(self, mock_session_cls):
        """Test search with custom size limit."""
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"hits": {"hits": []}}
        mock_session.post.return_value = mock_resp

        client = WazuhIndexerClient(self.cfg)
        start = datetime(2025, 12, 30, 10, 0, 0, tzinfo=timezone.utc)
        end = datetime(2025, 12, 30, 11, 0, 0, tzinfo=timezone.utc)

        client.search_alerts(start, end, size=5000)

        # Verify size was set correctly
        call_args = mock_session.post.call_args
        request_body = call_args[1]["json"]
        self.assertEqual(request_body["size"], 5000)

    @patch("sonar.wazuh_client.requests.Session")
    def test_index_anomaly_success(self, mock_session_cls):
        """Test successful anomaly indexing."""
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"_id": "anomaly-123"}
        mock_session.post.return_value = mock_resp

        client = WazuhIndexerClient(self.cfg)
        doc = {
            "timestamp": "2025-12-30T10:00:00Z",
            "rule": {"id": "900001", "description": "Anomaly detected"},
            "score": 0.95,
        }

        doc_id = client.index_anomaly(doc)

        self.assertEqual(doc_id, "anomaly-123")
        mock_session.post.assert_called_once()

    @patch("sonar.wazuh_client.requests.Session")
    def test_index_anomaly_with_special_types(self, mock_session_cls):
        """Test anomaly indexing with pandas/numpy types."""
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"_id": "anomaly-124"}
        mock_session.post.return_value = mock_resp

        client = WazuhIndexerClient(self.cfg)
        
        import pandas as pd
        doc = {
            "timestamp": pd.Timestamp("2025-12-30T10:00:00Z"),
            "score": 0.95,
        }

        doc_id = client.index_anomaly(doc)

        # Should handle pandas types via json.dumps default=str
        self.assertEqual(doc_id, "anomaly-124")

    @patch("sonar.wazuh_client.requests.Session")
    def test_check_connection_success(self, mock_session_cls):
        """Test successful connection check."""
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_session.get.return_value = mock_resp

        client = WazuhIndexerClient(self.cfg)
        
        self.assertTrue(client.check_connection())
        mock_session.get.assert_called_once()

    @patch("sonar.wazuh_client.requests.Session")
    def test_check_connection_failure(self, mock_session_cls):
        """Test failed connection check."""
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_session.get.side_effect = Exception("Connection refused")

        client = WazuhIndexerClient(self.cfg)
        
        self.assertFalse(client.check_connection())

    @patch("sonar.wazuh_client.requests.Session")
    def test_dry_run_mode(self, mock_session_cls):
        """Test dry run mode doesn't make actual API calls."""
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        client = WazuhIndexerClient(self.cfg, dry_run=True)
        doc = {"timestamp": "2025-12-30T10:00:00Z", "score": 0.95}

        doc_id = client.index_anomaly(doc)

        # Should return synthetic ID without calling API
        self.assertIsNotNone(doc_id)
        # API should not be called in dry run mode
        mock_session.post.assert_not_called()


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

        docs = self.processor.build_wazuh_anomaly_docs(timestamps, results, context)

        # Should generate one document for the anomaly
        self.assertEqual(len(docs), 1)
        self.assertIn("timestamp", docs[0])
        self.assertIn("rule", docs[0])
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

        docs = self.processor.build_wazuh_anomaly_docs(timestamps, results, context)

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

        docs = self.processor.build_wazuh_anomaly_docs(timestamps, results, context)

        # Should generate no documents
        self.assertEqual(len(docs), 0)

    def test_build_wazuh_anomaly_docs_empty_results(self):
        """Test handling of empty results."""
        timestamps = []
        results = {}
        context = {"scenario_id": "test", "alert_count": 0}

        docs = self.processor.build_wazuh_anomaly_docs(timestamps, results, context, threshold=0.8)

        # Empty results dict creates one fallback document
        self.assertEqual(len(docs), 1)
        
        # Check required fields are present
        self.assertIn("is_anomaly", docs[0])
        self.assertTrue(docs[0]["is_anomaly"])
        self.assertIn("anomaly_score", docs[0])
        self.assertIn("threshold", docs[0])
        self.assertEqual(docs[0]["threshold"], 0.8)
        self.assertIn("scenario_name", docs[0])
        self.assertIn("@timestamp", docs[0])
        
        # Check fallback data (new format uses result_type and result_repr)
        self.assertIn("data", docs[0])
        self.assertIn("result_type", docs[0]["data"])
        self.assertEqual(docs[0]["data"]["result_type"], "dict")

    def test_build_wazuh_anomaly_docs_includes_context(self):
        """Test that context information is included in docs."""
        timestamps = [datetime(2025, 12, 30, 10, 0, tzinfo=timezone.utc)]
        results = [
            {"index": pd.Timestamp("2025-12-30 10:00:00+00:00"), "is_anomaly": True, "score": 0.9, "severity": 0.8, "interpretation": []}
        ]
        context = {
            "bucket_minutes": 5,
            "lookback_minutes": 60,
            "custom_field": "test_value",
            "scenario_id": "test_scenario",
            "alert_count": 100,
            "model_path": "/path/to/model.pkl",
            "training_samples": 1000,
            "sliding_window": 200,
        }

        docs = self.processor.build_wazuh_anomaly_docs(timestamps, results, context, threshold=0.85)

        self.assertEqual(len(docs), 1)
        
        # Check required top-level fields
        self.assertIn("is_anomaly", docs[0])
        self.assertTrue(docs[0]["is_anomaly"])
        self.assertIn("anomaly_score", docs[0])
        self.assertEqual(docs[0]["anomaly_score"], 0.9)
        self.assertIn("threshold", docs[0])
        self.assertEqual(docs[0]["threshold"], 0.85)
        self.assertIn("scenario_name", docs[0])
        self.assertEqual(docs[0]["scenario_name"], "test_scenario")
        self.assertIn("detection_timestamp", docs[0])
        self.assertIn("alert_count", docs[0])
        self.assertEqual(docs[0]["alert_count"], 100)
        self.assertIn("feature_count", docs[0])
        
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
        results = [
            {"index": pd.Timestamp("2025-12-30 10:00:00+00:00"), "is_anomaly": True, "score": 0.9, "severity": 0.8, "interpretation": []}
        ]
        context = {}

        docs = self.processor.build_wazuh_anomaly_docs(timestamps, results, context)

        # Timestamp should be ISO format string
        self.assertIsInstance(docs[0]["timestamp"], str)
        self.assertIn("2025-12-30", docs[0]["timestamp"])


if __name__ == "__main__":
    unittest.main()
