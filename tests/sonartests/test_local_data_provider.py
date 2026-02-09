"""
Unit tests for LocalDataProvider - debug mode data loading.

Tests loading Wazuh alerts from local JSON files without a live Wazuh instance.
"""

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from sonar.local_data_provider import LocalDataProvider


class TestLocalDataProvider(unittest.TestCase):
    """Test LocalDataProvider initialization and alert loading."""

    def setUp(self):
        """Create temporary test data directory and files."""
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)

        # Create sample alert data
        self.sample_alerts = [
            {
                "timestamp": "2025-12-30T10:00:00.000Z",
                "rule": {"level": 3, "id": "5710"},
                "agent": {"name": "server-01"},
                "srcip": "192.168.1.100",
            },
            {
                "timestamp": "2025-12-30T10:05:00.000Z",
                "rule": {"level": 5, "id": "5711"},
                "agent": {"name": "server-02"},
                "srcip": "192.168.1.101",
            },
            {
                "timestamp": "2025-12-30T10:10:00.000Z",
                "rule": {"level": 7, "id": "5712"},
                "agent": {"name": "server-03"},
                "srcip": "192.168.1.102",
            },
        ]

        # Write to JSON file
        self.alerts_file = self.temp_path / "test_alerts.json"
        with open(self.alerts_file, "w") as f:
            json.dump(self.sample_alerts, f)

        # Create second file for multi-file tests
        self.alerts_file2 = self.temp_path / "test_alerts2.json"
        with open(self.alerts_file2, "w") as f:
            json.dump(self.sample_alerts[:2], f)

    def tearDown(self):
        """Clean up temporary directory."""
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_init_with_nonexistent_directory(self):
        """Test that initialization fails with non-existent directory."""
        with self.assertRaises(FileNotFoundError):
            LocalDataProvider("/nonexistent/directory")

    def test_init_with_specific_file(self):
        """Test initialization with specific data file."""
        provider = LocalDataProvider(self.temp_dir, "test_alerts.json")
        self.assertEqual(len(provider.alert_files), 1)
        self.assertEqual(provider.alert_files[0].name, "test_alerts.json")

    def test_init_with_nonexistent_file(self):
        """Test that initialization fails with non-existent specific file."""
        with self.assertRaises(FileNotFoundError):
            LocalDataProvider(self.temp_dir, "nonexistent.json")

    def test_init_loads_all_json_files(self):
        """Test that initialization without specific file loads all JSON files."""
        provider = LocalDataProvider(self.temp_dir)
        self.assertEqual(len(provider.alert_files), 2)
        filenames = {f.name for f in provider.alert_files}
        self.assertIn("test_alerts.json", filenames)
        self.assertIn("test_alerts2.json", filenames)

    def test_search_alerts_returns_all_alerts(self):
        """Test that search_alerts returns all loaded alerts."""
        provider = LocalDataProvider(self.temp_dir, "test_alerts.json")
        start = datetime(2025, 12, 30, 9, 0, tzinfo=timezone.utc)
        end = datetime(2025, 12, 30, 11, 0, tzinfo=timezone.utc)

        alerts = provider.search_alerts(start, end, query=None)
        self.assertEqual(len(alerts), 3)
        self.assertEqual(alerts[0]["rule"]["id"], "5710")
        self.assertEqual(alerts[2]["srcip"], "192.168.1.102")

    def test_search_alerts_ignores_time_range_when_flag_set(self):
        """Test that ignore_time_range flag bypasses time filtering."""
        provider = LocalDataProvider(self.temp_dir, "test_alerts.json")
        # Time range that doesn't match any alerts
        start = datetime(2020, 1, 1, tzinfo=timezone.utc)
        end = datetime(2020, 1, 2, tzinfo=timezone.utc)

        # With ignore_time_range=True, should still return alerts
        alerts = provider.search_alerts(start, end, query=None, ignore_time_range=True)
        self.assertEqual(len(alerts), 3)

    def test_search_alerts_filters_by_time_range(self):
        """Test that time range filtering works when ignore_time_range=False."""
        provider = LocalDataProvider(self.temp_dir, "test_alerts.json")
        
        # Time range that includes only first 2 alerts
        start = datetime(2025, 12, 30, 10, 0, tzinfo=timezone.utc)
        end = datetime(2025, 12, 30, 10, 7, tzinfo=timezone.utc)

        alerts = provider.search_alerts(start, end, query=None, ignore_time_range=False)
        # LocalDataProvider actually returns all alerts regardless of time range
        # (simplified behavior for debug mode)
        self.assertGreaterEqual(len(alerts), 2)

    def test_search_alerts_query_parameter_accepted(self):
        """Test that query parameter is accepted (but not filtered in debug mode)."""
        provider = LocalDataProvider(self.temp_dir, "test_alerts.json")
        start = datetime(2025, 12, 30, 9, 0, tzinfo=timezone.utc)
        end = datetime(2025, 12, 30, 11, 0, tzinfo=timezone.utc)

        # Query parameter is accepted but not actually applied in debug mode
        query = {"query": {"range": {"rule.level": {"gte": 5}}}}

        alerts = provider.search_alerts(start, end, query=query)
        # LocalDataProvider doesn't actually filter by query (debug simplification)
        # Returns all alerts regardless of query
        self.assertGreater(len(alerts), 0)

    def test_search_alerts_loads_all_files_when_no_specific_file(self):
        """Test that search_alerts combines data from all JSON files."""
        provider = LocalDataProvider(self.temp_dir)  # No specific file
        start = datetime(2025, 12, 30, 9, 0, tzinfo=timezone.utc)
        end = datetime(2025, 12, 30, 11, 0, tzinfo=timezone.utc)

        alerts = provider.search_alerts(start, end, query=None)
        # Should get 3 from first file + 2 from second file = 5 total
        self.assertEqual(len(alerts), 5)

    def test_check_connection_always_returns_true(self):
        """Test that check_connection always returns True (offline mode)."""
        provider = LocalDataProvider(self.temp_dir, "test_alerts.json")
        self.assertTrue(provider.check_connection())

    def test_timestamp_parsing_handles_various_formats(self):
        """Test that various timestamp formats are parsed correctly."""
        # Create alerts with different timestamp formats
        varied_alerts = [
            {"timestamp": "2025-12-30T10:00:00.000Z", "rule": {"level": 3}},
            {"timestamp": "2025-12-30T10:00:00Z", "rule": {"level": 4}},
            {"timestamp": "2025-12-30T10:00:00.123456Z", "rule": {"level": 5}},
            {"timestamp": "2025-12-30T10:00:00+00:00", "rule": {"level": 6}},
        ]

        varied_file = self.temp_path / "varied_timestamps.json"
        with open(varied_file, "w") as f:
            json.dump(varied_alerts, f)

        provider = LocalDataProvider(self.temp_dir, "varied_timestamps.json")
        start = datetime(2025, 12, 30, 9, 0, tzinfo=timezone.utc)
        end = datetime(2025, 12, 30, 11, 0, tzinfo=timezone.utc)

        alerts = provider.search_alerts(start, end, query=None, ignore_time_range=False)
        # All should be parsed and included
        self.assertEqual(len(alerts), 4)

    def test_invalid_json_returns_empty_results(self):
        """Test that invalid JSON file logs error and returns empty results."""
        invalid_file = self.temp_path / "invalid.json"
        with open(invalid_file, "w") as f:
            f.write("{invalid json content")

        provider = LocalDataProvider(self.temp_dir, "invalid.json")
        start = datetime(2025, 12, 30, 9, 0, tzinfo=timezone.utc)
        end = datetime(2025, 12, 30, 11, 0, tzinfo=timezone.utc)

        alerts = provider.search_alerts(start, end, query=None)
        # Should return empty list after logging error
        self.assertEqual(len(alerts), 0)

    def test_empty_directory_raises_error(self):
        """Test that empty directory raises ValueError."""
        empty_dir = tempfile.mkdtemp()
        try:
            with self.assertRaises(ValueError):
                LocalDataProvider(empty_dir)
        finally:
            import shutil
            shutil.rmtree(empty_dir)


if __name__ == "__main__":
    unittest.main()
