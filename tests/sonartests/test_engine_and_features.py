"""
Consolidated unit tests for MVADModelEngine and WazuhFeatureBuilder.

Tests core functionality of the MVAD engine and feature extraction pipeline.
"""

import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pandas as pd

from sonar.config import MVADConfig, FeatureConfig, PipelineConfig
from sonar.backends import PointResult
from sonar.engine import MVADModelEngine
from sonar.features import FEATURE_SCHEMA_VERSION, WazuhFeatureBuilder
from sonar.training_plan import InsufficientTrainingDataError


class TestMVADModelEngine(unittest.TestCase):
    """Test MVADModelEngine training and prediction."""

    def setUp(self):
        """Set up test fixtures.

        250 buckets with sliding_window=20 and batch_size=8 give 2 batches per epoch and
        15 validation windows, so the training pre-flight check passes.
        """
        self.cfg = PipelineConfig()
        self.cfg.mvad.sliding_window = 20
        self.cfg.mvad.extra_params = {"batch_size": 8}
        self.engine = MVADModelEngine(self.cfg)

    @patch("sonar.backends.mvad.MultivariateAnomalyDetector")
    def test_train_success(self, mock_mad_class):
        """Test successful model training."""
        mock_model = MagicMock()
        mock_mad_class.return_value = mock_model

        # Create training data with enough samples
        ts_data = pd.DataFrame({"rule.level": list(range(250))})

        self.engine.train(ts_data)

        # Verify model was created and fit was called
        mock_mad_class.assert_called_once()
        mock_model.fit.assert_called_once()
        self.assertIsNotNone(self.engine.backend)

    def test_train_raises_on_sliding_window_too_large(self):
        """Test that training fails when sliding_window > num_samples."""
        self.cfg.mvad.sliding_window = 300
        ts_data = pd.DataFrame({"rule.level": list(range(250))})

        with self.assertRaises(ValueError) as ctx:
            self.engine.train(ts_data)
        self.assertIn("sliding_window", str(ctx.exception))

    @patch("sonar.backends.mvad.MultivariateAnomalyDetector")
    def test_train_refuses_when_library_would_not_update(self, mock_mad_class):
        """288 buckets with the default window give no training batch: refuse, never fit."""
        cfg = PipelineConfig()  # sliding_window=200, library batch_size=128, interval=10
        engine = MVADModelEngine(cfg)
        ts_data = pd.DataFrame({"rule.level": [float(i % 7) for i in range(288)]})

        with self.assertRaises(InsufficientTrainingDataError) as ctx:
            engine.train(ts_data)
        self.assertIn("1725 buckets", str(ctx.exception))
        mock_mad_class.return_value.fit.assert_not_called()
        self.assertIsNone(engine.backend)

    @patch("sonar.backends.mvad.MultivariateAnomalyDetector")
    def test_train_rejects_unknown_extra_param_with_hint(self, mock_mad_class):
        """A parameter the library would silently drop is an error that names the fix."""
        self.cfg.mvad.extra_params = {"batch_size": 8, "learning_rate": 0.01}
        with self.assertRaises(ValueError) as ctx:
            self.engine.train(pd.DataFrame({"rule.level": list(range(250))}))
        self.assertIn("'lr'", str(ctx.exception))
        mock_mad_class.return_value.fit.assert_not_called()

    @patch("sonar.backends.mvad.MultivariateAnomalyDetector")
    def test_train_uses_private_checkpoint_dir(self, mock_mad_class):
        """Each fit gets its own checkpoint directory instead of ./model."""
        self.engine.train(pd.DataFrame({"rule.level": list(range(250))}))
        engine2 = MVADModelEngine(self.cfg)
        engine2.train(pd.DataFrame({"rule.level": list(range(250))}))
        saves = [c.kwargs["params"]["save"] for c in mock_mad_class.return_value.fit.call_args_list]
        self.assertEqual(len(saves), 2)
        self.assertNotEqual(saves[0], saves[1])
        self.assertTrue(all("sonar-mvad-" in s for s in saves))

    @patch("sonar.backends.mvad.MultivariateAnomalyDetector")
    def test_train_records_metadata(self, mock_mad_class):
        """The engine records how the model was trained."""
        self.engine.train(pd.DataFrame({"rule.level": list(range(250))}))
        md = self.engine.metadata
        self.assertEqual(md["gradient_steps"], 200)  # 2 batches/epoch x 100 epochs
        self.assertEqual(md["feature_schema_version"], FEATURE_SCHEMA_VERSION)
        self.assertEqual(md["mvad_params"]["sliding_window"], 20)
        self.assertNotIn("save", md["mvad_params"])

    def test_train_raises_on_empty_data(self):
        """Test that training fails with empty data."""
        ts_data = pd.DataFrame()

        with self.assertRaises(ValueError):
            self.engine.train(ts_data)

    @patch("sonar.backends.mvad.MultivariateAnomalyDetector")
    def test_predict_success(self, mock_mad_class):
        """Test successful prediction."""
        mock_model = MagicMock()
        # Mock MVAD's actual return format: list of dicts
        mock_model.predict.return_value = [
            {"index": pd.Timestamp.now(), "is_anomaly": False, "score": 0.1, "severity": 0.0, "interpretation": []},
            {"index": pd.Timestamp.now(), "is_anomaly": False, "score": 0.2, "severity": 0.0, "interpretation": []},
            {"index": pd.Timestamp.now(), "is_anomaly": True, "score": 0.9, "severity": 0.8, "interpretation": []},
        ]
        mock_mad_class.return_value = mock_model

        # Train first
        ts_data = pd.DataFrame({"rule.level": list(range(250))})
        self.engine.train(ts_data)

        # Now predict
        pred_data = pd.DataFrame({"rule.level": [5, 6, 15]})
        results = self.engine.predict(pred_data)

        # Results are PointResults, in the library's order
        self.assertEqual(len(results), 3)
        self.assertTrue(all(isinstance(r, PointResult) for r in results))
        self.assertEqual([r.is_anomaly for r in results], [False, False, True])
        self.assertEqual((results[2].severity, results[2].raw_score), (0.8, 0.9))

    def test_predict_raises_without_model(self):
        """Test that prediction fails if model not trained."""
        pred_data = pd.DataFrame({"rule.level": [5, 6, 7]})

        with self.assertRaises(RuntimeError) as ctx:
            self.engine.predict(pred_data)
        self.assertIn("not loaded", str(ctx.exception).lower())

    @patch("sonar.backends.mvad.MultivariateAnomalyDetector")
    def test_predict_calls_the_library_with_the_aligned_frame(self, mock_mad_class):
        """The library's predict(context, data) gets the frame in the training column order."""
        mock_model = mock_mad_class.return_value
        mock_model.predict.return_value = [{"index": pd.Timestamp("2026-01-01T00:00Z"), "is_anomaly": False, "score": 0.1, "severity": 0.0, "interpretation": []}]
        self.engine.train(pd.DataFrame({"rule.level": list(range(250)), "alert_count": [1.0] * 250}))
        self.engine.predict(pd.DataFrame({"alert_count": [2.0], "rule.level": [5.0]}))
        args, kwargs = mock_model.predict.call_args
        self.assertEqual(args, (None,))
        self.assertEqual(list(kwargs["data"].columns), ["rule.level", "alert_count"])

    @patch("sonar.backends.mvad.MultivariateAnomalyDetector")
    def test_mvad_config_params_passed_to_model(self, mock_mad_class):
        """Test that MVAD config parameters are passed to model."""
        mock_model = MagicMock()
        mock_mad_class.return_value = mock_model

        # Custom config (1500 buckets, sliding_window 100, batch 16: 7 batches/epoch)
        self.cfg.mvad.sliding_window = 100
        self.cfg.mvad.device = "cuda"
        self.cfg.mvad.extra_params = {"batch_size": 16, "lr": 0.01}

        engine = MVADModelEngine(self.cfg)
        ts_data = pd.DataFrame({"rule.level": list(range(1500))})
        engine.train(ts_data)

        # Check that model was instantiated (no params in __init__)
        mock_mad_class.assert_called_once_with()

        # Check that model.fit was called with data and params
        mock_model.fit.assert_called_once()
        fit_call_args = mock_model.fit.call_args
        self.assertEqual(fit_call_args[1]["params"]["sliding_window"], 100)
        self.assertEqual(fit_call_args[1]["params"]["device"], "cuda")
        self.assertEqual(fit_call_args[1]["params"]["lr"], 0.01)


class TestWazuhFeatureBuilder(unittest.TestCase):
    """Test WazuhFeatureBuilder feature extraction."""

    def setUp(self):
        """Set up test fixtures."""
        self.cfg = FeatureConfig()
        self.builder = WazuhFeatureBuilder(self.cfg)

    def test_extract_features_basic(self):
        """Test basic feature extraction from alerts."""
        alerts = [
            {
                "timestamp": "2025-12-30T10:00:00.000Z",
                "rule": {"level": 3},
            },
            {
                "timestamp": "2025-12-30T10:05:00.000Z",
                "rule": {"level": 5},
            },
            {
                "timestamp": "2025-12-30T10:10:00.000Z",
                "rule": {"level": 7},
            },
        ]

        ts_data = self.builder.build_timeseries(alerts)

        self.assertIsInstance(ts_data, pd.DataFrame)
        self.assertEqual(len(ts_data), 3)
        self.assertIn("rule.level", ts_data.columns)

    def test_extract_features_with_bucketing(self):
        """Test time bucketing aggregation."""
        # Create alerts within same 5-minute bucket
        alerts = [
            {"timestamp": "2025-12-30T10:00:00.000Z", "rule": {"level": 3}},
            {"timestamp": "2025-12-30T10:01:00.000Z", "rule": {"level": 4}},
            {"timestamp": "2025-12-30T10:02:00.000Z", "rule": {"level": 5}},
        ]

        ts_data = self.builder.build_timeseries(alerts)

        # All should be bucketed into single time point (mean aggregation)
        self.assertEqual(len(ts_data), 1)
        # Mean of [3, 4, 5] = 4
        self.assertEqual(ts_data["rule.level"].iloc[0], 4.0)

    def test_extract_features_handles_missing_fields(self):
        """Test graceful handling of missing numeric fields."""
        alerts = [
            {"timestamp": "2025-12-30T10:00:00.000Z", "rule": {"level": 3}},
            {"timestamp": "2025-12-30T10:05:00.000Z"},  # Missing rule.level
        ]

        ts_data = self.builder.build_timeseries(alerts)

        # Should fill missing with 0
        self.assertEqual(len(ts_data), 2)
        self.assertEqual(ts_data["rule.level"].iloc[1], 0.0)

    def test_extract_features_with_categorical_fields(self):
        """Test one-hot encoding of categorical fields."""
        cfg = FeatureConfig(
            numeric_fields=["rule.level"],
            categorical_fields=["rule.id"],
            categorical_top_k=3,
        )
        builder = WazuhFeatureBuilder(cfg)

        alerts = [
            {"timestamp": "2025-12-30T10:00:00.000Z", "rule": {"level": 3, "id": "5710"}},
            {"timestamp": "2025-12-30T10:05:00.000Z", "rule": {"level": 5, "id": "5711"}},
            {"timestamp": "2025-12-30T10:10:00.000Z", "rule": {"level": 7, "id": "5710"}},
        ]

        ts_data = builder.build_timeseries(alerts)

        # Should have numeric + categorical columns
        self.assertIn("rule.level", ts_data.columns)
        # Should have one-hot encoded columns for rule.id
        categorical_cols = [col for col in ts_data.columns if "rule.id" in col]
        self.assertGreater(len(categorical_cols), 0)

    def test_parse_timestamp_with_z_suffix(self):
        """Test timestamp parsing with Z suffix."""
        ts_str = "2025-12-30T10:30:45.123Z"
        dt = self.builder._parse_timestamp(ts_str)

        self.assertEqual(dt.year, 2025)
        self.assertEqual(dt.month, 12)
        self.assertEqual(dt.day, 30)
        self.assertEqual(dt.hour, 10)
        self.assertEqual(dt.minute, 30)
        self.assertEqual(dt.second, 45)
        self.assertEqual(dt.microsecond, 123000)
        self.assertEqual(dt.tzinfo, timezone.utc)

    def test_parse_timestamp_with_offset(self):
        """Test timestamp parsing with UTC offset."""
        ts_str = "2025-12-30T10:30:45.123+00:00"
        dt = self.builder._parse_timestamp(ts_str)

        self.assertEqual(dt.year, 2025)
        self.assertEqual(dt.hour, 10)
        self.assertEqual(dt.tzinfo.utcoffset(None), timedelta(0))

    def test_parse_timestamp_without_milliseconds(self):
        """Test timestamp parsing without milliseconds."""
        ts_str = "2025-12-30T10:30:45Z"
        dt = self.builder._parse_timestamp(ts_str)

        self.assertEqual(dt.microsecond, 0)
        self.assertEqual(dt.tzinfo, timezone.utc)

    def test_parse_timestamp_various_formats(self):
        """Test parsing various timestamp formats."""
        formats = [
            "2025-12-30T10:30:45.123456Z",
            "2025-12-30T10:30:45.123Z",
            "2025-12-30T10:30:45Z",
            "2025-12-30T10:30:45+00:00",
            "2025-12-30T10:30:45.123+00:00",
        ]

        for ts_str in formats:
            dt = self.builder._parse_timestamp(ts_str)
            self.assertIsInstance(dt, datetime)
            self.assertIsNotNone(dt.tzinfo)

    def test_extract_features_preserves_timestamp_order(self):
        """Test that timestamps are in ascending order."""
        alerts = [
            {"timestamp": "2025-12-30T10:10:00.000Z", "rule": {"level": 7}},
            {"timestamp": "2025-12-30T10:00:00.000Z", "rule": {"level": 3}},
            {"timestamp": "2025-12-30T10:05:00.000Z", "rule": {"level": 5}},
        ]

        ts_data = self.builder.build_timeseries(alerts)

        # Timestamps should be sorted
        timestamps = ts_data.index.tolist()
        self.assertEqual(timestamps, sorted(timestamps))

    def test_derived_features_flag(self):
        """Test that derived_features flag controls feature generation."""
        # With derived features disabled
        cfg = FeatureConfig(derived_features=False)
        builder = WazuhFeatureBuilder(cfg)

        alerts = [
            {"timestamp": "2025-12-30T10:00:00.000Z", "rule": {"level": 3}},
            {"timestamp": "2025-12-30T10:05:00.000Z", "rule": {"level": 5}},
        ]

        ts_data = builder.build_timeseries(alerts)

        # Only the alert count and the numeric fields (no derived features)
        self.assertEqual(list(ts_data.columns), ["alert_count", "rule.level"])


class TestMaxAggregation(unittest.TestCase):
    """Tests for per-bucket max column generation."""

    def _make_alerts(self, cpu_values):
        """Build minimal resource-monitoring alerts with given CPU values."""
        alerts = []
        for i, cpu in enumerate(cpu_values):
            alerts.append(
                {
                    "timestamp": f"2026-01-01T10:0{i}:00.000Z",
                    "rule": {"level": 3, "groups": ["performance_metric"]},
                    "data": {"cpu_usage_%": cpu, "memory_usage_%": 50.0},
                }
            )
        return alerts

    def test_max_column_produced(self):
        """build_timeseries produces <field>__max when max_numeric_fields is set."""
        cfg = FeatureConfig(
            numeric_fields=["data.cpu_usage_%"],
            bucket_minutes=5,
            max_numeric_fields=["data.cpu_usage_%"],
        )
        builder = WazuhFeatureBuilder(cfg)
        # Two alerts in the *same* 5-min bucket: values 20 and 90
        alerts = [
            {"timestamp": "2026-01-01T10:00:00.000Z", "rule": {"level": 3}, "data": {"cpu_usage_%": 20.0}},
            {"timestamp": "2026-01-01T10:01:00.000Z", "rule": {"level": 3}, "data": {"cpu_usage_%": 90.0}},
        ]
        ts = builder.build_timeseries(alerts)
        self.assertIn("data.cpu_usage_%__max", ts.columns)

    def test_max_column_value_is_max_not_mean(self):
        """Max column captures the highest value; mean column captures the average."""
        cfg = FeatureConfig(
            numeric_fields=["data.cpu_usage_%"],
            bucket_minutes=60,  # one bucket for all alerts
            max_numeric_fields=["data.cpu_usage_%"],
        )
        builder = WazuhFeatureBuilder(cfg)
        alerts = [
            {"timestamp": "2026-01-01T10:00:00.000Z", "rule": {"level": 3}, "data": {"cpu_usage_%": 20.0}},
            {"timestamp": "2026-01-01T10:30:00.000Z", "rule": {"level": 3}, "data": {"cpu_usage_%": 90.0}},
        ]
        ts = builder.build_timeseries(alerts)
        # Mean should be 55, max should be 90
        self.assertAlmostEqual(ts["data.cpu_usage_%"].iloc[0], 55.0, places=1)
        self.assertAlmostEqual(ts["data.cpu_usage_%__max"].iloc[0], 90.0, places=1)

    def test_max_column_absent_when_not_configured(self):
        """No __max columns when max_numeric_fields is empty."""
        cfg = FeatureConfig(
            numeric_fields=["data.cpu_usage_%"],
            bucket_minutes=5,
        )
        builder = WazuhFeatureBuilder(cfg)
        alerts = [
            {"timestamp": "2026-01-01T10:00:00.000Z", "rule": {"level": 3}, "data": {"cpu_usage_%": 80.0}},
        ]
        ts = builder.build_timeseries(alerts)
        self.assertFalse(any(c.endswith("__max") for c in ts.columns))

    def test_max_column_for_absent_field_is_zero(self):
        """A configured max field absent from the data still gets its column (stable contract), filled with 0."""
        cfg = FeatureConfig(
            numeric_fields=["data.cpu_usage_%"],
            bucket_minutes=5,
            max_numeric_fields=["data.nonexistent_field"],
        )
        builder = WazuhFeatureBuilder(cfg)
        alerts = [
            {"timestamp": "2026-01-01T10:00:00.000Z", "rule": {"level": 3}, "data": {"cpu_usage_%": 70.0}},
        ]
        ts = builder.build_timeseries(alerts)  # must not raise
        self.assertIn("data.nonexistent_field__max", ts.columns)
        self.assertEqual(ts["data.nonexistent_field__max"].iloc[0], 0.0)


class TestResourceDerivedFeatures(unittest.TestCase):
    """Tests for resource-specific derived features."""

    def _build_ts(self, cpu=0.0, mem=0.0, load1=0.0):
        cfg = FeatureConfig(
            numeric_fields=["rule.level"],
            bucket_minutes=60,
            derived_features=True,
        )
        builder = WazuhFeatureBuilder(cfg)
        alerts = [
            {
                "timestamp": "2026-01-01T10:00:00.000Z",
                "rule": {"level": 3, "groups": []},
                "data": {
                    "cpu_usage_%": cpu,
                    "memory_usage_%": mem,
                    "1min_loadAverage": load1,
                },
            }
        ]
        return builder.build_timeseries(alerts)

    def test_is_cpu_high_when_cpu_over_80(self):
        ts = self._build_ts(cpu=90.0)
        self.assertIn("is_cpu_high", ts.columns)
        self.assertEqual(ts["is_cpu_high"].iloc[0], 1.0)

    def test_is_cpu_high_zero_when_cpu_normal(self):
        ts = self._build_ts(cpu=50.0)
        self.assertEqual(ts["is_cpu_high"].iloc[0], 0.0)

    def test_is_cpu_critical_when_cpu_over_95(self):
        ts = self._build_ts(cpu=97.0)
        self.assertEqual(ts["is_cpu_critical"].iloc[0], 1.0)

    def test_is_memory_high_when_mem_over_80(self):
        ts = self._build_ts(mem=85.0)
        self.assertIn("is_memory_high", ts.columns)
        self.assertEqual(ts["is_memory_high"].iloc[0], 1.0)

    def test_is_memory_critical_when_mem_over_95(self):
        ts = self._build_ts(mem=96.0)
        self.assertEqual(ts["is_memory_critical"].iloc[0], 1.0)

    def test_is_high_load_when_load_over_4(self):
        ts = self._build_ts(load1=5.0)
        self.assertIn("is_high_load", ts.columns)
        self.assertEqual(ts["is_high_load"].iloc[0], 1.0)

    def test_is_high_load_zero_when_load_normal(self):
        ts = self._build_ts(load1=1.5)
        self.assertEqual(ts["is_high_load"].iloc[0], 0.0)

    def test_resource_features_absent_when_data_missing(self):
        """Alerts without data block default to 0.0 for resource features."""
        cfg = FeatureConfig(numeric_fields=["rule.level"], bucket_minutes=60)
        builder = WazuhFeatureBuilder(cfg)
        alerts = [{"timestamp": "2026-01-01T10:00:00.000Z", "rule": {"level": 5}}]
        ts = builder.build_timeseries(alerts)
        for col in ("is_cpu_high", "is_memory_high", "is_high_load"):
            self.assertIn(col, ts.columns)
            self.assertEqual(ts[col].iloc[0], 0.0)


if __name__ == "__main__":
    unittest.main()
