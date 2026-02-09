"""
Consolidated unit tests for MVADModelEngine and WazuhFeatureBuilder.

Tests core functionality of the MVAD engine and feature extraction pipeline.
"""

import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pandas as pd

from sonar.config import MVADConfig, FeatureConfig, PipelineConfig
from sonar.engine import MVADModelEngine
from sonar.features import WazuhFeatureBuilder


class TestMVADModelEngine(unittest.TestCase):
    """Test MVADModelEngine training and prediction."""

    def setUp(self):
        """Set up test fixtures."""
        self.cfg = PipelineConfig()
        self.engine = MVADModelEngine(self.cfg)

    @patch("sonar.engine.MultivariateAnomalyDetector")
    def test_train_success(self, mock_mad_class):
        """Test successful model training."""
        mock_model = MagicMock()
        mock_mad_class.return_value = mock_model

        # Create training data with enough samples
        ts_data = pd.DataFrame({
            "rule.level": list(range(250))
        })

        self.engine.train(ts_data)

        # Verify model was created and fit was called
        mock_mad_class.assert_called_once()
        mock_model.fit.assert_called_once()
        self.assertIsNotNone(self.engine.model)

    def test_train_raises_on_sliding_window_too_large(self):
        """Test that training fails when sliding_window > num_samples."""
        self.cfg.mvad.sliding_window = 300
        ts_data = pd.DataFrame({
            "rule.level": list(range(250))
        })

        with self.assertRaises(ValueError) as ctx:
            self.engine.train(ts_data)
        self.assertIn("sliding_window", str(ctx.exception))

    def test_train_raises_on_empty_data(self):
        """Test that training fails with empty data."""
        ts_data = pd.DataFrame()

        with self.assertRaises(ValueError):
            self.engine.train(ts_data)

    @patch("sonar.engine.MultivariateAnomalyDetector")
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
        ts_data = pd.DataFrame({
            "rule.level": list(range(250))
        })
        self.engine.train(ts_data)

        # Now predict
        pred_data = pd.DataFrame({
            "rule.level": [5, 6, 15]
        })
        results = self.engine.predict(pred_data)

        # Results should be a list
        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 3)
        # Each result should have expected keys
        self.assertIn("is_anomaly", results[0])
        self.assertIn("score", results[0])

    def test_predict_raises_without_model(self):
        """Test that prediction fails if model not trained."""
        pred_data = pd.DataFrame({
            "rule.level": [5, 6, 7]
        })

        with self.assertRaises(RuntimeError) as ctx:
            self.engine.predict(pred_data)
        self.assertIn("not loaded", str(ctx.exception).lower())

    @patch("sonar.engine.MultivariateAnomalyDetector")
    def test_predict_passes_context_to_model(self, mock_mad_class):
        """Test that context is passed to model if it accepts it."""
        mock_model = MagicMock()
        mock_model.predict = MagicMock()
        # Mock MVAD's actual return format
        mock_model.predict.return_value = [
            {"index": pd.Timestamp.now(), "is_anomaly": False, "score": 0.1, "severity": 0.0, "interpretation": []}
        ]
        mock_mad_class.return_value = mock_model

        # Train
        ts_data = pd.DataFrame({"rule.level": list(range(250))})
        self.engine.train(ts_data)

        # Predict
        pred_data = pd.DataFrame({"rule.level": [5]})
        self.engine.predict(pred_data)

        # Check if context was passed as a keyword argument
        call_args = mock_model.predict.call_args
        # Should be called with data= and context= kwargs
        self.assertIn("context", call_args[1])
        self.assertIn("pipeline_config", call_args[1]["context"])

    @patch("sonar.engine.MultivariateAnomalyDetector")
    def test_predict_handles_model_without_context_param(self, mock_mad_class):
        """Test fallback when model doesn't accept context parameter."""
        # Create a model that raises TypeError when context is passed
        mock_model = MagicMock()
        
        def predict_no_context(data, context=None):
            if context is not None:
                raise TypeError("predict() got an unexpected keyword argument 'context'")
            # Mock MVAD's actual return format
            return [
                {"index": pd.Timestamp.now(), "is_anomaly": False, "score": 0.1, "severity": 0.0, "interpretation": []}
            ]
        
        mock_model.predict = predict_no_context
        mock_mad_class.return_value = mock_model

        # Train
        ts_data = pd.DataFrame({"rule.level": list(range(250))})
        self.engine.train(ts_data)

        # Predict should fallback to calling without context
        pred_data = pd.DataFrame({"rule.level": [5]})
        results = self.engine.predict(pred_data)
        
        # Results should be a list
        self.assertIsInstance(results, list)
        self.assertIn("is_anomaly", results[0])

    @patch("sonar.engine.MultivariateAnomalyDetector")
    def test_mvad_config_params_passed_to_model(self, mock_mad_class):
        """Test that MVAD config parameters are passed to model."""
        mock_model = MagicMock()
        mock_mad_class.return_value = mock_model

        # Custom config
        self.cfg.mvad.sliding_window = 100
        self.cfg.mvad.device = "cuda"
        self.cfg.mvad.extra_params = {"custom_param": "value"}

        engine = MVADModelEngine(self.cfg)
        ts_data = pd.DataFrame({"rule.level": list(range(150))})
        engine.train(ts_data)

        # Check that model was instantiated (no params in __init__)
        mock_mad_class.assert_called_once_with()
        
        # Check that model.fit was called with data and params
        mock_model.fit.assert_called_once()
        fit_call_args = mock_model.fit.call_args
        self.assertEqual(fit_call_args[1]["params"]["sliding_window"], 100)
        self.assertEqual(fit_call_args[1]["params"]["device"], "cuda")
        self.assertEqual(fit_call_args[1]["params"]["custom_param"], "value")


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

        # Should only have basic numeric fields (no derived features)
        self.assertEqual(list(ts_data.columns), ["rule.level"])


if __name__ == "__main__":
    unittest.main()
