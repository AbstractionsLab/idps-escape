"""
Unit tests for SONAR configuration dataclasses.

Tests WazuhIndexerConfig, MVADConfig, FeatureConfig, DebugConfig, and PipelineConfig.
"""

import unittest
from sonar.config import (
    WazuhIndexerConfig,
    MVADConfig,
    FeatureConfig,
    DebugConfig,
    PipelineConfig,
)


class TestWazuhIndexerConfig(unittest.TestCase):
    """Test WazuhIndexerConfig initialization and defaults."""

    def test_default_values(self):
        """Test all default configuration values."""
        cfg = WazuhIndexerConfig()
        self.assertEqual(cfg.base_url, "https://localhost:9200")
        self.assertEqual(cfg.username, "admin")
        self.assertEqual(cfg.password, "admin")
        self.assertFalse(cfg.verify_ssl)
        self.assertEqual(cfg.alerts_index_pattern, "wazuh-alerts-*")
        self.assertEqual(cfg.anomalies_index, "wazuh-anomalies-mvad")

    def test_custom_values(self):
        """Test custom configuration."""
        cfg = WazuhIndexerConfig(
            base_url="https://os.example.com:9200",
            username="test_user",
            password="test_pass",
            verify_ssl=True,
            alerts_index_pattern="custom-alerts-*",
            anomalies_index="custom-anomalies",
        )
        self.assertEqual(cfg.base_url, "https://os.example.com:9200")
        self.assertEqual(cfg.username, "test_user")
        self.assertEqual(cfg.password, "test_pass")
        self.assertTrue(cfg.verify_ssl)
        self.assertEqual(cfg.alerts_index_pattern, "custom-alerts-*")
        self.assertEqual(cfg.anomalies_index, "custom-anomalies")


class TestMVADConfig(unittest.TestCase):
    """Test MVADConfig initialization and conversion."""

    def test_default_values(self):
        """Test default MVAD configuration."""
        cfg = MVADConfig()
        self.assertEqual(cfg.sliding_window, 200)
        self.assertEqual(cfg.device, "cpu")
        self.assertEqual(cfg.extra_params, {})

    def test_custom_values(self):
        """Test custom MVAD configuration."""
        cfg = MVADConfig(
            sliding_window=100,
            device="cuda",
            extra_params={"learning_rate": 0.001, "epochs": 50},
        )
        self.assertEqual(cfg.sliding_window, 100)
        self.assertEqual(cfg.device, "cuda")
        self.assertEqual(cfg.extra_params["learning_rate"], 0.001)
        self.assertEqual(cfg.extra_params["epochs"], 50)

    def test_to_params(self):
        """Test conversion to parameter dictionary."""
        cfg = MVADConfig(sliding_window=150, device="cuda")
        params = cfg.to_params()
        self.assertEqual(params["sliding_window"], 150)
        self.assertEqual(params["device"], "cuda")

    def test_to_params_includes_extras(self):
        """Test that extra_params are merged into to_params output."""
        cfg = MVADConfig(
            sliding_window=200,
            extra_params={"custom_param": "value", "threshold": 0.7},
        )
        params = cfg.to_params()
        self.assertEqual(params["sliding_window"], 200)
        self.assertEqual(params["device"], "cpu")
        self.assertEqual(params["custom_param"], "value")
        self.assertEqual(params["threshold"], 0.7)


class TestFeatureConfig(unittest.TestCase):
    """Test FeatureConfig initialization and defaults."""

    def test_default_values(self):
        """Test default feature configuration."""
        cfg = FeatureConfig()
        self.assertEqual(cfg.numeric_fields, ("rule.level",))
        self.assertEqual(cfg.bucket_minutes, 5)
        self.assertEqual(cfg.categorical_fields, ())
        self.assertEqual(cfg.categorical_top_k, 10)
        self.assertTrue(cfg.derived_features)

    def test_custom_numeric_fields(self):
        """Test custom numeric fields."""
        cfg = FeatureConfig(
            numeric_fields=["rule.level", "data.srcport", "data.dstport"]
        )
        self.assertEqual(len(cfg.numeric_fields), 3)
        self.assertIn("rule.level", cfg.numeric_fields)
        self.assertIn("data.srcport", cfg.numeric_fields)

    def test_custom_categorical_fields(self):
        """Test custom categorical fields."""
        cfg = FeatureConfig(
            categorical_fields=["rule.id", "agent.name"],
            categorical_top_k=20,
        )
        self.assertEqual(len(cfg.categorical_fields), 2)
        self.assertEqual(cfg.categorical_top_k, 20)

    def test_bucket_minutes(self):
        """Test custom bucket size."""
        cfg = FeatureConfig(bucket_minutes=10)
        self.assertEqual(cfg.bucket_minutes, 10)

    def test_derived_features_disabled(self):
        """Test disabling derived features."""
        cfg = FeatureConfig(derived_features=False)
        self.assertFalse(cfg.derived_features)


class TestDebugConfig(unittest.TestCase):
    """Test DebugConfig initialization and defaults."""

    def test_default_values(self):
        """Test default debug configuration."""
        cfg = DebugConfig()
        self.assertFalse(cfg.enabled)
        self.assertEqual(cfg.data_dir, "./test_data/synthetic_alerts")
        self.assertEqual(cfg.training_data_file, "normal_baseline.json")
        self.assertEqual(cfg.detection_data_file, "with_anomalies.json")

    def test_custom_values(self):
        """Test custom debug configuration."""
        cfg = DebugConfig(
            enabled=True,
            data_dir="./custom_test_data",
            training_data_file="training.json",
            detection_data_file="detection.json",
        )
        self.assertTrue(cfg.enabled)
        self.assertEqual(cfg.data_dir, "./custom_test_data")
        self.assertEqual(cfg.training_data_file, "training.json")
        self.assertEqual(cfg.detection_data_file, "detection.json")


class TestPipelineConfig(unittest.TestCase):
    """Test PipelineConfig initialization and nested configs."""

    def test_default_initialization(self):
        """Test that all sub-configs are properly initialized."""
        cfg = PipelineConfig()
        self.assertIsInstance(cfg.wazuh, WazuhIndexerConfig)
        self.assertIsInstance(cfg.mvad, MVADConfig)
        self.assertIsInstance(cfg.features, FeatureConfig)
        self.assertIsInstance(cfg.debug, DebugConfig)
        self.assertEqual(cfg.model_path, "./mvad_model.pkl")

    def test_custom_nested_configs(self):
        """Test custom nested configuration objects."""
        wazuh_cfg = WazuhIndexerConfig(base_url="https://custom:9200")
        mvad_cfg = MVADConfig(sliding_window=100)
        feature_cfg = FeatureConfig(bucket_minutes=10)
        debug_cfg = DebugConfig(enabled=True)

        cfg = PipelineConfig(
            wazuh=wazuh_cfg,
            mvad=mvad_cfg,
            features=feature_cfg,
            debug=debug_cfg,
            model_path="./custom_model.pkl",
        )

        self.assertEqual(cfg.wazuh.base_url, "https://custom:9200")
        self.assertEqual(cfg.mvad.sliding_window, 100)
        self.assertEqual(cfg.features.bucket_minutes, 10)
        self.assertTrue(cfg.debug.enabled)
        self.assertEqual(cfg.model_path, "./custom_model.pkl")

    def test_default_nested_values(self):
        """Test that nested configs have their defaults."""
        cfg = PipelineConfig()
        # Check nested defaults
        self.assertEqual(cfg.wazuh.username, "admin")
        self.assertEqual(cfg.mvad.device, "cpu")
        self.assertEqual(cfg.features.bucket_minutes, 5)
        self.assertFalse(cfg.debug.enabled)


if __name__ == "__main__":
    unittest.main()
