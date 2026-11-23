"""
Unit tests for SONAR scenario system.

Tests for:
- TrainingScenario, DetectionScenario, and UseCase dataclasses
- UseCase.from_yaml() and to_yaml() methods
- cmd_scenario() and helper functions
"""

import json
import tempfile
import unittest

from sonar.paths import default_models_dir
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch, call

import pandas as pd
import yaml

from sonar.scenario import TrainingScenario, DetectionScenario, UseCase
from sonar.config import PipelineConfig


class TestTrainingScenario(unittest.TestCase):
    """Test TrainingScenario dataclass initialization and defaults."""

    def test_default_values(self):
        """Test all default values."""
        ts = TrainingScenario()
        assert ts.lookback_hours == 24
        assert ts.numeric_fields == ["rule.level"]
        assert ts.categorical_fields == []
        assert ts.categorical_top_k == 10
        assert ts.bucket_minutes == 5
        assert ts.sliding_window == 200
        assert ts.device == "cpu"
        assert ts.extra_params == {}
        assert not hasattr(ts, "fill_with_synthetic")  # synthetic fill was removed

    def test_custom_values(self):
        """Test custom initialization."""
        ts = TrainingScenario(
            lookback_hours=48,
            numeric_fields=["rule.level", "data.srcport"],
            categorical_fields=["rule.id"],
            categorical_top_k=20,
            bucket_minutes=10,
            sliding_window=150,
            device="cuda",
        )
        assert ts.lookback_hours == 48
        assert ts.numeric_fields == ["rule.level", "data.srcport"]
        assert ts.categorical_fields == ["rule.id"]
        assert ts.categorical_top_k == 20
        assert ts.bucket_minutes == 10
        assert ts.sliding_window == 150
        assert ts.device == "cuda"

    def test_extra_params(self):
        """Test extra_params dictionary."""
        extra = {"learning_rate": 0.001, "epochs": 10}
        ts = TrainingScenario(extra_params=extra)
        assert ts.extra_params == extra


class TestDetectionScenario(unittest.TestCase):
    """Test DetectionScenario dataclass initialization and defaults."""

    def test_default_values(self):
        """Test all default values."""
        ds = DetectionScenario()
        assert ds.mode == "historical"
        assert ds.lookback_minutes == 10
        assert ds.polling_interval_seconds is None
        assert ds.threshold is None
        assert ds.print_payloads is False
        assert ds.dry_run is False
        assert ds.payload_dir is None

    def test_custom_values(self):
        """Test custom initialization."""
        ds = DetectionScenario(
            mode="realtime",
            lookback_minutes=30,
            polling_interval_seconds=300,
            threshold=0.6,
            print_payloads=True,
            dry_run=True,
            payload_dir="/tmp/payloads",
        )
        assert ds.mode == "realtime"
        assert ds.lookback_minutes == 30
        assert ds.polling_interval_seconds == 300
        assert ds.threshold == 0.6
        assert ds.print_payloads is True
        assert ds.dry_run is True
        assert ds.payload_dir == "/tmp/payloads"

    def test_mode_validation(self):
        """Test that mode accepts only valid values."""
        # These should work
        DetectionScenario(mode="historical")
        DetectionScenario(mode="batch")
        DetectionScenario(mode="realtime")


class TestUseCase(unittest.TestCase):
    """Test UseCase dataclass and YAML I/O."""

    def test_default_initialization(self):
        """Test default initialization."""
        uc = UseCase(name="Test Scenario")
        assert uc.name == "Test Scenario"
        assert uc.description == ""
        assert uc.enabled is True
        assert isinstance(uc.training, TrainingScenario)
        assert isinstance(uc.detection, DetectionScenario)

    def test_custom_initialization(self):
        """Test custom initialization with sub-configs."""
        ts = TrainingScenario(lookback_hours=48)
        ds = DetectionScenario(mode="batch")
        uc = UseCase(
            name="Custom Scenario",
            description="Test description",
            training=ts,
            detection=ds,
            enabled=True,
        )
        assert uc.name == "Custom Scenario"
        assert uc.description == "Test description"
        assert uc.training.lookback_hours == 48
        assert uc.detection.mode == "batch"

    def test_from_yaml_minimal(self):
        """Test loading minimal YAML."""
        yaml_content = """
name: "Minimal Scenario"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            yaml_path = f.name

        try:
            uc = UseCase.from_yaml(yaml_path)
            assert uc.name == "Minimal Scenario"
            assert uc.description == ""
            assert uc.enabled is True
            assert uc.training.lookback_hours == 24
            assert uc.detection.mode == "historical"
        finally:
            Path(yaml_path).unlink()

    def test_from_yaml_complete(self):
        """Test loading complete YAML with all options."""
        yaml_content = """
name: "Complete Scenario"
description: "Full configuration"
enabled: true

training:
  lookback_hours: 48
  numeric_fields:
    - "rule.level"
    - "data.srcport"
  categorical_fields:
    - "rule.id"
  categorical_top_k: 20
  bucket_minutes: 10
  sliding_window: 150
  device: "cuda"
  fill_with_synthetic: true
  synthetic_count: 500
  synthetic_mode: "copy"
  synthetic_level: 4
  synthetic_srcip: "10.0.0.1"

detection:
  mode: "realtime"
  lookback_minutes: 30
  polling_interval_seconds: 300
  fill_with_synthetic: true
  synthetic_count: 100
  print_payloads: true
  dry_run: true
  payload_dir: "/tmp/payloads"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            yaml_path = f.name

        try:
            with self.assertLogs("sonar.scenario", level="WARNING") as logs:
                uc = UseCase.from_yaml(yaml_path)
            assert uc.name == "Complete Scenario"
            assert uc.description == "Full configuration"
            assert uc.enabled is True
            
            # Training config
            assert uc.training.lookback_hours == 48
            assert uc.training.numeric_fields == ["rule.level", "data.srcport"]
            assert uc.training.categorical_fields == ["rule.id"]
            assert uc.training.categorical_top_k == 20
            assert uc.training.bucket_minutes == 10
            assert uc.training.sliding_window == 150
            assert uc.training.device == "cuda"
            # The removed synthetic-fill keys are reported as obsolete, in both sections
            obsolete = [line for line in logs.output if "obsolete key" in line]
            assert len(obsolete) == 7, logs.output
            assert all("synthetic fill was removed" in line for line in obsolete)
            
            # Detection config
            assert uc.detection.mode == "realtime"
            assert uc.detection.lookback_minutes == 30
            assert uc.detection.polling_interval_seconds == 300
            assert uc.detection.print_payloads is True
            assert uc.detection.dry_run is True
            assert uc.detection.payload_dir == "/tmp/payloads"
        finally:
            Path(yaml_path).unlink()

    def _load(self, yaml_content):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            path = f.name
        try:
            return UseCase.from_yaml(path)
        finally:
            Path(path).unlink()

    def test_threshold_is_a_severity_between_0_and_1(self):
        assert self._load("detection:\n  threshold: 0.4\n").detection.threshold == 0.4
        assert self._load("detection:\n  threshold: null\n").detection.threshold is None
        assert self._load("detection:\n  mode: historical\n").detection.threshold is None
        with self.assertRaises(ValueError):
            self._load("detection:\n  threshold: 1.4\n")
        with self.assertRaises(ValueError):
            self._load("detection:\n  threshold: high\n")

    def test_realtime_delivery_settings(self):
        detection = self._load("detection:\n  mode: realtime\n").detection
        assert (detection.ingest_delay_seconds, detection.max_consecutive_failures) == (60, 5)
        detection = self._load("detection:\n  ingest_delay_seconds: 0\n  max_consecutive_failures: 1\n").detection
        assert (detection.ingest_delay_seconds, detection.max_consecutive_failures) == (0, 1)
        for bad in ("ingest_delay_seconds: -1", "max_consecutive_failures: 0", "ingest_delay_seconds: soon"):
            with self.assertRaises(ValueError):
                self._load(f"detection:\n  {bad}\n")

    def test_output_section_reaches_the_config(self):
        from sonar.cli import apply_scenario_to_config, load_config

        with self.assertNoLogs("sonar.scenario", "WARNING"):
            uc = self._load("name: s\noutput:\n  state_dir: /var/lib/sonar/state\n")
        cfg = load_config(None)
        apply_scenario_to_config(cfg, uc, {"output": {"state_dir": "/var/lib/sonar/state"}})
        assert cfg.output.state_dir == "/var/lib/sonar/state"

    def test_from_yaml_file_not_found(self):
        """Test handling of missing YAML file."""
        with self.assertRaises(ValueError) as ctx:
            UseCase.from_yaml("/nonexistent/path/scenario.yaml")
        assert "not found" in str(ctx.exception).lower()

    def test_from_yaml_invalid_yaml(self):
        """Test handling of invalid YAML syntax."""
        yaml_content = """
name: Scenario
invalid: [unclosed
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            yaml_path = f.name

        try:
            with self.assertRaises(ValueError):
                UseCase.from_yaml(yaml_path)
        finally:
            Path(yaml_path).unlink()

    def test_from_yaml_not_dict(self):
        """Test handling of YAML that's not a dict."""
        yaml_content = """
- item1
- item2
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            yaml_path = f.name

        try:
            with self.assertRaises(ValueError):
                UseCase.from_yaml(yaml_path)
        finally:
            Path(yaml_path).unlink()

    def test_to_yaml(self):
        """Test saving use case to YAML."""
        uc = UseCase(
            name="Test Scenario",
            description="Test description",
            enabled=True,
            training=TrainingScenario(lookback_hours=48, device="cuda"),
            detection=DetectionScenario(mode="batch", lookback_minutes=20),
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml_path = f.name

        try:
            uc.to_yaml(yaml_path)

            # Verify the file was created and can be parsed
            with open(yaml_path, "r") as f:
                saved_data = yaml.safe_load(f)

            assert saved_data["name"] == "Test Scenario"
            assert saved_data["description"] == "Test description"
            assert saved_data["enabled"] is True
            assert saved_data["training"]["lookback_hours"] == 48
            assert saved_data["training"]["device"] == "cuda"
            assert saved_data["detection"]["mode"] == "batch"
            assert saved_data["detection"]["lookback_minutes"] == 20
        finally:
            Path(yaml_path).unlink()

    def test_to_yaml_and_from_yaml_roundtrip(self):
        """Test saving and reloading YAML preserves data."""
        original = UseCase(
            name="Roundtrip Test",
            description="Testing save and reload",
            enabled=True,
            training=TrainingScenario(
                lookback_hours=72,
                numeric_fields=["rule.level", "data.srcport"],
                categorical_fields=["rule.id", "rule.groups"],
                sliding_window=300,
            ),
            detection=DetectionScenario(
                mode="realtime",
                lookback_minutes=15,
                polling_interval_seconds=60,
                print_payloads=True,
            ),
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml_path = f.name

        try:
            # Save and reload
            original.to_yaml(yaml_path)
            reloaded = UseCase.from_yaml(yaml_path)

            # Verify all fields match
            assert reloaded.name == original.name
            assert reloaded.description == original.description
            assert reloaded.enabled == original.enabled
            assert reloaded.training.lookback_hours == original.training.lookback_hours
            assert reloaded.training.numeric_fields == original.training.numeric_fields
            assert reloaded.training.categorical_fields == original.training.categorical_fields
            assert reloaded.training.sliding_window == original.training.sliding_window
            assert reloaded.detection.mode == original.detection.mode
            assert reloaded.detection.lookback_minutes == original.detection.lookback_minutes
            assert reloaded.detection.polling_interval_seconds == original.detection.polling_interval_seconds
            assert reloaded.detection.print_payloads == original.detection.print_payloads
        finally:
            Path(yaml_path).unlink()


class TestCmdScenario(unittest.TestCase):
    """Test cmd_scenario and related CLI functions."""

    def setUp(self):
        """Set up test fixtures."""
        self.scenario_yaml = """
name: "Test Scenario"
description: "Testing scenario execution"
enabled: true

training:
  lookback_hours: 24
  numeric_fields:
    - "rule.level"
  bucket_minutes: 5
  sliding_window: 200

detection:
  mode: "historical"
  lookback_minutes: 10
"""

    @patch("sonar.cli.load_config")
    @patch("sonar.cli._execute_training_phase")
    def test_cmd_scenario_batch_mode(self, mock_train, mock_load_cfg):
        """Test cmd_scenario with training AND detection sections (both phases execute)."""
        # Import here to avoid circular imports
        from sonar.cli import cmd_scenario
        import argparse

        # Create actual YAML file with both sections
        yaml_content = """
name: "Test Scenario"
training:
  lookback_hours: 24
detection:
  mode: "batch"
  lookback_minutes: 10
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            yaml_path = f.name

        try:
            mock_load_cfg.return_value = MagicMock()
            mock_train.return_value = 0

            args = argparse.Namespace(
                use_case=yaml_path,
                config=None,
                mode=None,
                print_payloads=False,
                dry_run=False,
                payload_dir="./payloads",
                debug=False,
                ship=False,
            )

            with patch("sonar.cli.MVADModelEngine") as mock_engine:
                with patch("sonar.cli._execute_detection_phase") as mock_detect:
                    mock_engine_instance = MagicMock()
                    mock_engine.return_value = mock_engine_instance
                    mock_detect.return_value = 0

                    result = cmd_scenario(args)

                    # Should have called training phase
                    mock_train.assert_called_once()
                    
                    # Should have called detection phase
                    mock_detect.assert_called_once()
                    
                    assert result == 0
        finally:
            Path(yaml_path).unlink()

    @patch("sonar.cli.load_config")
    @patch("sonar.cli.MVADModelEngine")
    @patch("sonar.cli._execute_detection_phase")
    def test_cmd_scenario_historical_mode(
        self, mock_detect, mock_engine, mock_load_cfg
    ):
        """Test cmd_scenario with detection-only section (skips training)."""
        from sonar.cli import cmd_scenario
        import argparse

        # Create YAML with detection section only
        yaml_content = """
name: "Test Scenario"
detection:
  mode: "historical"
  lookback_minutes: 10
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            yaml_path = f.name

        try:
            mock_load_cfg.return_value = MagicMock(model_path="./mvad_model.pkl")
            mock_engine_instance = MagicMock()
            mock_engine.return_value = mock_engine_instance
            mock_detect.return_value = 0

            args = argparse.Namespace(
                use_case=yaml_path,
                config=None,
                mode=None,
                print_payloads=False,
                dry_run=False,
                payload_dir="./payloads",
                debug=False,
                ship=False,
            )

            result = cmd_scenario(args)

            # Detection-only: the detection phase (which loads the model) runs in the YAML's mode
            mock_detect.assert_called_once()
            self.assertEqual(mock_detect.call_args.args[3], "historical")
            assert result == 0
        finally:
            Path(yaml_path).unlink()

    def test_cmd_scenario_disabled(self):
        """Test cmd_scenario skips disabled scenarios."""
        from sonar.cli import cmd_scenario
        import argparse

        # Create YAML with disabled scenario
        yaml_content = """
name: "Disabled Scenario"
enabled: false
training:
  lookback_hours: 24
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            yaml_path = f.name

        try:
            args = argparse.Namespace(
                use_case=yaml_path,
                config=None,
                mode=None,
                print_payloads=False,
                dry_run=False,
                payload_dir="./payloads",
                debug=False,
                ship=False,
            )

            result = cmd_scenario(args)

            # Should return 0 (success) for disabled scenarios
            assert result == 0
        finally:
            Path(yaml_path).unlink()

    def test_cmd_scenario_yaml_error(self):
        """Test cmd_scenario handles YAML loading errors."""
        from sonar.cli import cmd_scenario
        import argparse

        # Create invalid YAML
        yaml_content = """
name: Test
invalid: [unclosed
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            yaml_path = f.name

        try:
            args = argparse.Namespace(
                use_case=yaml_path,
                config=None,
                mode=None,
                print_payloads=False,
                dry_run=False,
                payload_dir="./payloads",
                debug=False,
                ship=False,
            )

            result = cmd_scenario(args)

            # Should return 1 (error)
            assert result == 1
        finally:
            Path(yaml_path).unlink()

    def test_cmd_scenario_mode_override(self):
        """Test cmd_scenario respects --mode override when detection section exists."""
        from sonar.cli import cmd_scenario
        import argparse

        # Create YAML with detection section
        yaml_content = """
name: "Test Scenario"
detection:
  mode: "historical"
  lookback_minutes: 10
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            yaml_path = f.name

        try:
            with patch("sonar.cli.load_config"):
                with patch("sonar.cli.MVADModelEngine"):
                    with patch("sonar.cli._execute_detection_phase") as mock_detect:
                        mock_detect.return_value = 0

                        args = argparse.Namespace(
                            use_case=yaml_path,
                            config=None,
                            mode="batch",  # Override to batch
                            print_payloads=False,
                            dry_run=False,
                            payload_dir="./payloads",
                            debug=False,
                            ship=False,
                        )

                        # The mode override should be passed to detection phase
                        cmd_scenario(args)
        finally:
            Path(yaml_path).unlink()

    @patch("sonar.cli.load_config")
    @patch("sonar.cli._execute_training_phase")
    def test_cmd_scenario_training_only(self, mock_train, mock_load_cfg):
        """Test cmd_scenario with training-only section (no detection)."""
        from sonar.cli import cmd_scenario
        import argparse

        # Create YAML with training section only
        yaml_content = """
name: "Test Scenario"
training:
  lookback_hours: 24
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            yaml_path = f.name

        try:
            mock_load_cfg.return_value = MagicMock()
            mock_train.return_value = 0

            args = argparse.Namespace(
                use_case=yaml_path,
                config=None,
                mode=None,
                print_payloads=False,
                dry_run=False,
                payload_dir="./payloads",
                debug=False,
                ship=False,
            )

            result = cmd_scenario(args)

            # Should have called training phase only
            mock_train.assert_called_once()
            
            assert result == 0
        finally:
            Path(yaml_path).unlink()

    @patch("sonar.cli.load_config")
    @patch("sonar.cli._execute_detection_phase")
    def test_cmd_scenario_detection_only(self, mock_detect, mock_load_cfg):
        """Test cmd_scenario with detection-only section (no training)."""
        from sonar.cli import cmd_scenario
        import argparse

        # Create YAML with detection section only
        yaml_content = """
name: "Test Scenario"
detection:
  mode: "historical"
  lookback_minutes: 10
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            yaml_path = f.name

        try:
            mock_load_cfg.return_value = MagicMock(model_path="./mvad_model.pkl")
            mock_detect.return_value = 0

            args = argparse.Namespace(
                use_case=yaml_path,
                config=None,
                mode=None,
                print_payloads=False,
                dry_run=False,
                payload_dir="./payloads",
                debug=False,
                ship=False,
            )

            with patch("sonar.cli.MVADModelEngine") as mock_engine:
                mock_engine_instance = MagicMock()
                mock_engine.return_value = mock_engine_instance

                result = cmd_scenario(args)

                # Should have loaded model (no training section)
                # The detection phase loads the model itself

                # Should have called detection phase
                mock_detect.assert_called_once()
                
                assert result == 0
        finally:
            Path(yaml_path).unlink()


class TestTrainingScenarioNewFields(unittest.TestCase):
    """Tests for the three fields added to TrainingScenario."""

    def test_derived_features_default_true(self):
        ts = TrainingScenario()
        self.assertTrue(ts.derived_features)

    def test_alert_filter_default_none(self):
        ts = TrainingScenario()
        self.assertIsNone(ts.alert_filter)

    def test_max_numeric_fields_default_empty(self):
        ts = TrainingScenario()
        self.assertEqual(ts.max_numeric_fields, [])

    def test_from_yaml_parses_derived_features_false(self):
        yaml_content = """
name: Test
training:
  derived_features: false
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            yaml_path = f.name
        try:
            uc = UseCase.from_yaml(yaml_path)
            self.assertFalse(uc.training.derived_features)
        finally:
            Path(yaml_path).unlink()

    def test_from_yaml_parses_alert_filter(self):
        yaml_content = """
name: Test
training:
  alert_filter:
    terms:
      rule.groups:
        - performance_metric
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            yaml_path = f.name
        try:
            uc = UseCase.from_yaml(yaml_path)
            self.assertEqual(
                uc.training.alert_filter,
                {"terms": {"rule.groups": ["performance_metric"]}},
            )
        finally:
            Path(yaml_path).unlink()

    def test_from_yaml_parses_max_numeric_fields(self):
        yaml_content = """
name: Test
training:
  max_numeric_fields:
    - "data.cpu_usage_%"
    - "data.memory_usage_%"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            yaml_path = f.name
        try:
            uc = UseCase.from_yaml(yaml_path)
            self.assertEqual(uc.training.max_numeric_fields, ["data.cpu_usage_%", "data.memory_usage_%"])
        finally:
            Path(yaml_path).unlink()

    def test_to_yaml_roundtrip_new_fields(self):
        """New fields survive a YAML write/read roundtrip."""
        ts = TrainingScenario(
            derived_features=False,
            alert_filter={"terms": {"rule.groups": ["performance_metric"]}},
            max_numeric_fields=["data.cpu_usage_%"],
        )
        uc = UseCase(name="Roundtrip", training=ts)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml_path = f.name
        try:
            uc.to_yaml(yaml_path)
            uc2 = UseCase.from_yaml(yaml_path)
            self.assertFalse(uc2.training.derived_features)
            self.assertEqual(uc2.training.alert_filter, {"terms": {"rule.groups": ["performance_metric"]}})
            self.assertEqual(uc2.training.max_numeric_fields, ["data.cpu_usage_%"])
        finally:
            Path(yaml_path).unlink()


class TestScenarioConfigAlignment(unittest.TestCase):
    """All three CLI entry points apply the same scenario keys."""

    YAML = """
name: Align
model_name: align_model
wazuh:
  base_url: "https://scenario-host:9200"
training:
  lookback_hours: 48
  numeric_fields: ["rule.level"]
  categorical_fields:
  sliding_window: 50
  derived_features: false
  alert_filter: {"terms": {"rule.groups": ["sshd"]}}
  max_numeric_fields: ["rule.level"]
detection:
  lookback_minutes: 300
  threshold: 0.6
  min_consecutive: 2
"""

    def setUp(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(self.YAML)
            self.path = f.name

    def tearDown(self):
        Path(self.path).unlink()

    def test_empty_yaml_key_uses_default(self):
        uc = UseCase.from_yaml(self.path)
        self.assertEqual(uc.training.categorical_fields, [])

    def test_empty_training_section_uses_defaults(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("name: Empty\ntraining:\ndetection:\n")
            path = f.name
        try:
            uc = UseCase.from_yaml(path)
            self.assertEqual(uc.training.sliding_window, 200)
            self.assertIsNone(uc.detection.threshold)  # MVAD's own decision unless set
        finally:
            Path(path).unlink()

    def test_load_scenario_for_phase_applies_all_feature_keys(self):
        from sonar.cli import load_scenario_for_phase

        for phase in ("training", "detection"):
            cfg, _ = load_scenario_for_phase(self.path, phase, None)
            self.assertFalse(cfg.features.derived_features, phase)
            self.assertEqual(cfg.features.alert_filter, {"terms": {"rule.groups": ["sshd"]}}, phase)
            self.assertEqual(list(cfg.features.max_numeric_fields), ["rule.level"], phase)
            self.assertEqual(cfg.mvad.sliding_window, 50, phase)
            self.assertEqual(cfg.wazuh.base_url, "https://scenario-host:9200", phase)
            self.assertEqual(cfg.model_path, str(default_models_dir() / "align_model"), phase)

    def test_cmd_scenario_applies_wazuh_section(self):
        from sonar import cli

        captured = {}

        def fake_training(cfg, training, args):
            captured["cfg"] = cfg
            return 0

        args = MagicMock(use_case=self.path, config=None, mode=None, debug=False)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(self.YAML.replace("detection:", "unused_detection:"))
            path = f.name
        try:
            args.use_case = path
            with patch("sonar.cli._execute_training_phase", side_effect=fake_training):
                self.assertEqual(cli.cmd_scenario(args), 0)
        finally:
            Path(path).unlink()
        self.assertEqual(captured["cfg"].wazuh.base_url, "https://scenario-host:9200")
        self.assertEqual(captured["cfg"].mvad.sliding_window, 50)

    def _run_cmd(self, cmd, expected_exit=0, **overrides):
        """Run cmd_train/cmd_detect with a mocked client (no alerts) and return the search window in minutes."""
        from sonar import cli

        client = MagicMock()
        client.check_connection.return_value = True
        client.search_alerts.return_value = []
        args = MagicMock(scenario=self.path, config=None, debug=False, model_name=None, fill_with_synthetic=False,
                         synthetic_count=None, synthetic_mode="constant", synthetic_level=None, synthetic_srcip=None,
                         lookback_hours=None, lookback_minutes=None, print_payloads=False, dry_run=False, payload_dir=None, agent=None)
        for k, v in overrides.items():
            setattr(args, k, v)
        engine = MagicMock(context_buckets=0, min_detection_points=1, feature_config=None)
        with patch("sonar.cli.WazuhIndexerClient", return_value=client), patch("sonar.cli.MVADModelEngine", return_value=engine):
            self.assertEqual(cmd(args), expected_exit)
        start, end = client.search_alerts.call_args.args[:2]
        self.assertEqual(client.search_alerts.call_args.kwargs.get("query"), {"terms": {"rule.groups": ["sshd"]}})
        return round((end - start).total_seconds() / 60)

    def test_train_uses_scenario_lookback_unless_cli_given(self):
        from sonar.cli import cmd_train

        # No alerts: training fails (exit 1) after searching the right window.
        self.assertEqual(self._run_cmd(cmd_train, expected_exit=1), 48 * 60)
        self.assertEqual(self._run_cmd(cmd_train, expected_exit=1, lookback_hours=24), 24 * 60)

    def test_detect_uses_scenario_lookback_unless_cli_given(self):
        from sonar.cli import cmd_detect

        # No alerts: nothing could be scored (exit 2). With no context needed, the search
        # window is exactly the scored window.
        self.assertEqual(self._run_cmd(cmd_detect, expected_exit=2), 300)
        self.assertEqual(self._run_cmd(cmd_detect, expected_exit=2, lookback_minutes=10), 10)


if __name__ == "__main__":
    unittest.main()
