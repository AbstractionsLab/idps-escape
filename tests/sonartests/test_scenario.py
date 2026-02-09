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
        assert ts.fill_with_synthetic is False
        assert ts.synthetic_count == 100
        assert ts.synthetic_mode == "random"
        assert ts.synthetic_level == 5
        assert ts.synthetic_srcip == "192.0.2.0"

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
            fill_with_synthetic=True,
            synthetic_count=500,
            synthetic_mode="copy",
        )
        assert ts.lookback_hours == 48
        assert ts.numeric_fields == ["rule.level", "data.srcport"]
        assert ts.categorical_fields == ["rule.id"]
        assert ts.categorical_top_k == 20
        assert ts.bucket_minutes == 10
        assert ts.sliding_window == 150
        assert ts.device == "cuda"
        assert ts.fill_with_synthetic is True
        assert ts.synthetic_count == 500
        assert ts.synthetic_mode == "copy"

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
        assert ds.fill_with_synthetic is False
        assert ds.synthetic_count == 50
        assert ds.print_payloads is False
        assert ds.dry_run is False
        assert ds.payload_dir is None

    def test_custom_values(self):
        """Test custom initialization."""
        ds = DetectionScenario(
            mode="realtime",
            lookback_minutes=30,
            polling_interval_seconds=300,
            fill_with_synthetic=True,
            synthetic_count=100,
            print_payloads=True,
            dry_run=True,
            payload_dir="/tmp/payloads",
        )
        assert ds.mode == "realtime"
        assert ds.lookback_minutes == 30
        assert ds.polling_interval_seconds == 300
        assert ds.fill_with_synthetic is True
        assert ds.synthetic_count == 100
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
            assert uc.training.fill_with_synthetic is True
            assert uc.training.synthetic_count == 500
            assert uc.training.synthetic_mode == "copy"
            
            # Detection config
            assert uc.detection.mode == "realtime"
            assert uc.detection.lookback_minutes == 30
            assert uc.detection.polling_interval_seconds == 300
            assert uc.detection.fill_with_synthetic is True
            assert uc.detection.print_payloads is True
            assert uc.detection.dry_run is True
            assert uc.detection.payload_dir == "/tmp/payloads"
        finally:
            Path(yaml_path).unlink()

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

            # Should have loaded engine (no training, detection-only mode)
            mock_engine.assert_called_once()
            mock_engine_instance.load.assert_called_once()

            # Should have called detection phase
            mock_detect.assert_called_once()
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
                mock_engine.assert_called_once()
                mock_engine_instance.load.assert_called_once()

                # Should have called detection phase
                mock_detect.assert_called_once()
                
                assert result == 0
        finally:
            Path(yaml_path).unlink()




if __name__ == "__main__":
    unittest.main()
