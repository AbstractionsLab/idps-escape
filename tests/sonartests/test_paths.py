"""
Path resolution (sonar/paths.py, sonar/cli.py): nothing depends on the working directory.
"""

import ast
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import sonar
from sonar import cli, paths
from sonar.config import PipelineConfig

PACKAGE = Path(sonar.__file__).resolve().parent


class TestHome(unittest.TestCase):
    def test_sonar_home_env_wins(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {"SONAR_HOME": d}):
            self.assertEqual(paths.sonar_home(), Path(d).resolve())
            self.assertEqual(Path(PipelineConfig().model_path), Path(d).resolve() / "models" / "sonar")

    def test_source_checkout_uses_the_package_directory(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SONAR_HOME", None)
            self.assertTrue(paths.is_source_checkout())
            self.assertEqual(paths.sonar_home(), PACKAGE)

    def test_installed_package_uses_dot_sonar(self):
        with patch.dict(os.environ, {}, clear=False), patch.object(paths, "is_source_checkout", return_value=False):
            os.environ.pop("SONAR_HOME", None)
            self.assertEqual(paths.sonar_home(), Path.home() / ".sonar")

    def test_slug(self):
        self.assertEqual(paths.slug("Linux Resource Monitoring!"), "linux_resource_monitoring")
        self.assertEqual(paths.slug("  "), "sonar")

    def test_packaged_scenario(self):
        self.assertEqual(paths.packaged_scenario("linux_resource_monitoring"), PACKAGE / "scenarios" / "linux_resource_monitoring.yaml")
        self.assertIsNone(paths.packaged_scenario("no_such_scenario"))


class TestFileRelativePaths(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name).resolve()
        (self.root / "conf").mkdir()
        (self.root / "scen").mkdir()
        self.config = self.root / "conf" / "sonar.yaml"
        self.config.write_text("models_dir: ../models\nmodel_name: base\noutput:\n  state_dir: state\n  jsonl_path: out/events.jsonl\ndebug:\n  data_dir: data\n")
        self.scenario = self.root / "scen" / "my.yaml"
        self.scenario.write_text("name: My Scenario\ndebug:\n  data_dir: ../scenario-data\ndetection:\n  payload_dir: payloads\n")

    def test_config_paths_are_relative_to_the_config_file(self):
        cfg = cli.load_config(str(self.config))
        self.assertEqual(cfg.model_path, str(self.root / "models" / "base"))
        self.assertEqual(cfg.output.state_dir, str(self.root / "conf" / "state"))
        self.assertEqual(cfg.output.jsonl_path, str(self.root / "conf" / "out" / "events.jsonl"))
        self.assertEqual(cfg.debug.data_dir, str(self.root / "conf" / "data"))

    def test_scenario_paths_are_relative_to_the_scenario_file(self):
        cfg, detection = cli.load_scenario_for_phase(str(self.scenario), "detection", str(self.config))
        self.assertEqual(cfg.debug.data_dir, str(self.root / "scenario-data"))
        self.assertEqual(detection.payload_dir, str(self.root / "scen" / "payloads"))
        # A scenario without model_name gets its name, so train and detect find the same model.
        self.assertEqual(cfg.model_path, str(self.root / "models" / "my_scenario"))

    def test_same_result_from_any_working_directory(self):
        here = os.getcwd()
        results = []
        try:
            for cwd in (self.root, self.root / "scen", Path(tempfile.gettempdir())):
                os.chdir(cwd)
                cfg, _ = cli.load_scenario_for_phase(str(self.scenario), "training", str(self.config))
                results.append((cfg.model_path, cfg.debug.data_dir, cfg.output.state_dir))
        finally:
            os.chdir(here)
        self.assertEqual(len(set(results)), 1)

    def test_default_config_points_at_packaged_debug_data(self):
        cfg = cli.load_config(None)
        self.assertEqual(Path(cfg.debug.data_dir), PACKAGE / "test_data" / "synthetic_alerts")
        self.assertTrue(Path(cfg.debug.data_dir).is_dir())

    def test_packaged_scenario_debug_data_resolves(self):
        cfg, _ = cli.load_scenario_for_phase("linux_resource_monitoring", "training", None)
        self.assertEqual(Path(cfg.debug.data_dir), PACKAGE / "test_data" / "resource_monitoring")
        self.assertTrue((Path(cfg.debug.data_dir) / cfg.debug.training_data_file).is_file())

    def test_deprecated_model_path_still_works(self):
        self.config.write_text("model_path: old/model.pkl\n")
        with self.assertLogs("sonar.cli", "WARNING"):
            cfg = cli.load_config(str(self.config))
        self.assertEqual((cfg.models_dir, cfg.model_name), (str(self.root / "conf" / "old"), "model"))

    def test_scenario_id_defaults_to_the_model_name(self):
        cfg = PipelineConfig()
        cfg.model_name = "Brute-Force v2"
        self.assertEqual(cli._get_scenario_id(cfg), "brute-force_v2")
        cfg.shipping.scenario_id = "explicit"
        self.assertEqual(cli._get_scenario_id(cfg), "explicit")


class TestReservedNames(unittest.TestCase):
    def test_a_model_cannot_be_named_like_the_state_directory(self):
        cfg = PipelineConfig(model_name="state")
        with self.assertRaises(ValueError):
            cfg.model_path
        cfg.output.state_dir = "/var/lib/sonar/state"
        self.assertTrue(cfg.model_path.endswith("/state"))

    def test_old_pickle_message_keeps_dotted_names(self):
        from sonar.engine import IncompatibleModelError, ModelEngine

        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "brute_v1.2.pkl").write_bytes(b"x")
            cfg = PipelineConfig(models_dir=d, model_name="brute_v1.2")
            with self.assertRaises(IncompatibleModelError) as ctx:
                ModelEngine(cfg).load()
            self.assertIn(str(Path(d) / "brute_v1.2") + "/", str(ctx.exception))

    def test_command_line_payload_dir_wins_over_the_scenario(self):
        import argparse
        from unittest.mock import MagicMock

        from sonar.scenario import DetectionScenario

        args = argparse.Namespace(debug=False, dry_run=True, print_payloads=False, payload_dir="/from/cli", ship=False)
        delivery = cli._build_delivery(PipelineConfig(), MagicMock(), args, DetectionScenario(payload_dir="/from/scenario"))
        self.assertEqual(str(delivery.sinks[0].path), "/from/cli/anomalies.jsonl")


class TestNoWorkingDirectoryPaths(unittest.TestCase):
    """No code under sonar/ (outside its test-data scripts) builds a path from the working directory."""

    def test_no_cwd_relative_literals_or_getcwd(self):
        offenders = []
        for path in PACKAGE.rglob("*.py"):
            if "test_data" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.startswith("./"):
                    offenders.append(f"{path.relative_to(PACKAGE)}:{node.lineno} {node.value!r}")
                if isinstance(node, ast.Attribute) and node.attr in ("getcwd", "cwd"):
                    offenders.append(f"{path.relative_to(PACKAGE)}:{node.lineno} {node.attr}()")
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
