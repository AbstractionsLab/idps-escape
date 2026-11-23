"""
Packaging smoke test: the built wheel's ``sonar`` package runs a packaged example scenario
outside the repository (slow: builds the wheel).

The wheel is pure Python, so installing it means unpacking it. Only its ``sonar`` package is
unpacked, into a temporary directory placed first on ``PYTHONPATH``, and run with this
interpreter (whose dependencies stand in for the ones pip would install). The run happens in
another temporary directory with ``SONAR_HOME`` set, so nothing touches the repository.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


@pytest.mark.slow
class TestWheel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which("poetry") is None:
            raise unittest.SkipTest("poetry is not available to build the wheel")
        subprocess.run(["poetry", "build", "-f", "wheel"], cwd=REPO, check=True, capture_output=True)
        wheels = sorted((REPO / "dist").glob("*.whl"), key=lambda p: p.stat().st_mtime)
        cls.wheel = wheels[-1]
        cls.tmp = tempfile.TemporaryDirectory()
        cls.site = Path(cls.tmp.name) / "site"
        with zipfile.ZipFile(cls.wheel) as wheel:
            cls.names = wheel.namelist()
            wheel.extractall(cls.site, [n for n in cls.names if n.startswith("sonar/")])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _run(self, *args, cwd, env):
        return subprocess.run([sys.executable, *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=600)

    def test_wheel_contents(self):
        self.assertIn("sonar/scenarios/linux_resource_monitoring.yaml", self.names)
        self.assertIn("sonar/test_data/resource_monitoring/resource_monitoring_training.json", self.names)
        self.assertIn("sonar/wazuh/rules/sonar_rules.xml", self.names)
        self.assertIn("sonar/default_config.yaml", self.names)
        for forbidden in ("adbox/assets/secrets/", "sonar/models/", ".env"):
            self.assertFalse([n for n in self.names if forbidden in n], forbidden)

    def test_packaged_example_runs_outside_the_repository(self):
        work = Path(self.tmp.name) / "work"
        home = Path(self.tmp.name) / "home"
        work.mkdir()
        config = work / "sonar.yaml"
        # The ewma backend keeps the test fast; the scenario, data and output path are the packaged ones.
        config.write_text("backend: ewma\noutput:\n  debug_sinks: [jsonl]\n  jsonl_path: events.jsonl\n")
        env = {k: v for k, v in os.environ.items() if k != "SONAR_HOME"}
        env.update(PYTHONPATH=str(self.site), SONAR_HOME=str(home))

        where = self._run("-c", "import sonar, sys; print(sonar.__file__)", cwd=work, env=env)
        self.assertTrue(where.stdout.strip().startswith(str(self.site)), where.stdout + where.stderr)

        run = self._run("-m", "sonar", "scenario", "--use-case", "linux_resource_monitoring", "--config", str(config), "--debug", cwd=work, env=env)
        self.assertEqual(run.returncode, 0, run.stderr[-3000:])
        self.assertTrue((home / "models" / "linux_resource_monitoring" / "metadata.json").is_file())
        events = [json.loads(line) for line in (work / "events.jsonl").read_text().splitlines()]
        self.assertTrue(events)
        self.assertTrue(all(e["integration"] == "sonar" for e in events))
        self.assertFalse((REPO / "sonar" / "models" / "linux_resource_monitoring" / "ewma_state.json").exists())


if __name__ == "__main__":
    unittest.main()
