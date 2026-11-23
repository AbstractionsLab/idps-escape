"""
Detector backends (sonar/backends/): the contract every backend honours, the model directory
format, and the MVAD regression against verdicts recorded before the backend refactor.
"""

import json
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from sonar.backends import PointResult, backend_class
from sonar.config import EWMAConfig, PCAConfig, PipelineConfig
from sonar.engine import METADATA_FILE, IncompatibleModelError, ModelEngine
from sonar.training_plan import InsufficientTrainingDataError

GOLDEN = Path(__file__).resolve().parents[1] / "assets" / "sonar_mvad_regression.json"


def regression_dataset() -> pd.DataFrame:
    """The dataset of tests/assets/sonar_mvad_regression.json: 700 five-minute buckets, two injected anomalies."""
    rng = np.random.default_rng(7)
    n = 700
    idx = pd.date_range("2026-01-01", periods=n, freq="5min", tz="UTC")
    t = np.arange(n)
    df = pd.DataFrame(
        {
            "alert_count": 20 + 5 * np.sin(2 * np.pi * t / 288) + rng.normal(0, 1, n),
            "rule.level": 3 + rng.normal(0, 0.2, n),
            "is_auth_failure": np.clip(rng.poisson(2, n), 0, None).astype(float),
        },
        index=idx,
    )
    df.iloc[650:660, 0] += 60  # alert burst
    df.iloc[675:680, 2] += 25  # authentication failures
    return df


class BackendContract:
    """Checks every backend must pass; subclasses set up `self.cfg` and the data."""

    backend = ""

    def make_cfg(self, models_dir: str) -> PipelineConfig:
        raise NotImplementedError

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.cfg = self.make_cfg(self.dir.name)
        self.df = regression_dataset()
        self.engine = ModelEngine(self.cfg)
        self.engine.train(self.df.iloc[:600])
        self.window = self.df.iloc[600 - self.engine.context_buckets :]
        self.results = self.engine.predict(self.window)

    def test_one_verdict_per_bucket_after_the_context(self):
        self.assertEqual(len(self.results), len(self.window) - self.engine.context_buckets)
        self.assertEqual([r.timestamp for r in self.results], list(self.window.index[self.engine.context_buckets :]))
        self.assertEqual(self.engine.min_detection_points, self.engine.context_buckets + 1)

    def test_results_are_normalised(self):
        for r in self.results:
            self.assertIsInstance(r, PointResult)
            self.assertTrue(0.0 <= r.severity <= 1.0)
            if not r.is_anomaly:
                self.assertEqual(r.severity, 0.0)
            for c in r.contributors:
                self.assertIn(c.variable, self.df.columns)
            contributions = [c.contribution for c in r.contributors]
            self.assertEqual(contributions, sorted(contributions, reverse=True))

    def test_injected_anomalies_are_found(self):
        flagged = {r.timestamp for r in self.results if r.is_anomaly}
        self.assertTrue(flagged & set(self.df.index[650:660]), "alert burst missed")

    def test_save_and_load_give_the_same_verdicts(self):
        self.engine.save()
        model_dir = Path(self.cfg.model_path)
        metadata = json.loads((model_dir / METADATA_FILE).read_text())
        self.assertEqual(metadata["backend"], self.backend)
        self.assertEqual(metadata["columns"], list(self.df.columns))
        self.assertFalse(list(model_dir.glob("*.pkl")), "no pickle in the model directory")
        loaded = ModelEngine(self.cfg)
        loaded.load()
        again = loaded.predict(self.window)
        self.assertEqual([(r.timestamp, r.is_anomaly) for r in again], [(r.timestamp, r.is_anomaly) for r in self.results])
        self.assertTrue(np.allclose([r.severity for r in again], [r.severity for r in self.results]))

    def test_saving_again_replaces_the_model(self):
        self.engine.save()
        self.engine.save()
        siblings = [p.name for p in Path(self.cfg.models_dir).iterdir()]
        self.assertEqual(siblings, [self.cfg.model_name])  # no staging or backup directories left


class TestEWMABackend(BackendContract, unittest.TestCase):
    backend = "ewma"

    def make_cfg(self, models_dir):
        cfg = PipelineConfig(backend="ewma", models_dir=models_dir, model_name="ewma_model")
        return cfg

    def test_parameters(self):
        with self.assertRaises(ValueError):
            backend_class("ewma")(EWMAConfig(alpha=0))
        with self.assertRaises(ValueError):
            backend_class("ewma")(EWMAConfig(z_threshold=-1))
        self.assertEqual(backend_class("ewma")(EWMAConfig(alpha=1.0)).min_points, 1)
        self.assertEqual(backend_class("ewma")(EWMAConfig(alpha=0.5)).min_points, 3)

    def test_too_little_training_data(self):
        engine = ModelEngine(self.cfg)
        with self.assertRaises(InsufficientTrainingDataError):
            engine.train(self.df.iloc[:5])

    def test_severity_scale(self):
        # At the threshold a bucket is anomalous with severity 0.5; twice the threshold or more is 1.
        backend = backend_class("ewma")(EWMAConfig(alpha=1.0, z_threshold=2.0))
        idx = pd.date_range("2026-01-01", periods=12, freq="5min", tz="UTC")
        backend.fit(pd.DataFrame({"x": [0.0, 1.0] * 6}, index=idx))  # median 0.5, scale 0.5 * 1.4826
        scale = backend.scale["x"]
        test = pd.DataFrame({"x": [0.5, 0.5 + 2 * scale, 0.5 + 10 * scale]}, index=idx[:3])
        r = backend.predict(test)
        self.assertEqual([p.is_anomaly for p in r], [False, True, True])
        self.assertAlmostEqual(r[1].severity, 0.5)
        self.assertEqual(r[2].severity, 1.0)

    def test_unknown_backend(self):
        with self.assertRaises(ValueError):
            backend_class("isolation_forest")


class TestPCABackend(BackendContract, unittest.TestCase):
    backend = "pca"

    def make_cfg(self, models_dir):
        return PipelineConfig(backend="pca", models_dir=models_dir, model_name="pca_model")

    def test_parameters(self):
        for bad in (PCAConfig(window=0), PCAConfig(variance=1.0), PCAConfig(variance=0.0), PCAConfig(z_threshold=0)):
            with self.assertRaises(ValueError):
                backend_class("pca")(bad)
        self.assertEqual(backend_class("pca")(PCAConfig(window=10)).min_points, 10)

    def test_too_little_training_data(self):
        with self.assertRaises(InsufficientTrainingDataError):
            ModelEngine(self.cfg).train(self.df.iloc[:15])  # needs window - 1 + 20 = 22

    def test_both_injected_anomalies_are_found_and_explained(self):
        by_time = {r.timestamp: r for r in self.results}
        for rows, feature in ((slice(650, 660), "alert_count"), (slice(675, 680), "is_auth_failure")):
            flagged = [by_time[t] for t in self.df.index[rows] if by_time[t].is_anomaly]
            self.assertTrue(flagged, f"{feature} anomaly missed")
            self.assertEqual(flagged[0].contributors[0].variable, feature)

    def test_normal_data_is_rarely_flagged(self):
        # Before the first injected anomaly, and after the last one has left the window.
        quiet = [r.is_anomaly for r in self.results if r.timestamp < self.df.index[650] or r.timestamp >= self.df.index[680 + self.cfg.pca.window]]
        self.assertLessEqual(sum(quiet) / len(quiet), 0.05)

    def test_settings_from_config_and_scenario(self):
        from sonar import cli

        root = Path(self.dir.name)
        (root / "config.yaml").write_text("pca:\n  variance: 0.8\n  z_threshold: 5.0\n")
        (root / "scenario.yaml").write_text("name: s\ntraining:\n  backend: pca\n  pca:\n    window: 5\n    z_threshold: 6.0\n")
        cfg, _ = cli.load_scenario_for_phase(str(root / "scenario.yaml"), "training", str(root / "config.yaml"))
        self.assertEqual(cfg.backend, "pca")
        self.assertEqual((cfg.pca.window, cfg.pca.variance, cfg.pca.z_threshold), (5, 0.8, 6.0))  # the scenario wins over the config

    def _correlated(self, n: int, broken: bool = False) -> pd.DataFrame:
        rng = np.random.default_rng(3)
        idx = pd.date_range("2026-01-01", periods=n, freq="5min", tz="UTC")
        a = rng.normal(0, 1, n)
        b = a + rng.normal(0, 0.05, n)
        if broken:
            b[-1] = -a[-1]  # each value normal on its own, their relation never seen
        return pd.DataFrame({"a": a, "b": b}, index=idx)

    def test_broken_correlation_is_found(self):
        # What a per-feature detector cannot see: both values are within their usual range.
        backend = backend_class("pca")(PCAConfig(window=1))
        backend.fit(self._correlated(300))
        test = self._correlated(301, broken=True).iloc[-20:]
        self.assertLess(abs(test["b"].iloc[-1]), 3.0)
        results = backend.predict(test)
        self.assertTrue(results[-1].is_anomaly)
        self.assertFalse(any(r.is_anomaly for r in results[:-1]))

    def test_constant_training_feature(self):
        # A feature that never moved in training (an unseen category) scores its first change as anomalous.
        idx = pd.date_range("2026-01-01", periods=100, freq="5min", tz="UTC")
        rng = np.random.default_rng(4)
        train = pd.DataFrame({"x": rng.normal(10, 1, 100), "other": np.zeros(100)}, index=idx)
        backend = backend_class("pca")(PCAConfig(window=3))
        backend.fit(train)
        test = train.iloc[:10].copy()
        test.iloc[-1, 1] = 1.0
        results = backend.predict(test)
        self.assertTrue(results[-1].is_anomaly)
        self.assertEqual(results[-1].contributors[0].variable, "other")
        self.assertTrue(all(np.isfinite(r.raw_score) for r in results))


class TestModelDirectory(unittest.TestCase):
    def test_missing_model(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(FileNotFoundError):
                ModelEngine(PipelineConfig(models_dir=d, model_name="none")).load()

    def test_other_format_version_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = PipelineConfig(backend="ewma", models_dir=d, model_name="m")
            engine = ModelEngine(cfg)
            engine.train(regression_dataset().iloc[:100])
            engine.save()
            path = Path(cfg.model_path) / METADATA_FILE
            metadata = json.loads(path.read_text())
            metadata["format_version"] = 99
            path.write_text(json.dumps(metadata))
            with self.assertRaises(IncompatibleModelError):
                ModelEngine(cfg).load()


@pytest.mark.slow
class TestMVADBackend(BackendContract, unittest.TestCase):
    backend = "mvad"

    def make_cfg(self, models_dir):
        cfg = PipelineConfig(backend="mvad", models_dir=models_dir, model_name="mvad_model")
        cfg.mvad.sliding_window = 30
        cfg.mvad.extra_params = {"interval": 1, "epochs": 4, "batch_size": 32}
        cfg.mvad.min_gradient_steps = 0
        return cfg

    def test_same_verdicts_as_before_the_backend_refactor(self):
        """tests/assets/sonar_mvad_regression.json was recorded with the pre-backend engine, same seed and data."""
        golden = json.loads(GOLDEN.read_text())
        self.assertEqual(golden["params"], {"sliding_window": 30, "interval": 1, "epochs": 4, "batch_size": 32})
        expected = golden["results"]
        self.assertEqual([r.timestamp.isoformat() for r in self.results], [g["timestamp"] for g in expected])
        self.assertEqual([r.is_anomaly for r in self.results], [g["is_anomaly"] for g in expected])
        self.assertTrue(np.allclose([r.severity for r in self.results], [g["severity"] for g in expected], atol=1e-6))
        self.assertTrue(np.allclose([r.raw_score for r in self.results], [g["score"] for g in expected], atol=1e-6))

    def test_weights_load_without_pickle(self):
        import torch

        self.engine.save()
        state = torch.load(Path(self.cfg.model_path) / "mvad_weights.pt", weights_only=True)
        self.assertTrue(all(isinstance(v, torch.Tensor) for v in state.values()))


if __name__ == "__main__":
    unittest.main()
