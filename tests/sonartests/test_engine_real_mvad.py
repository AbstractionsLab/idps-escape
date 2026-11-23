"""
Tests against the real MVAD library (time-series-anomaly-detector).

Every other SONAR test mocks the library, which is how untrained models went unnoticed.
These tests keep sizes small (short windows, few epochs) and fixed seeds so they run in
seconds, but they import torch: deselect them with ``-m "not slow"``.
"""

import dataclasses
import os
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from sonar.config import PipelineConfig
from sonar.engine import MVADModelEngine
from sonar.training_plan import LIBRARY_CONFIG_FIELDS, LIBRARY_DEFAULTS, InsufficientTrainingDataError, plan_training, window_sizes

pytestmark = pytest.mark.slow


def _frame(rows: int, cols: int = 3, seed: int = 0) -> pd.DataFrame:
    """Smooth periodic signals with noise, one row per 5-minute bucket."""
    rng = np.random.default_rng(seed)
    t = np.arange(rows)
    data = {f"f{i}": np.sin(2 * np.pi * t / (24 + 7 * i)) + 0.1 * rng.standard_normal(rows) for i in range(cols)}
    return pd.DataFrame(data, index=pd.date_range("2026-01-01", periods=rows, freq="5min", tz="UTC"))


class TestLibraryContract(unittest.TestCase):
    """The constants in sonar.training_plan must match the installed library."""

    def test_defaults_match_multiadconfig(self):
        from anomaly_detector.multivariate.contract import MultiADConfig

        defaults = {f.name: f.default for f in dataclasses.fields(MultiADConfig)}
        for key, value in LIBRARY_DEFAULTS.items():
            self.assertEqual(defaults[key], value, key)

    def test_config_fields_match_multiadconfig(self):
        from anomaly_detector.multivariate.contract import MultiADConfig

        self.assertEqual({f.name for f in dataclasses.fields(MultiADConfig)}, set(LIBRARY_CONFIG_FIELDS))

    def test_window_sizes_match_library(self):
        from anomaly_detector import MultivariateAnomalyDetector

        for sw in (2, 20, 96, 200, 300, 500):
            self.assertEqual(window_sizes(sw), MultivariateAnomalyDetector.compute_window_sizes(sw), sw)


class TestPlanMatchesLibrary(unittest.TestCase):
    """The predicted number of optimiser steps equals what the library actually does."""

    def _count_steps(self, rows: int, params: dict) -> int:
        import torch
        from anomaly_detector import MultivariateAnomalyDetector

        steps = {"n": 0}
        original = torch.optim.Adam.step

        def counting_step(opt, *args, **kwargs):
            steps["n"] += 1
            return original(opt, *args, **kwargs)

        torch.optim.Adam.step = counting_step
        try:
            with tempfile.TemporaryDirectory() as tmp:
                MultivariateAnomalyDetector().fit(_frame(rows), params={**params, "save": tmp})
        finally:
            torch.optim.Adam.step = original
        return steps["n"]

    def test_predicted_steps_equal_counted_steps(self):
        cases = [
            (120, {"sliding_window": 20, "epochs": 2, "batch_size": 8}),  # 1 batch/epoch
            (400, {"sliding_window": 20, "epochs": 2, "batch_size": 8}),  # several batches/epoch
            (300, {"sliding_window": 30, "epochs": 2, "batch_size": 16, "interval": 1}),
            (150, {"sliding_window": 40, "epochs": 2}),  # library defaults: no batch at all
        ]
        for rows, params in cases:
            with self.subTest(rows=rows, params=params):
                self.assertEqual(self._count_steps(rows, params), plan_training(rows, params).gradient_steps)


class TestEngineWithRealLibrary(unittest.TestCase):
    """Train, save and load through MVADModelEngine with the real library."""

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)
        self.cfg = PipelineConfig()
        self.cfg.mvad.sliding_window = 20
        self.cfg.mvad.extra_params = {"epochs": 3, "batch_size": 8}
        self.cfg.model_path = str(Path(self._tmp.name) / "m.pkl")

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def test_trained_weights_differ_from_initialisation(self):
        """The saved network is not the random initialisation the library starts from."""
        import torch
        from anomaly_detector.multivariate.module import MultivariateGraphAttnDetector

        engine = MVADModelEngine(self.cfg)
        engine.train(_frame(300))
        lib = engine.backend.model
        torch.manual_seed(lib.config.seed)
        initial = MultivariateGraphAttnDetector(lib.config).state_dict()
        trained = lib.model.state_dict()
        changed = [k for k in initial if not torch.equal(initial[k], trained[k])]
        self.assertTrue(changed, "no parameter changed during training")
        self.assertGreater(engine.metadata["gradient_steps"], 0)

    def test_save_load_round_trip_keeps_metadata_and_predicts(self):
        engine = MVADModelEngine(self.cfg)
        engine.train(_frame(300))
        engine.save()

        loaded = MVADModelEngine(self.cfg)
        loaded.load()
        self.assertEqual(loaded.metadata["gradient_steps"], engine.metadata["gradient_steps"])
        self.assertEqual(loaded.training_columns, ["f0", "f1", "f2"])
        results = loaded.predict(_frame(60, seed=1))
        self.assertEqual(len(results), 60 - 20 + 1)

    def test_no_checkpoint_written_to_working_directory(self):
        MVADModelEngine(self.cfg).train(_frame(300))
        self.assertFalse(Path("model").exists(), "library checkpoint leaked into ./model")

    def test_refuses_data_the_library_cannot_train_on(self):
        self.cfg.mvad.extra_params = {"epochs": 3}  # batch_size 128 with 300 buckets: no batch
        with self.assertRaises(InsufficientTrainingDataError):
            MVADModelEngine(self.cfg).train(_frame(300))


if __name__ == "__main__":
    unittest.main()
