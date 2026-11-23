"""
End to end with real detectors: alerts -> features -> trained model -> verdicts -> sinks.

Every other detection test mocks the detector, so these are the tests that show SONAR
detects anything. The injected-anomaly checks run with the MVAD library and with the
``pca`` backend. Labelled intervals are injected into small generated alert streams
(``e2e_data.py``, fixed seeds). A model is trained on normal data with a short window and few
epochs. On such small, noisy streams MVAD also flags some normal buckets, so the tests check
a contrast: the injected interval is (nearly) all flagged, and flagged far more often than
the rest of the data. Marked ``slow`` (imports torch); each training takes a few seconds on
an idle CPU.
"""

import argparse
import json
import random
import tempfile
import unittest
from pathlib import Path

import pandas as pd
import pytest

from sonar import cli
from sonar.config import FeatureConfig, PipelineConfig
from sonar.engine import ModelEngine
from sonar.features import WazuhFeatureBuilder
from sonar.scenario import DetectionScenario
from sonar.sinks.local import JsonlSink
from sonar.watermark import Watermark
from tests.sonartests.e2e_data import event_alerts, metric_alerts

pytestmark = pytest.mark.slow

TRAIN_START = pd.Timestamp("2024-12-01T00:00:00Z")
TEST_START = pd.Timestamp("2024-12-02T00:00:00Z")
TRAIN_MINUTES = 400
TEST_MINUTES = 240
EVENT = (150, 165)  # minutes after TEST_START
MVAD_PARAMS = {"interval": 1, "epochs": 10, "batch_size": 32, "seed": 1}


def _config(backend: str = "mvad", **features) -> PipelineConfig:
    cfg = PipelineConfig(backend=backend)
    cfg.features = FeatureConfig(bucket_minutes=1, derived_features=False, **features)
    cfg.mvad.sliding_window = 20
    cfg.mvad.extra_params = dict(MVAD_PARAMS)
    cfg.mvad.min_gradient_steps = 0
    return cfg


def _train(cfg: PipelineConfig, alerts: list) -> ModelEngine:
    fb = WazuhFeatureBuilder(cfg.features)
    engine = ModelEngine(cfg)
    engine.train(fb.build_timeseries(alerts), vocabulary=fb.vocabulary)
    return engine


def _flag_rates(engine: ModelEngine, cfg: PipelineConfig, alerts: list, interval) -> tuple:
    """Share of flagged buckets inside the interval, and outside it (a margin of a few buckets around it excluded)."""
    end = TEST_START + pd.Timedelta(minutes=TEST_MINUTES)
    ts = WazuhFeatureBuilder(cfg.features, vocabulary=engine.vocabulary).build_timeseries(alerts, start=TEST_START.to_pydatetime(), end=end.to_pydatetime())
    inside, outside = [], []
    for r in engine.predict(ts):
        minute = int((r.timestamp - TEST_START) / pd.Timedelta(minutes=1))
        if interval[0] <= minute < interval[1]:
            inside.append(r.is_anomaly)
        elif not interval[0] - 2 <= minute < interval[1] + 3:
            outside.append(r.is_anomaly)
    return sum(inside) / len(inside), sum(outside) / len(outside)


class TestDetectsInjectedAnomalies(unittest.TestCase):
    """Each kind of anomaly SONAR's features are meant to expose is found by the real model."""

    backend = "mvad"

    def _check(self, cfg: PipelineConfig, train: list, test: list, interval=EVENT) -> None:
        inside, outside = _flag_rates(_train(cfg, train), cfg, test, interval)
        self.assertGreaterEqual(inside, 0.8, f"only {inside:.0%} of the injected interval flagged")
        self.assertGreaterEqual(inside, 2 * outside, f"interval flagged {inside:.0%}, the rest {outside:.0%}: no contrast")

    def test_metric_spike(self):
        rng = random.Random(1)
        cfg = _config(self.backend, numeric_fields=("data.cpu_usage_%",), max_numeric_fields=("data.cpu_usage_%",), numeric_fill="ffill")
        self._check(cfg, metric_alerts(TRAIN_START, TRAIN_MINUTES, rng), metric_alerts(TEST_START, TEST_MINUTES, rng, spikes=[EVENT]))

    def test_volume_burst(self):
        rng = random.Random(2)
        cfg = _config(self.backend, numeric_fields=())
        self._check(cfg, event_alerts(TRAIN_START, TRAIN_MINUTES, rng), event_alerts(TEST_START, TEST_MINUTES, rng, bursts=[EVENT]))

    def test_silence(self):
        # The time grid gives silent buckets a zero count instead of dropping them (feature schema 2).
        rng = random.Random(3)
        cfg = _config(self.backend, numeric_fields=())
        self._check(cfg, event_alerts(TRAIN_START, TRAIN_MINUTES, rng), event_alerts(TEST_START, TEST_MINUTES, rng, silences=[EVENT]))

    def test_new_category(self):
        # A group never seen in training lands in rule.groups__other.
        rng = random.Random(4)
        cfg = _config(self.backend, numeric_fields=(), categorical_fields=("rule.groups",))
        self._check(cfg, event_alerts(TRAIN_START, TRAIN_MINUTES, rng), event_alerts(TEST_START, TEST_MINUTES, rng, new_category=[EVENT]))


class TestPCADetectsInjectedAnomalies(TestDetectsInjectedAnomalies):
    """The same anomalies, found by the pca backend (no torch; trains in milliseconds)."""

    backend = "pca"


class _Indexer:
    """The alerts a live indexer would hold: everything up to the time of each search."""

    def __init__(self, alerts: list):
        self.alerts = alerts

    def search_alerts(self, start, end, query=None, source_fields=None):
        lo, hi = pd.Timestamp(start), pd.Timestamp(end)
        return [a for a in self.alerts if lo <= pd.Timestamp(a["timestamp"]) < hi]


class TestRealtimeDeliversOnce(unittest.TestCase):
    """Realtime polling with the real model: overlapping windows, one jsonl line per anomaly."""

    def test_no_duplicates_through_the_jsonl_sink(self):
        rng = random.Random(5)
        cfg = _config(numeric_fields=())
        engine = _train(cfg, event_alerts(TRAIN_START, TRAIN_MINUTES, rng))
        indexer = _Indexer(event_alerts(TEST_START, TEST_MINUTES, rng, bursts=[EVENT]))

        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "anomalies.jsonl"
            # Each poll scores the last 30 minutes, so every bucket is scored by many polls.
            detection = DetectionScenario(lookback_minutes=30, ingest_delay_seconds=0, min_consecutive=1)
            args = argparse.Namespace(debug=False, dry_run=False, print_payloads=False, payload_dir=None, ship=False)

            def run(first_minute: int, polls: int) -> None:
                clock = {"now": TEST_START + pd.Timedelta(minutes=first_minute)}
                count = {"n": 0}

                def sleep(_seconds):
                    count["n"] += 1
                    if count["n"] >= polls:
                        raise KeyboardInterrupt
                    clock["now"] += pd.Timedelta(minutes=5)

                delivery = cli._Delivery(sinks=[JsonlSink(str(out))], fallback=None, watermark=Watermark(d, "e2e"))
                code = cli._realtime_loop(cfg, indexer, engine, detection, args, now=lambda: clock["now"].to_pydatetime(), sleep=sleep, delivery=delivery)
                self.assertEqual(code, 0)

            run(first_minute=100, polls=12)  # minutes 100-160
            run(first_minute=130, polls=12)  # a restart that re-scores minutes 100-190
            lines = [json.loads(line) for line in out.read_text().splitlines()]

        ids = [line["sonar"]["anomaly_id"] for line in lines]
        self.assertTrue(ids, "the burst was not delivered")
        self.assertEqual(len(ids), len(set(ids)), "an anomaly was delivered twice")


if __name__ == "__main__":
    unittest.main()
