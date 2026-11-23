"""
Detection semantics (sonar/cli.py): the scored window, its context, complete buckets only,
one detection path for every command, and exit codes.
"""

import argparse
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pandas as pd

from sonar import cli
from sonar.backends.mvad import mvad_results_to_points
from sonar.config import FeatureConfig, PipelineConfig
from sonar.features import FeatureVocabulary
from sonar.scenario import DetectionScenario

BUCKET = timedelta(minutes=5)
NOW = datetime(2026, 1, 1, 12, 7, 30, tzinfo=timezone.utc)


def _engine(context_buckets=11, columns=None):
    """A loaded model whose predict() flags every bucket it scores, like MVAD's output shape."""
    engine = MagicMock()
    engine.context_buckets = context_buckets
    engine.min_detection_points = context_buckets + 1
    engine.sliding_window = 12
    engine.feature_config = FeatureConfig(derived_features=False)
    engine.vocabulary = FeatureVocabulary()
    engine.training_columns = columns or ["alert_count", "rule.level"]
    engine._training_samples = 2016

    def predict(ts):
        return mvad_results_to_points(
            [{"index": idx, "is_anomaly": True, "score": 1.2, "severity": 0.7, "interpretation": [{"variable_name": "alert_count", "contribution_score": 0.9}]} for idx in ts.index[context_buckets:]]
        )

    engine.predict.side_effect = predict
    return engine


def _alerts_every_minute(start, end):
    alerts, t = [], start
    while t < end:
        alerts.append({"timestamp": t.isoformat().replace("+00:00", "Z"), "rule": {"level": 3, "groups": ["syslog"]}})
        t += timedelta(minutes=1)
    return alerts


class _RecordingSink:
    name = "record"

    def __init__(self):
        self.delivered = []

    def emit(self, docs):
        from sonar.sinks import DeliveryResult

        self.delivered.extend(docs)
        return DeliveryResult(len(docs), len(docs))


class TestScoringWindow(unittest.TestCase):
    def test_window_ends_at_last_complete_bucket_and_adds_context(self):
        cfg = PipelineConfig()
        now = datetime(2026, 1, 1, 12, 7, 30, tzinfo=timezone.utc)  # bucket 12:05 is still filling
        fetch_start, score_start, end = cli._scoring_window(cfg, _engine(context_buckets=11), lookback_minutes=60, now=now)
        self.assertEqual(end, datetime(2026, 1, 1, 12, 5, tzinfo=timezone.utc))
        self.assertEqual(score_start, datetime(2026, 1, 1, 11, 5, tzinfo=timezone.utc))
        self.assertEqual(fetch_start, score_start - 11 * BUCKET)

    def test_ingest_delay_holds_back_a_bucket_that_just_ended(self):
        cfg = PipelineConfig()
        just_after = datetime(2026, 1, 1, 12, 5, 30, tzinfo=timezone.utc)  # bucket 12:00 ended 30 s ago
        _, _, end = cli._scoring_window(cfg, _engine(), lookback_minutes=60, now=just_after, ingest_delay_seconds=60)
        self.assertEqual(end, datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc))
        _, _, end = cli._scoring_window(cfg, _engine(), lookback_minutes=60, now=just_after + timedelta(seconds=30), ingest_delay_seconds=60)
        self.assertEqual(end, datetime(2026, 1, 1, 12, 5, tzinfo=timezone.utc))

    def test_lookback_shorter_than_a_bucket_still_scores_one_bucket(self):
        cfg = PipelineConfig()
        now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        _, score_start, end = cli._scoring_window(cfg, _engine(), lookback_minutes=1, now=now)
        self.assertEqual(end - score_start, BUCKET)


class TestSingleDetection(unittest.TestCase):
    def setUp(self):
        self.cfg = PipelineConfig()
        self.cfg.features = FeatureConfig(derived_features=False)
        self.cfg.model_path = "./sonar/models/test_model.pkl"
        self.cfg.shipping.scenario_id = "test_scenario"
        self.detection = DetectionScenario(lookback_minutes=60)
        self.args = argparse.Namespace(ship=False, debug=False)
        self.state = tempfile.TemporaryDirectory()
        self.addCleanup(self.state.cleanup)
        self.cfg.output.state_dir = self.state.name

    def _window(self, engine):
        return cli._scoring_window(self.cfg, engine, 60, now=NOW, ingest_delay_seconds=self.detection.ingest_delay_seconds)

    def _run(self, engine, alerts):
        client = MagicMock(dry_run=False)
        client.search_alerts.return_value = alerts
        sink = _RecordingSink()
        code = cli._run_single_detection(self.cfg, client, engine, self.detection, self.args, now=NOW, delivery=cli._Delivery([sink]))
        return code, client, sink.delivered

    def test_every_bucket_of_the_window_gets_a_verdict_and_nothing_else(self):
        engine = _engine(context_buckets=11)
        _, score_start, end = self._window(engine)
        alerts = _alerts_every_minute(score_start - 11 * BUCKET, end + 4 * BUCKET)  # alerts after `end` too
        code, client, docs = self._run(engine, alerts)

        self.assertEqual(code, cli.EXIT_OK)
        start_arg, end_arg = client.search_alerts.call_args.args[:2]
        self.assertEqual((start_arg, end_arg), (score_start - 11 * BUCKET, end))
        stamps = [pd.Timestamp(d["timestamp"]) for d in docs]
        self.assertEqual(len(stamps), 12)  # 60 minutes of 5-minute buckets
        self.assertEqual(min(stamps), pd.Timestamp(score_start))
        self.assertLess(max(stamps), pd.Timestamp(end))  # the still-filling bucket is never scored

    def test_documents_describe_the_model(self):
        engine = _engine(columns=["alert_count", "rule.level", "rule.groups__other"])
        _, score_start, end = self._window(engine)
        _, _, docs = self._run(engine, _alerts_every_minute(score_start - 11 * BUCKET, end))
        doc = docs[0]
        self.assertEqual(doc["scenario_name"], "test_scenario")
        self.assertEqual(doc["model_name"], "test_model")
        self.assertEqual(doc["feature_count"], 3)
        self.assertEqual(doc["context"]["feature_names"], ["alert_count", "rule.level", "rule.groups__other"])
        self.assertEqual(doc["sliding_window"], 12)
        self.assertEqual(doc["bucket_minutes"], 5)
        self.assertEqual(doc["anomaly_score"], 0.7)
        self.assertEqual(doc["mvad_interpretation"][0]["variable"], "alert_count")
        self.assertEqual(doc["mvad_interpretation"][0]["value"], 5.0)  # 5 alerts per 5-minute bucket

    def test_no_alerts_means_nothing_scored(self):
        code, _, docs = self._run(_engine(), [])
        self.assertEqual((code, docs), (cli.EXIT_NOT_ENOUGH_DATA, []))

    def test_too_few_buckets_means_nothing_scored(self):
        engine = _engine(context_buckets=11)
        _, _, end = self._window(engine)
        code, _, _ = self._run(engine, _alerts_every_minute(end - 3 * BUCKET, end))  # alerts only in the last 15 minutes
        # The grid still spans the whole fetched window, so silence before the alerts is data
        self.assertEqual(code, cli.EXIT_OK)
        code, _, _ = self._run(_engine(context_buckets=200), _alerts_every_minute(end - 3 * BUCKET, end))
        self.assertEqual(code, cli.EXIT_OK)
        engine.min_detection_points = 10_000
        code, _, _ = self._run(engine, _alerts_every_minute(end - 3 * BUCKET, end))
        self.assertEqual(code, cli.EXIT_NOT_ENOUGH_DATA)

    def test_model_error_is_exit_1(self):
        engine = _engine()
        engine.predict.side_effect = ValueError("broken")
        _, score_start, end = self._window(engine)
        code, _, _ = self._run(engine, _alerts_every_minute(score_start - 11 * BUCKET, end))
        self.assertEqual(code, cli.EXIT_ERROR)


class TestOneDetectionPath(unittest.TestCase):
    """`sonar detect` with and without a scenario goes through _run_single_detection."""

    def _args(self, **kw):
        base = dict(scenario=None, config=None, lookback_minutes=None, debug=False, ship=False, print_payloads=False, dry_run=False, payload_dir=None)
        base.update(kw)
        return argparse.Namespace(**base)

    def test_plain_detect_uses_the_shared_path(self):
        with patch.object(cli, "_load_engine", return_value=_engine()), patch.object(cli, "WazuhIndexerClient") as client_cls, patch.object(cli, "_run_single_detection", return_value=cli.EXIT_NOT_ENOUGH_DATA) as run:
            client_cls.return_value.check_connection.return_value = True
            self.assertEqual(cli.cmd_detect(self._args(lookback_minutes=30)), cli.EXIT_NOT_ENOUGH_DATA)
        detection = run.call_args.args[3]
        self.assertEqual(detection.lookback_minutes, 30)
        self.assertIsNone(detection.threshold)

    def test_scenario_detect_uses_the_shared_path(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write("name: t\nmodel_name: t\ndetection:\n  lookback_minutes: 45\n  threshold: 0.4\n")
            path = f.name
        try:
            with patch.object(cli, "_load_engine", return_value=_engine()), patch.object(cli, "WazuhIndexerClient") as client_cls, patch.object(cli, "_run_single_detection", return_value=cli.EXIT_OK) as run:
                client_cls.return_value.check_connection.return_value = True
                self.assertEqual(cli.cmd_detect(self._args(scenario=path)), cli.EXIT_OK)
        finally:
            Path(path).unlink()
        detection = run.call_args.args[3]
        self.assertEqual((detection.lookback_minutes, detection.threshold), (45, 0.4))

    def test_missing_model_is_exit_1(self):
        with patch.object(cli, "_load_engine", return_value=None):
            self.assertEqual(cli.cmd_detect(self._args()), cli.EXIT_ERROR)


class TestNoAlertWrites(unittest.TestCase):
    def test_client_cannot_write_alerts(self):
        from sonar.wazuh_client import WazuhIndexerClient

        self.assertFalse(hasattr(WazuhIndexerClient, "index_alert"))

    def test_synthetic_options_are_gone(self):
        with patch("sys.argv", ["sonar", "train", "--fill-with-synthetic"]), self.assertRaises(SystemExit):
            cli.main()


if __name__ == "__main__":
    unittest.main()
