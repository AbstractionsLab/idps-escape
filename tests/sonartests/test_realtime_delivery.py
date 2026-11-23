"""
Realtime delivery (sonar/watermark.py, sonar/cli.py): each anomalous bucket is delivered at
most once per scenario, across polls and restarts; a failing poll is retried with backoff.

Fake clock, fake model and fake sinks: no indexer is contacted.
"""

import argparse
import json
import tempfile
from pathlib import Path
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pandas as pd
from opensearchpy.exceptions import ConflictError

from sonar import cli
from sonar.backends.mvad import mvad_results_to_points
from sonar.config import FeatureConfig, PipelineConfig, WazuhIndexerConfig
from sonar.features import FeatureVocabulary
from sonar.scenario import DetectionScenario
from sonar.shipper.wazuh_data_shipper import WazuhDataShipper
from sonar.sinks import DeliveryResult
from sonar.watermark import Watermark, anomaly_id

BUCKET = timedelta(minutes=5)
CONTEXT = 11
# 12:07:30 with the default 60 s ingest delay: the last scored bucket is 12:00-12:05.
NOW = datetime(2026, 1, 1, 12, 7, 30, tzinfo=timezone.utc)


def _engine(anomalous_from=None):
    """A loaded model that flags every scored bucket at or after `anomalous_from` (all if None)."""
    engine = MagicMock()
    engine.context_buckets = CONTEXT
    engine.min_detection_points = CONTEXT + 1
    engine.sliding_window = CONTEXT + 1
    engine.feature_config = FeatureConfig(derived_features=False)
    engine.vocabulary = FeatureVocabulary()
    engine.training_columns = ["alert_count", "rule.level"]
    engine._training_samples = 2016

    def predict(ts):
        results = []
        for idx in ts.index[CONTEXT:]:
            flagged = anomalous_from is None or idx >= pd.Timestamp(anomalous_from)
            results.append({"index": idx, "is_anomaly": flagged, "score": 1.2 if flagged else 0.0, "severity": 0.7 if flagged else 0.0, "interpretation": []})
        return mvad_results_to_points(results)

    engine.predict.side_effect = predict
    return engine


def _alerts(start, end):
    alerts, t = [], start
    while t < end:
        alerts.append({"timestamp": t.isoformat().replace("+00:00", "Z"), "rule": {"level": 3}})
        t += timedelta(minutes=1)
    return alerts


class _Sink:
    """Records what was delivered; can be told to fail, or to accept only the first `accept_only`."""

    def __init__(self, name="wazuh"):
        self.name = name
        self.delivered = []
        self.fail = False
        self.accept_only = None

    def emit(self, docs):
        if self.fail:
            return DeliveryResult(0, len(docs), "down")
        n = len(docs) if self.accept_only is None else min(self.accept_only, len(docs))
        self.delivered.extend(docs[:n])
        return DeliveryResult(n, len(docs), None if n == len(docs) else "partial")

    def buckets(self):
        return [pd.Timestamp(d["timestamp"]) for d in self.delivered]


class _Base(unittest.TestCase):
    def setUp(self):
        self.state = tempfile.TemporaryDirectory()
        self.addCleanup(self.state.cleanup)
        self.cfg = PipelineConfig()
        self.cfg.features = FeatureConfig(derived_features=False)
        self.cfg.model_path = "./sonar/models/test_model.pkl"
        self.cfg.shipping.scenario_id = "realtime_test"
        self.cfg.output.state_dir = self.state.name
        self.detection = DetectionScenario(lookback_minutes=60)
        self.args = argparse.Namespace(ship=False, debug=False)
        self.sink = _Sink()

    def watermark(self):
        return Watermark(self.state.name, "realtime_test")

    def poll(self, engine, now, sinks=None, fallback=None):
        """One detection run at `now`, over alerts that cover everything it fetches."""
        client = MagicMock()
        client.search_alerts.side_effect = lambda start, end, **kw: _alerts(start, end)
        delivery = cli._Delivery(sinks or [self.sink], fallback, self.watermark())
        return cli._run_single_detection(self.cfg, client, engine, self.detection, self.args, now=now, delivery=delivery)


class TestAnomalyId(unittest.TestCase):
    def test_same_scenario_and_bucket_give_the_same_id(self):
        self.assertEqual(anomaly_id("s", "2026-01-01T12:00:00Z"), anomaly_id("s", pd.Timestamp("2026-01-01 13:00", tz="Europe/Luxembourg")))
        self.assertEqual(anomaly_id("s", "2026-01-01T12:00:00"), anomaly_id("s", "2026-01-01T12:00:00+00:00"))  # naive is UTC

    def test_other_scenario_or_bucket_give_another_id(self):
        base = anomaly_id("s", "2026-01-01T12:00:00Z")
        self.assertNotEqual(base, anomaly_id("t", "2026-01-01T12:00:00Z"))
        self.assertNotEqual(base, anomaly_id("s", "2026-01-01T12:05:00Z"))

    def test_documents_carry_their_id(self):
        from sonar.pipeline import MVADPostProcessor

        ts = pd.Timestamp("2026-01-01T12:00:00Z")
        docs = MVADPostProcessor(FeatureConfig()).build_wazuh_anomaly_docs(mvad_results_to_points([{"index": ts, "is_anomaly": True, "score": 1.0, "severity": 0.6}]), {"scenario_id": "s"})
        self.assertEqual(docs[0]["anomaly_id"], anomaly_id("s", ts))


class TestWatermarkFile(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def test_persists_across_instances(self):
        self.assertIsNone(Watermark(self.dir.name, "s").load("wazuh"))
        Watermark(self.dir.name, "s").advance("wazuh", "2026-01-01T12:00:00Z")
        self.assertEqual(Watermark(self.dir.name, "s").load("wazuh"), pd.Timestamp("2026-01-01T12:00:00Z"))
        stored = json.loads((Watermark(self.dir.name, "s").path).read_text())
        self.assertEqual(stored, {"scenario_id": "s", "sinks": {"wazuh": "2026-01-01T12:00:00+00:00"}})

    def test_never_moves_back(self):
        mark = Watermark(self.dir.name, "s")
        mark.advance("wazuh", "2026-01-01T12:00:00Z")
        self.assertEqual(mark.advance("wazuh", "2026-01-01T11:00:00Z"), pd.Timestamp("2026-01-01T12:00:00Z"))
        self.assertEqual(mark.load("wazuh"), pd.Timestamp("2026-01-01T12:00:00Z"))

    def test_scenarios_and_sinks_are_independent(self):
        Watermark(self.dir.name, "s").advance("wazuh", "2026-01-01T12:00:00Z")
        Watermark(self.dir.name, "s").advance("datastream", "2026-01-01T11:00:00Z")
        self.assertIsNone(Watermark(self.dir.name, "t").load("wazuh"))
        self.assertEqual(Watermark(self.dir.name, "s").load("wazuh"), pd.Timestamp("2026-01-01T12:00:00Z"))
        self.assertEqual(Watermark(self.dir.name, "s").load("datastream"), pd.Timestamp("2026-01-01T11:00:00Z"))

    def test_unreadable_file_means_no_watermark(self):
        mark = Watermark(self.dir.name, "s")
        mark.path.write_text("{not json")
        with self.assertLogs("sonar.watermark", "WARNING"):
            self.assertIsNone(mark.load("wazuh"))


class TestDeliveredOnce(_Base):
    def test_two_polls_over_the_same_data_deliver_each_anomaly_once(self):
        engine = _engine()
        self.assertEqual(self.poll(engine, NOW), cli.EXIT_OK)
        first = self.sink.buckets()
        self.assertEqual(len(first), 12)
        self.assertEqual(self.poll(engine, NOW + timedelta(seconds=20)), cli.EXIT_OK)
        self.assertEqual(self.sink.buckets(), first)

    def test_restart_does_not_deliver_again(self):
        self.poll(_engine(), NOW)
        delivered = len(self.sink.delivered)
        # A new process: new engine and sink, same state directory.
        self.sink = _Sink()
        self.assertEqual(self.poll(_engine(), NOW), cli.EXIT_OK)
        self.assertEqual(self.sink.delivered, [])
        self.assertEqual(delivered, 12)

    def test_a_run_across_a_poll_boundary_delivers_only_the_new_buckets(self):
        engine = _engine(anomalous_from=datetime(2026, 1, 1, 11, 50, tzinfo=timezone.utc))
        self.poll(engine, NOW)
        self.assertEqual(self.sink.buckets(), [pd.Timestamp(f"2026-01-01T{t}Z") for t in ("11:50", "11:55", "12:00")])
        self.poll(engine, NOW + BUCKET)
        self.assertEqual(self.sink.buckets()[3:], [pd.Timestamp("2026-01-01T12:05Z")])

    def test_min_consecutive_counts_buckets_before_the_poll_boundary(self):
        # Two anomalous buckets at the end of poll 1 are too short a run; the third, in poll 2,
        # completes it, and all three are delivered then.
        self.detection.min_consecutive = 3
        engine = _engine(anomalous_from=datetime(2026, 1, 1, 11, 55, tzinfo=timezone.utc))
        self.poll(engine, NOW)
        self.assertEqual(self.sink.delivered, [])
        self.poll(engine, NOW + BUCKET)
        self.assertEqual(self.sink.buckets(), [pd.Timestamp(f"2026-01-01T{t}Z") for t in ("11:55", "12:00", "12:05")])

    def test_failed_delivery_keeps_the_watermark_and_is_retried(self):
        engine = _engine()
        self.sink.fail = True
        self.assertEqual(self.poll(engine, NOW), cli.EXIT_ERROR)
        self.assertIsNone(self.watermark().load("wazuh"))
        self.sink.fail = False
        self.assertEqual(self.poll(engine, NOW), cli.EXIT_OK)
        self.assertEqual(len(self.sink.delivered), 12)

    def test_partial_delivery_advances_over_the_accepted_prefix(self):
        engine = _engine()
        self.sink.accept_only = 5
        self.assertEqual(self.poll(engine, NOW), cli.EXIT_ERROR)  # the only sink failed
        self.assertEqual(self.watermark().load("wazuh"), self.sink.buckets()[-1])
        self.sink.accept_only = None
        self.poll(engine, NOW)
        buckets = self.sink.buckets()
        self.assertEqual(len(buckets), 12)
        self.assertEqual(len(set(buckets)), 12)  # nothing delivered twice

    def test_each_sink_keeps_its_own_watermark(self):
        engine = _engine()
        wazuh, stream = _Sink("wazuh"), _Sink("datastream")
        stream.fail = True
        self.assertEqual(self.poll(engine, NOW, sinks=[wazuh, stream]), cli.EXIT_OK)  # one sink accepted
        self.assertEqual(len(wazuh.delivered), 12)
        stream.fail = False
        self.poll(engine, NOW, sinks=[wazuh, stream])
        self.assertEqual(len(wazuh.delivered), 12)  # the manager does not get them twice
        self.assertEqual(len(stream.delivered), 12)  # the recovered sink catches up

    def test_fallback_takes_what_a_sink_rejected(self):
        engine = _engine()
        self.sink.fail = True
        fallback = _Sink("index")
        self.assertEqual(self.poll(engine, NOW, fallback=fallback), cli.EXIT_OK)
        self.assertEqual(len(fallback.delivered), 12)
        self.assertIsNone(self.watermark().load("wazuh"))  # the primary sink is retried
        self.assertIsNone(self.watermark().load("index"))

    def test_every_sink_failing_is_exit_1(self):
        engine = _engine()
        a, b, fallback = _Sink("wazuh"), _Sink("datastream"), _Sink("index")
        a.fail = b.fail = fallback.fail = True
        self.assertEqual(self.poll(engine, NOW, sinks=[a, b], fallback=fallback), cli.EXIT_ERROR)

    def test_dry_run_writes_a_jsonl_file_and_leaves_the_watermark_alone(self):
        payloads = tempfile.TemporaryDirectory()
        self.addCleanup(payloads.cleanup)
        args = argparse.Namespace(ship=False, debug=False, dry_run=True, payload_dir=payloads.name)
        client = MagicMock()
        client.search_alerts.side_effect = lambda start, end, **kw: _alerts(start, end)
        delivery = cli._build_delivery(self.cfg, client, args, self.detection)
        self.assertEqual([s.name for s in delivery.sinks], ["jsonl"])
        self.assertIsNone(delivery.watermark)
        cli._run_single_detection(self.cfg, client, _engine(), self.detection, args, now=NOW, delivery=delivery)
        lines = (Path(payloads.name) / "anomalies.jsonl").read_text().splitlines()
        self.assertEqual(len(lines), 12)
        self.assertEqual(json.loads(lines[0])["integration"], "sonar")
        self.assertFalse(self.watermark().path.exists())

    def test_state_dir_defaults_to_state_next_to_the_model(self):
        self.cfg.output.state_dir = None
        self.assertEqual(cli._state_dir(self.cfg), "sonar/models/state")


class TestRealtimeLoop(_Base):
    def _loop(self, codes):
        """Run the loop over the given poll results; it stops (Ctrl+C) when they run out."""
        clock = {"now": NOW}
        waits = []
        results = iter(codes)

        def run(cfg, client, engine, detection, args, now, delivery=None):
            try:
                return next(results)
            except StopIteration:
                raise KeyboardInterrupt

        def sleep(seconds):
            waits.append(seconds)
            clock["now"] += timedelta(seconds=seconds)

        with patch.object(cli, "_run_single_detection", side_effect=run):
            code = cli._realtime_loop(self.cfg, MagicMock(), _engine(), self.detection, self.args, now=lambda: clock["now"], sleep=sleep)
        return code, waits

    def test_polls_are_aligned_to_buckets_plus_ingest_delay(self):
        code, waits = self._loop([cli.EXIT_OK, cli.EXIT_OK])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(waits, [210.0, 300.0])  # 12:07:30 -> 12:11:00 -> 12:16:00

    def test_fixed_polling_interval_overrides_alignment(self):
        self.detection.polling_interval_seconds = 42
        _, waits = self._loop([cli.EXIT_OK])
        self.assertEqual(waits, [42.0])

    def test_transient_error_is_retried(self):
        code, waits = self._loop([cli.EXIT_ERROR, cli.EXIT_OK])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(waits[0], cli.RETRY_BASE_SECONDS)

    def test_gives_up_after_max_consecutive_failures(self):
        code, waits = self._loop([cli.EXIT_ERROR] * 5 + [cli.EXIT_OK])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertEqual(waits, [10, 20, 40, 80])

    def test_backoff_is_capped_at_one_bucket(self):
        self.cfg.features.bucket_minutes = 1
        self.detection.max_consecutive_failures = 10
        _, waits = self._loop([cli.EXIT_ERROR] * 5)
        self.assertEqual(waits, [10, 20, 40, 60, 60])

    def test_not_enough_data_is_not_a_failure(self):
        code, _ = self._loop([cli.EXIT_ERROR] * 4 + [cli.EXIT_NOT_ENOUGH_DATA] + [cli.EXIT_ERROR] * 4)
        self.assertEqual(code, cli.EXIT_OK)


class TestSinksDeduplicate(unittest.TestCase):
    DOC = {"anomaly_id": "abc123", "timestamp": "2026-01-01T12:00:00Z"}

    # The anomalies index (WazuhIndexerClient.index_anomaly) is covered in test_indexer_client.py.

    def _shipper(self):
        with patch("sonar.shipper.wazuh_data_shipper.build_opensearch_client"):
            shipper = WazuhDataShipper(WazuhIndexerConfig(), install=False)
        shipper.client = MagicMock()
        return shipper

    def test_data_stream_creates_by_anomaly_id(self):
        shipper = self._shipper()
        shipper.ship_single("stream", dict(self.DOC))
        self.assertEqual(shipper.client.create.call_args.kwargs["id"], "abc123")
        shipper.client.index.assert_not_called()

    def test_data_stream_conflict_counts_as_delivered(self):
        shipper = self._shipper()
        shipper.client.create.side_effect = ConflictError(409, "version_conflict_engine_exception", {})
        self.assertEqual(shipper.ship_single("stream", dict(self.DOC))["_id"], "abc123")

    def test_datastream_sink_counts_existing_documents_as_delivered(self):
        from sonar.sinks.indexer import DataStreamSink

        shipper = self._shipper()
        shipper.client.bulk.return_value = {"errors": True, "items": [{"create": {"status": 409}}, {"create": {"status": 201}}]}
        sink = DataStreamSink(WazuhIndexerConfig(), PipelineConfig().shipping, "brute")
        sink._shipper = shipper
        result = sink.emit([dict(self.DOC), dict(self.DOC, anomaly_id="def456")])
        self.assertTrue(result.ok)
        body = shipper.client.bulk.call_args.kwargs["body"].splitlines()
        self.assertEqual(json.loads(body[0]), {"create": {"_index": "sonar_anomalies_mvad_brute", "_id": "abc123"}})

    def test_datastream_sink_reports_the_accepted_prefix(self):
        from sonar.sinks.indexer import DataStreamSink

        shipper = self._shipper()
        shipper.client.bulk.return_value = {"errors": True, "items": [{"create": {"status": 201}}, {"create": {"status": 400, "error": "mapping"}}]}
        sink = DataStreamSink(WazuhIndexerConfig(), PipelineConfig().shipping, "brute")
        sink._shipper = shipper
        result = sink.emit([dict(self.DOC), dict(self.DOC, anomaly_id="def456")])
        self.assertEqual((result.accepted, result.ok), (1, False))


if __name__ == "__main__":
    unittest.main()
