"""
SONAR on RADAR's linux_resource_utilization data (SRS-081): the packaged scenario, one model per
agent (``--agent``), RADAR's detector results read from the indexer and ``sonar export``.

The indexer is replaced by fakes and mocks; no indexer is contacted.
"""

import argparse
import importlib.util
import json
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from opensearchpy.exceptions import TransportError

from sonar import cli
from sonar.config import PipelineConfig, WazuhIndexerConfig
from sonar.evaluation import Labels, load_external_detections
from sonar.features import WazuhFeatureBuilder
from sonar.local_data_provider import LocalDataProvider
from sonar.wazuh_client import WazuhIndexerClient

PACKAGE = Path(cli.__file__).resolve().parent
SCENARIO = "radar_linux_resource_utilization"
START = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _radar_format():
    """The converter in sonar/test_data (a script directory, not a package)."""
    spec = importlib.util.spec_from_file_location("radar_format", PACKAGE / "test_data" / "radar_format.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _event(minute: int, agent: str = "web-01", cpu: str = "12.50", mem: str = "40.00") -> dict:
    ts = (START + timedelta(minutes=minute)).strftime("%Y-%m-%dT%H:%M:%S.000+0000")
    return {"timestamp": ts, "agent": {"id": "001", "name": agent}, "predecoder": {"program_name": "resource_usage_metric"}, "data": {"cpu_usage_pct": cpu, "mem_usage_pct": mem}}


class TestScenario(unittest.TestCase):
    """The packaged scenario reads what RADAR's detector reads."""

    def setUp(self):
        self.cfg, self.training = cli.load_scenario_for_phase(SCENARIO, "training", None)

    def test_radar_index_fields_and_bucket(self):
        f = self.cfg.features
        self.assertEqual(self.cfg.wazuh.alerts_index_pattern, "wazuh-archives-*")
        self.assertEqual(list(f.numeric_fields), ["data.cpu_usage_pct", "data.mem_usage_pct"])
        self.assertEqual(list(f.max_numeric_fields), ["data.cpu_usage_pct", "data.mem_usage_pct"])
        self.assertEqual((f.bucket_minutes, f.derived_features, list(f.categorical_fields), f.numeric_fill), (1, False, [], "zero"))

    def test_filter_is_radars_without_the_seeded_history(self):
        query = self.cfg.features.alert_filter["bool"]
        self.assertEqual(query["filter"], [{"exists": {"field": "data.mem_usage_pct"}}])
        self.assertEqual(query["must_not"], [{"term": {"radar_seed": True}}])

    def test_requests_only_radar_fields(self):
        self.assertEqual(WazuhFeatureBuilder(self.cfg.features).required_source_fields(), ["timestamp", "data.cpu_usage_pct", "data.mem_usage_pct"])

    def test_string_metrics_and_offset_timestamps(self):
        # RADAR's decoder stores the values as strings; archived events carry +0000 offsets.
        ts = WazuhFeatureBuilder(self.cfg.features).build_timeseries([_event(0, cpu="10.00"), _event(0, cpu="30.00"), _event(2, cpu="5.00")])
        self.assertEqual(list(ts.columns), ["alert_count", "data.cpu_usage_pct", "data.mem_usage_pct", "data.cpu_usage_pct__max", "data.mem_usage_pct__max"])
        self.assertEqual(ts["data.cpu_usage_pct"].tolist(), [20.0, 0.0, 5.0])
        self.assertEqual(ts["data.cpu_usage_pct__max"].tolist(), [30.0, 0.0, 5.0])

    def test_debug_data_resolves_and_matches_the_features(self):
        provider = LocalDataProvider(self.cfg.debug.data_dir, data_file=self.cfg.debug.training_data_file)
        ts = WazuhFeatureBuilder(self.cfg.features).build_timeseries(provider.get_all_alerts())
        self.assertEqual(len(ts), 1440)
        self.assertGreater(ts["data.cpu_usage_pct"].min(), 0.0)

    def test_detection_settings_are_calibrated(self):
        _, detection = cli.load_scenario_for_phase(SCENARIO, "detection", None)
        self.assertEqual((detection.threshold, detection.min_consecutive), (0.25, 5))
        self.assertIsNotNone(detection.anomaly_confidence)


class TestConverter(unittest.TestCase):
    def test_keeps_time_and_agent_and_writes_radars_fields(self):
        alert = {"timestamp": "2024-12-01T00:00:00.000Z", "agent": {"id": "002", "name": "db", "ip": "10.0.0.2"}, "rule": {"level": 3}, "data": {"cpu_usage_%": 7.5, "memory_usage_%": 61.234}}
        other = {"timestamp": "2024-12-01T00:00:00.000Z", "agent": {"name": "web"}, "data": {"cpu_usage_%": 1, "memory_usage_%": 2}}
        events = _radar_format().convert([alert, other, {"timestamp": "x", "data": {}}], agent="db")
        self.assertEqual(
            events,
            [
                {
                    "timestamp": "2024-12-01T00:00:00.000Z",
                    "location": "/var/log/radar/resource_usage_metric.log",
                    "agent": {"id": "002", "name": "db"},
                    "predecoder": {"program_name": "resource_usage_metric"},
                    "data": {"cpu_usage_pct": "7.50", "mem_usage_pct": "61.23"},
                }
            ],
        )


class TestApplyAgent(unittest.TestCase):
    def test_no_agent_changes_nothing(self):
        cfg = PipelineConfig(model_name="m")
        cli.apply_agent(cfg, None)
        self.assertEqual((cfg.model_name, cfg.agent, cfg.features.alert_filter), ("m", None, None))

    def test_agent_joins_the_filter_and_names_the_model_and_scenario(self):
        cfg = PipelineConfig(model_name="radar")
        cfg.features.alert_filter = {"exists": {"field": "data.mem_usage_pct"}}
        cfg.shipping.scenario_id = "res"
        cli.apply_agent(cfg, "Web Server 01")
        self.assertEqual(cfg.features.alert_filter, {"bool": {"filter": [{"exists": {"field": "data.mem_usage_pct"}}, {"term": {"agent.name": "Web Server 01"}}]}})
        self.assertEqual((cfg.model_name, cfg.shipping.scenario_id, cfg.agent), ("radar-web_server_01", "res-web_server_01", "Web Server 01"))

    def test_without_filter_or_scenario_id(self):
        cfg = PipelineConfig(model_name="radar")
        cli.apply_agent(cfg, "db")
        self.assertEqual(cfg.features.alert_filter, {"term": {"agent.name": "db"}})
        self.assertEqual(cli._get_scenario_id(cfg), "radar-db")

    def test_debug_data_is_filtered_by_agent(self):
        # Local files ignore alert_filter, so the agent is applied to them directly.
        cfg = PipelineConfig()
        cfg.agent = "db"
        client = MagicMock()
        client.search_alerts.return_value = [_event(0, agent="db"), _event(0, agent="web"), {"timestamp": "x"}]
        alerts = cli._search_alerts(client, START, START, cfg, debug=True)
        self.assertEqual([a["agent"]["name"] for a in alerts], ["db"])

    def test_per_agent_model_end_to_end_in_debug_mode(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        config = root / "cfg.yaml"
        config.write_text(f"models_dir: {root / 'models'}\nbackend: pca\noutput:\n  debug_sinks: [jsonl]\n  jsonl_path: {root / 'out.jsonl'}\n")
        args = argparse.Namespace(use_case=SCENARIO, config=str(config), mode=None, print_payloads=False, dry_run=False, payload_dir=None, debug=True, ship=False, agent="web-server-02")
        with self.assertNoLogs("sonar.cli", "WARNING"):  # train and detect agree on the features
            self.assertEqual(cli.cmd_scenario(args), 0)
        model = root / "models" / f"{SCENARIO}-web-server-02"
        stored = json.loads((model / "metadata.json").read_text())["feature_config"]["alert_filter"]
        self.assertIn({"term": {"agent.name": "web-server-02"}}, stored["bool"]["filter"])
        events = [json.loads(line) for line in (root / "out.jsonl").read_text().splitlines()]
        self.assertTrue(events)
        self.assertEqual({e["sonar"]["scenario"] for e in events}, {"radar_resource_utilization-web-server-02"})


class FakeScroll:
    """Serves detector results through search(scroll) / scroll / clear_scroll, like OpenSearch."""

    def __init__(self, n, page=3):
        self.docs = [{"detector_id": "d", "data_start_time": i, "data_end_time": i + 60_000, "anomaly_grade": 0.0} for i in range(n)]
        self.page, self.pos, self.cleared, self.search_kw = page, 0, [], None
        self.fail_on_scroll = False

    def _next(self):
        hits = [{"_source": d} for d in self.docs[self.pos : self.pos + self.page]]
        self.pos += self.page
        return {"_scroll_id": "s1", "hits": {"hits": hits}}

    def search(self, **kw):
        self.search_kw = kw
        return self._next()

    def scroll(self, body):
        if self.fail_on_scroll:
            raise TransportError(500, "boom")
        assert body["scroll_id"] == "s1"
        return self._next()

    def clear_scroll(self, body):
        self.cleared.append(body["scroll_id"])


def _scroll_client(fake, **cfg):
    with patch("sonar.wazuh_client.build_opensearch_client", return_value=fake):
        return WazuhIndexerClient(WazuhIndexerConfig(**cfg))


class TestDetectorResults(unittest.TestCase):
    def test_reads_every_page_and_clears_the_scroll(self):
        fake = FakeScroll(7)
        results = _scroll_client(fake).search_detector_results("opensearch-ad-plugin-result-x*", START, START + timedelta(hours=1))
        self.assertEqual([r["data_start_time"] for r in results], list(range(7)))
        self.assertEqual(fake.cleared, ["s1"])
        self.assertEqual(fake.search_kw["index"], "opensearch-ad-plugin-result-x*")
        query = fake.search_kw["body"]["query"]["bool"]["filter"]
        self.assertEqual(query, [{"range": {"data_start_time": {"gte": START.isoformat(), "lt": (START + timedelta(hours=1)).isoformat()}}}])

    def test_entity_filter_is_nested(self):
        fake = FakeScroll(0)
        _scroll_client(fake).search_detector_results("r", START, START, entity="web-01")
        nested = fake.search_kw["body"]["query"]["bool"]["filter"][1]["nested"]
        self.assertEqual(nested["path"], "entity")
        self.assertEqual(nested["query"]["bool"]["filter"], [{"term": {"entity.name": "agent.name"}}, {"term": {"entity.value": "web-01"}}])

    def test_scroll_is_cleared_when_a_page_fails(self):
        fake = FakeScroll(7)
        fake.fail_on_scroll = True
        with self.assertRaises(TransportError):
            _scroll_client(fake).search_detector_results("r", START, START)
        self.assertEqual(fake.cleared, ["s1"])

    def test_cap(self):
        fake = FakeScroll(10)
        with self.assertLogs("sonar.wazuh_client", "WARNING"):
            results = _scroll_client(fake, max_alerts=4).search_detector_results("r", START, START)
        self.assertEqual(len(results), 4)


class TestExport(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.client = MagicMock()
        self.client.check_connection.return_value = True
        self.client.search_alerts.return_value = [_event(0), _event(1)]
        self.client.search_detector_results.return_value = [{"data_start_time": 1, "data_end_time": 2, "anomaly_grade": 0.4}]

    def _args(self, **kw):
        base = dict(scenario=SCENARIO, config=None, start="2026-01-01T12:00:30Z", end="2026-01-01T14:00:00", output_dir=str(self.root / "out"), agent=None, context_minutes=None, radar_results=None, event=None)
        base.update(kw)
        return argparse.Namespace(**base)

    def _run(self, expected=0, **kw):
        with patch("sonar.cli.WazuhIndexerClient", return_value=self.client):
            self.assertEqual(cli.cmd_export(self._args(**kw)), expected)

    def test_window_context_filter_and_files(self):
        self._run(radar_results="opensearch-ad-plugin-result-linux-resource-utilization*", agent="web-01", event=["cpu_spike,2026-01-01T12:30:00Z,2026-01-01T12:45:00Z", "cpu_spike,2026-01-01T13:00:00,2026-01-01T13:05:00"])
        start, end = datetime(2026, 1, 1, 12, tzinfo=timezone.utc), datetime(2026, 1, 1, 14, tzinfo=timezone.utc)
        (fetch_start, fetch_end), kw = self.client.search_alerts.call_args.args, self.client.search_alerts.call_args.kwargs
        # MVAD with sliding_window 120 needs 119 one-minute buckets before the first verdict.
        self.assertEqual((fetch_start, fetch_end), (start - timedelta(minutes=119), end))
        self.assertIn({"term": {"agent.name": "web-01"}}, kw["query"]["bool"]["filter"])
        self.assertEqual(self.client.search_detector_results.call_args.args, ("opensearch-ad-plugin-result-linux-resource-utilization*", start, end))
        self.assertEqual(self.client.search_detector_results.call_args.kwargs, {"entity": "web-01", "entity_field": "agent.name"})

        out = self.root / "out"
        self.assertEqual(len(LocalDataProvider(str(out), data_file="events.json").get_all_alerts()), 2)
        labels = Labels.from_file(str(out / "labels.json"))
        self.assertEqual((labels.span_start.to_pydatetime(), labels.span_end.to_pydatetime()), (start, end))
        self.assertEqual([(e.id, e.type) for e in labels.events], [("cpu_spike_1", "cpu_spike"), ("cpu_spike_2", "cpu_spike")])
        self.assertEqual(len(load_external_detections(str(out / "radar_results.json"))), 1)

    def test_explicit_context_and_no_radar_results(self):
        self._run(context_minutes=0)
        self.assertEqual(self.client.search_alerts.call_args.args[0], datetime(2026, 1, 1, 12, tzinfo=timezone.utc))
        self.client.search_detector_results.assert_not_called()
        self.assertFalse((self.root / "out" / "radar_results.json").exists())
        self.assertEqual(Labels.from_file(str(self.root / "out" / "labels.json")).events, [])

    def test_no_alerts_is_exit_2(self):
        self.client.search_alerts.return_value = []
        self._run(expected=2)

    def test_invalid_input_fails_before_connecting(self):
        for kw in ({"event": ["cpu_spike,2026-01-01T12:30:00Z"]}, {"event": ["x,2026-01-02T00:00:00Z,2026-01-02T01:00:00Z"]}, {"event": ["x,2026-01-01T13:00:00Z,2026-01-01T12:00:00Z"]}, {"end": "2026-01-01T12:00:00Z"}):
            with self.subTest(**kw):
                self._run(expected=1, **kw)
        self.client.check_connection.assert_not_called()


if __name__ == "__main__":
    unittest.main()
