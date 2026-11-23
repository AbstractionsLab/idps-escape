"""
Anomaly sinks (sonar/sinks/): the SONAR event for the Wazuh manager, the file and API
transports, the rules, sink selection, and the guard that keeps SONAR's own alerts out of
its input. No Wazuh manager or indexer is contacted.
"""

import argparse
import io
import json
import re
import tempfile
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests

from sonar import cli
from sonar.config import PipelineConfig, WazuhIndexerConfig, WazuhSinkConfig
from sonar.local_data_provider import LocalDataProvider
from sonar.scenario import DetectionScenario
from sonar.sinks.events import event_line, severity_band, wazuh_event
from sonar.sinks.local import JsonlSink, StdoutSink
from sonar.sinks.wazuh import MAX_EVENTS_PER_REQUEST, RULES_FILE, ApiTransport, FileTransport, WazuhApi, WazuhApiError, WazuhSink

REPO = Path(__file__).resolve().parents[2]

DOC = {
    "anomaly_id": "a1",
    "timestamp": "2026-11-19T10:05:00+00:00",
    "anomaly_score": 0.82,
    "anomaly_confidence": 0.7,
    "scenario_name": "brute_force",
    "model_name": "brute_force",
    "bucket_minutes": 5,
    "mvad_score": 1.41,
    "mvad_interpretation": [{"variable": "alert_count", "contribution": 0.61, "value": 212.0}, {"variable": "rule.level", "contribution": 0.2, "value": float("nan")}],
}


def _response(status, body=None, headers=None):
    resp = MagicMock(status_code=status, headers=headers or {}, text=json.dumps(body or {}))
    resp.json.return_value = body or {}
    return resp


class TestEvent(unittest.TestCase):
    def test_shape(self):
        event = wazuh_event(DOC)
        self.assertEqual(event["integration"], "sonar")
        self.assertEqual((event["anomaly_grade"], event["anomaly_confidence"]), (0.82, 0.7))
        sonar = event["sonar"]
        self.assertEqual(sonar["bucket_start"], "2026-11-19T10:05:00Z")
        self.assertEqual((sonar["scenario"], sonar["model"], sonar["anomaly_id"], sonar["severity_band"]), ("brute_force", "brute_force", "a1", "high"))
        self.assertEqual(sonar["top_contributors"][0], {"variable": "alert_count", "contribution": 0.61, "value": 212.0})

    def test_line_is_single_line_valid_json_without_nan(self):
        line = event_line(wazuh_event(DOC))
        self.assertNotIn("\n", line)
        self.assertIsNone(json.loads(line)["sonar"]["top_contributors"][1]["value"])

    def test_uncalibrated_confidence_defaults_to_one_half(self):
        self.assertEqual(wazuh_event(dict(DOC, anomaly_confidence=None))["anomaly_confidence"], 0.5)

    def test_bands(self):
        self.assertEqual([severity_band(v) for v in (0.0, 0.49, 0.5, 0.79, 0.8, 1.0)], ["low", "low", "medium", "medium", "high", "high"])
        self.assertEqual(severity_band(0.6, medium=0.3, high=0.6), "high")


class TestFileTransport(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = Path(self.dir.name) / "sub" / "anomalies.json"

    def test_appends_one_line_per_event(self):
        sink = WazuhSink(WazuhSinkConfig(file_path=str(self.path)))
        self.assertTrue(sink.emit([DOC, dict(DOC, anomaly_id="a2")]).ok)
        self.assertTrue(sink.emit([dict(DOC, anomaly_id="a3")]).ok)
        lines = self.path.read_text().splitlines()
        self.assertEqual([json.loads(line)["sonar"]["anomaly_id"] for line in lines], ["a1", "a2", "a3"])

    def test_rotates_by_size(self):
        transport = FileTransport(str(self.path), max_bytes=100, backup_count=2)
        for i in range(4):
            transport.send(["x" * 60 + str(i)])
        self.assertEqual(self.path.read_text(), "x" * 60 + "3\n")
        self.assertEqual(Path(f"{self.path}.1").read_text(), "x" * 60 + "2\n")
        self.assertEqual(Path(f"{self.path}.2").read_text(), "x" * 60 + "1\n")
        self.assertFalse(Path(f"{self.path}.3").exists())

    def test_unwritable_file_is_a_failed_delivery(self):
        blocker = Path(self.dir.name) / "file"
        blocker.write_text("")
        result = WazuhSink(WazuhSinkConfig(file_path=str(blocker / "anomalies.json"))).emit([DOC])
        self.assertEqual((result.accepted, result.ok), (0, False))


class TestApiTransport(unittest.TestCase):
    def _api(self, responses, sleep=None):
        session = MagicMock()
        session.post.return_value = _response(200, {"data": {"token": "T1"}})
        session.request.side_effect = responses
        return WazuhApi("https://manager:55000/", "sonar", "pw", verify="/ca.pem", session=session, sleep=sleep or MagicMock()), session

    def test_authenticates_once_and_batches(self):
        ok = _response(200, {"data": {"total_affected_items": 1, "total_failed_items": 0}})
        api, session = self._api([ok, ok, ok])
        accepted, error = ApiTransport(api).send([f"e{i}" for i in range(2 * MAX_EVENTS_PER_REQUEST + 1)])
        self.assertEqual((accepted, error), (2 * MAX_EVENTS_PER_REQUEST + 1, None))
        self.assertEqual(session.post.call_count, 1)
        self.assertEqual(session.post.call_args.kwargs["auth"], ("sonar", "pw"))
        sizes = [len(c.kwargs["json"]["events"]) for c in session.request.call_args_list]
        self.assertEqual(sizes, [MAX_EVENTS_PER_REQUEST, MAX_EVENTS_PER_REQUEST, 1])
        method, url = session.request.call_args.args
        self.assertEqual((method, url), ("POST", "https://manager:55000/events"))
        self.assertEqual(session.request.call_args.kwargs["headers"]["Authorization"], "Bearer T1")
        self.assertEqual(session.verify, "/ca.pem")

    def test_reauthenticates_on_401(self):
        api, session = self._api([_response(401), _response(200, {"data": {}})])
        self.assertEqual(ApiTransport(api).send(["e"]), (1, None))
        self.assertEqual(session.post.call_count, 2)

    def test_backs_off_on_429(self):
        sleep = MagicMock()
        api, _ = self._api([_response(429, headers={"Retry-After": "7"}), _response(429), _response(200, {"data": {}})], sleep=sleep)
        self.assertEqual(ApiTransport(api).send(["e"]), (1, None))
        self.assertEqual([c.args[0] for c in sleep.call_args_list], [7.0, 4.0])

    def test_gives_up_after_repeated_429(self):
        api, _ = self._api([_response(429)] * 5)
        accepted, error = ApiTransport(api).send(["e"])
        self.assertEqual(accepted, 0)
        self.assertIn("429", error)

    def test_reports_the_accepted_prefix(self):
        ok = _response(200, {"data": {"total_failed_items": 0}})
        rejected = _response(200, {"data": {"total_failed_items": 2, "failed_items": [{"error": "x"}]}})
        api, _ = self._api([ok, rejected])
        accepted, error = ApiTransport(api).send(["e"] * (MAX_EVENTS_PER_REQUEST + 5))
        self.assertEqual(accepted, MAX_EVENTS_PER_REQUEST)
        self.assertIn("rejected 2", error)

    def test_unreachable_manager(self):
        api, session = self._api([])
        session.post.side_effect = requests.ConnectionError("refused")
        accepted, error = ApiTransport(api).send(["e"])
        self.assertEqual(accepted, 0)
        self.assertIn("cannot reach", error)

    def test_password_from_environment(self):
        from sonar.sinks.wazuh import api_from_config

        with patch.dict("os.environ", {"SONAR_WAZUH_API_PASSWORD": "from-env"}):
            self.assertEqual(api_from_config(WazuhSinkConfig(transport="api")).password, "from-env")
            self.assertEqual(api_from_config(WazuhSinkConfig(transport="api", api_password="from-config")).password, "from-config")


class TestLocalSinks(unittest.TestCase):
    def test_stdout_prints_events(self):
        out = io.StringIO()
        self.assertTrue(StdoutSink(stream=out).emit([DOC]).ok)
        self.assertEqual(json.loads(out.getvalue())["sonar"]["anomaly_id"], "a1")

    def test_jsonl_appends_events(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "x.jsonl"
            JsonlSink(str(path)).emit([DOC])
            JsonlSink(str(path)).emit([DOC])
            self.assertEqual(len(path.read_text().splitlines()), 2)


class TestRules(unittest.TestCase):
    def _rules(self):
        text = RULES_FILE.read_text()
        return ET.fromstring(f"<root>{text}</root>").iter("rule")

    def test_well_formed_ids_in_range_and_unique(self):
        ids = [int(rule.get("id")) for rule in self._rules()]
        self.assertEqual(ids, [100500, 100501, 100502, 100503])
        self.assertTrue(all(100500 <= i <= 100519 for i in ids))

    def test_no_collision_with_radar_rules(self):
        radar_ids = set()
        for path in (REPO / "radar").rglob("*.xml"):
            radar_ids.update(int(m) for m in re.findall(r'<rule\s+id="(\d+)"', path.read_text(errors="ignore")))
        self.assertTrue(radar_ids, "no RADAR rules found")
        self.assertFalse(set(range(100500, 100520)) & radar_ids)

    def test_rules_match_the_event(self):
        rules = {int(r.get("id")): r for r in self._rules()}
        base = rules[100500]
        self.assertEqual(base.findtext("decoded_as"), "json")
        self.assertEqual(base.find("field").attrib["name"], "integration")
        self.assertEqual(base.find("field").text, f"^{wazuh_event(DOC)['integration']}$")
        bands = {rid: (r.findtext("if_sid"), r.find("field").attrib["name"], r.find("field").text, int(r.get("level"))) for rid, r in rules.items() if rid != 100500}
        self.assertEqual(
            bands,
            {100501: ("100500", "sonar.severity_band", "^low$", 3), 100502: ("100500", "sonar.severity_band", "^medium$", 7), 100503: ("100500", "sonar.severity_band", "^high$", 10)},
        )

    def test_rule_group_is_the_one_searches_exclude(self):
        group = ET.fromstring(f"<root>{RULES_FILE.read_text()}</root>").find("group").get("name")
        self.assertIn("sonar", group.split(","))
        self.assertIn("sonar", WazuhIndexerConfig().exclude_rule_groups)


class TestOwnAlertsExcluded(unittest.TestCase):
    def _body(self, **cfg):
        from sonar.wazuh_client import WazuhIndexerClient

        fake = MagicMock()
        fake.create_pit.return_value = {"pit_id": "p"}
        fake.search.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
        with patch("sonar.wazuh_client.build_opensearch_client", return_value=fake):
            WazuhIndexerClient(WazuhIndexerConfig(**cfg)).search_alerts(datetime(2026, 1, 1, tzinfo=timezone.utc), datetime(2026, 1, 2, tzinfo=timezone.utc))
        return fake.search.call_args.kwargs["body"]["query"]["bool"]

    def test_sonar_alerts_are_never_read(self):
        self.assertEqual(self._body()["must_not"], [{"terms": {"rule.groups": ["sonar"]}}])

    def test_can_be_disabled(self):
        self.assertNotIn("must_not", self._body(exclude_rule_groups=[]))


class TestSinkSelection(unittest.TestCase):
    def setUp(self):
        self.cfg = PipelineConfig()
        self.cfg.shipping.scenario_id = "s"
        self.args = argparse.Namespace(ship=False, debug=False, dry_run=False, print_payloads=False, payload_dir=None)

    def names(self, client=None, detection=None, **args):
        delivery = cli._build_delivery(self.cfg, client or MagicMock(), argparse.Namespace(**{**vars(self.args), **args}), detection or DetectionScenario(anomaly_confidence=0.6))
        return [s.name for s in delivery.sinks], delivery

    def test_default_is_the_wazuh_sink_with_watermark(self):
        names, delivery = self.names()
        self.assertEqual(names, ["wazuh"])
        self.assertIsNotNone(delivery.watermark)
        self.assertIsNone(delivery.fallback)

    def test_ship_adds_the_data_stream(self):
        self.assertEqual(self.names(ship=True)[0], ["wazuh", "datastream"])

    def test_debug_uses_debug_sinks_without_watermark(self):
        provider = MagicMock(spec=LocalDataProvider)
        names, delivery = self.names(client=provider, ship=True)
        self.assertEqual(names, ["stdout"])
        self.assertIsNone(delivery.watermark)

    def test_print_payloads_adds_stdout(self):
        self.assertEqual(self.names(print_payloads=True)[0], ["wazuh", "stdout"])

    def test_fallback(self):
        self.cfg.output.fallback = "index"
        self.assertEqual(self.names()[1].fallback.name, "index")
        self.cfg.output.fallback = "elsewhere"
        with self.assertRaises(ValueError):
            self.names()

    def test_unknown_sink(self):
        self.cfg.output.sinks = ["wazuh", "kafka"]
        with self.assertRaises(ValueError):
            self.names()

    def test_index_sink_needs_the_indexer(self):
        self.cfg.output.debug_sinks = ["index"]
        with self.assertRaises(ValueError):
            self.names(client=MagicMock(spec=LocalDataProvider))

    def test_uncalibrated_confidence_warns(self):
        with self.assertLogs("sonar.cli", "WARNING") as logs:
            self.names(detection=DetectionScenario())
        self.assertTrue(any("anomaly_confidence" in line for line in logs.output))

    def test_output_section_from_yaml(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write("output:\n  sinks: [wazuh, datastream]\n  fallback: index\n  wazuh:\n    transport: api\n    api_url: https://m:55000\n")
            path = f.name
        try:
            cfg = cli.load_config(path)
        finally:
            Path(path).unlink()
        self.assertEqual((cfg.output.sinks, cfg.output.fallback), (["wazuh", "datastream"], "index"))
        self.assertEqual((cfg.output.wazuh.transport, cfg.output.wazuh.api_url, cfg.output.wazuh.file_path), ("api", "https://m:55000", "/var/log/sonar/anomalies.json"))

    def test_bad_transport(self):
        self.cfg.output.wazuh.transport = "syslog"
        with self.assertRaises(ValueError):
            self.names()


class TestOutputValidatedBeforeTraining(unittest.TestCase):
    def test_validate_output(self):
        cli._validate_output(PipelineConfig())
        for key, bad in (("sinks", ["wazuh", "kafka"]), ("debug_sinks", ["printer"]), ("fallback", "elsewhere")):
            cfg = PipelineConfig()
            setattr(cfg.output, key, bad)
            with self.assertRaises(ValueError):
                cli._validate_output(cfg)
        cfg = PipelineConfig()
        cfg.output.wazuh.transport = "syslog"
        with self.assertRaises(ValueError):
            cli._validate_output(cfg)

    def test_scenario_with_a_bad_sink_fails_before_training(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write("name: t\nmodel_name: t\ntraining:\n  lookback_hours: 1\ndetection:\n  lookback_minutes: 10\noutput:\n  sinks: [wazuh, kafka]\n")
            path = f.name
        try:
            with patch.object(cli, "_execute_training_phase") as train:
                code = cli.cmd_scenario(argparse.Namespace(use_case=path, config=None, mode=None))
        finally:
            Path(path).unlink()
        self.assertEqual(code, cli.EXIT_ERROR)
        train.assert_not_called()


class TestDebugRunExercisesTheOutputPath(unittest.TestCase):
    def test_debug_detection_prints_events(self):
        from tests.sonartests.test_realtime_delivery import NOW, _alerts, _engine

        cfg = PipelineConfig()
        cfg.shipping.scenario_id = "s"
        provider = MagicMock(spec=LocalDataProvider)
        provider.search_alerts.side_effect = lambda *a, **k: _alerts(NOW - timedelta(hours=3), NOW - timedelta(minutes=5))
        out = io.StringIO()
        delivery = cli._Delivery([StdoutSink(stream=out)])
        code = cli._run_single_detection(cfg, provider, _engine(), DetectionScenario(lookback_minutes=60), argparse.Namespace(debug=True), now=NOW, delivery=delivery)
        self.assertEqual(code, cli.EXIT_OK)
        events = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertTrue(events)
        self.assertTrue(all(e["integration"] == "sonar" for e in events))


class TestInstallRules(unittest.TestCase):
    def _run(self, *argv, responses=None, env=None):
        session = MagicMock()
        session.post.return_value = _response(200, {"data": {"token": "T"}})
        session.request.side_effect = responses or [_response(200, {}), _response(200, {})]
        env = {"SONAR_WAZUH_ADMIN_PASSWORD": "pw"} if env is None else env
        clean = {k: v for k, v in __import__("os").environ.items() if not k.startswith("SONAR_WAZUH_")}
        with patch("sonar.sinks.wazuh.requests.Session", return_value=session), patch.dict("os.environ", {**clean, **env}, clear=True), patch("sys.argv", ["sonar", "wazuh", "install-rules", *argv]), patch(
            "sys.stdin.isatty", return_value=False
        ):
            code = cli.main()
        return code, session

    def test_admin_does_not_get_the_ingest_password(self):
        _, session = self._run("--user", "admin", env={"SONAR_WAZUH_API_PASSWORD": "ingest-pw"})
        self.assertEqual(session.post.call_args.kwargs["auth"], ("admin", ""))

    def test_without_user_the_sink_password_applies(self):
        _, session = self._run(env={"SONAR_WAZUH_API_PASSWORD": "ingest-pw"})
        self.assertEqual(session.post.call_args.kwargs["auth"], ("sonar", "ingest-pw"))

    def test_uploads_the_rules_file(self):
        code, session = self._run("--api-url", "https://m:55000", "--user", "admin")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(session.post.call_args.kwargs["auth"], ("admin", "pw"))
        method, url = session.request.call_args.args
        self.assertEqual((method, url), ("PUT", "https://m:55000/rules/files/sonar_rules.xml"))
        self.assertEqual(session.request.call_args.kwargs["params"], {"overwrite": "true"})
        self.assertEqual(session.request.call_args.kwargs["data"], RULES_FILE.read_bytes())

    def test_restart(self):
        _, session = self._run("--restart")
        self.assertEqual(session.request.call_args.args, ("PUT", "https://localhost:55000/manager/restart"))

    def test_failure_is_exit_1(self):
        code, _ = self._run(responses=[_response(403, {"detail": "Permission denied"})])
        self.assertEqual(code, cli.EXIT_ERROR)


class TestApiErrors(unittest.TestCase):
    def test_error_carries_status(self):
        session = MagicMock()
        session.post.return_value = _response(401)
        with self.assertRaises(WazuhApiError) as ctx:
            WazuhApi("https://m", "u", "p", session=session).request("GET", "/")
        self.assertEqual(ctx.exception.status, 401)


if __name__ == "__main__":
    unittest.main()
