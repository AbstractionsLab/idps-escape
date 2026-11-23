"""
Indexer access (sonar/indexer.py, sonar/wazuh_client.py): one OpenSearch client for search
and shipping, paginated alert search with a point-in-time, source filtering and the cap.

The OpenSearch client is replaced by an in-memory fake; no indexer is contacted.
"""

import math
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from opensearchpy.exceptions import ConflictError, TransportError

from sonar import cli
from sonar.config import FeatureConfig, PipelineConfig, WazuhIndexerConfig
from sonar.features import DERIVED_FEATURE_FIELDS, DERIVED_FEATURES, WazuhFeatureBuilder, get_nested_field
from sonar.indexer import build_opensearch_client, json_safe, tls_options
from sonar.shipper.wazuh_data_shipper import WazuhDataShipper
from sonar.wazuh_client import WazuhIndexerClient

START = datetime(2026, 1, 1, tzinfo=timezone.utc)


class FakeIndexer:
    """Serves `n` alerts through create_pit / search(search_after) / delete_pit, like OpenSearch."""

    def __init__(self, n, same_timestamp_every=3):
        # Several alerts share a timestamp, so the tiebreaker matters.
        self.docs = []
        for i in range(n):
            ts = START + timedelta(seconds=i // same_timestamp_every)
            self.docs.append({"timestamp": ts.isoformat(), "id": f"{int(ts.timestamp())}.{i:06d}", "rule": {"level": 3}, "full_log": "x" * 10})
        self.bodies, self.closed, self.pits = [], [], 0
        self.fail_on_page = None

    def create_pit(self, index, params):
        self.pits += 1
        self.pit_index, self.pit_params = index, params
        return {"pit_id": f"pit-{self.pits}"}

    def delete_pit(self, body):
        self.closed.extend(body["pit_id"])

    @staticmethod
    def _key(doc):
        return (datetime.fromisoformat(doc["timestamp"]).timestamp() * 1000, doc["id"])

    def search(self, body, **kw):
        assert "index" not in kw, "a point-in-time search must not name an index"
        self.bodies.append(body)
        if self.fail_on_page is not None and len(self.bodies) == self.fail_on_page:
            raise TransportError(500, "boom")
        ordered = sorted(self.docs, key=self._key, reverse=True)
        if "search_after" in body:
            after = tuple(body["search_after"])
            ordered = [d for d in ordered if self._key(d) < after]
        page = ordered[: body["size"]]
        hits = [{"_source": {k: v for k, v in d.items() if "_source" not in body or k in body["_source"]}, "sort": list(self._key(d))} for d in page]
        total = {"value": len(self.docs), "relation": "eq"} if body.get("track_total_hits") else {"value": 10_000, "relation": "gte"}
        return {"pit_id": body["pit"]["id"], "hits": {"total": total, "hits": hits}}


def _client(fake, **cfg):
    with patch("sonar.wazuh_client.build_opensearch_client", return_value=fake):
        return WazuhIndexerClient(WazuhIndexerConfig(**cfg))


class TestPaginatedSearch(unittest.TestCase):
    def test_returns_every_alert_in_timestamp_order_and_closes_the_pit(self):
        fake = FakeIndexer(25_000)
        alerts = _client(fake).search_alerts(START, START + timedelta(days=1))
        self.assertEqual(len(alerts), 25_000)
        self.assertEqual(len({a["id"] for a in alerts}), 25_000)
        self.assertEqual([a["id"] for a in alerts], sorted((a["id"] for a in alerts), key=lambda i: (int(i.split(".")[0]), i)))
        self.assertEqual([b["size"] for b in fake.bodies], [10_000, 10_000, 10_000])
        self.assertEqual(fake.closed, ["pit-1"])
        self.assertEqual((fake.pit_index, fake.pit_params), ("wazuh-alerts-*", {"keep_alive": "2m"}))

    def test_query_contract(self):
        fake = FakeIndexer(5)
        alert_filter = {"terms": {"rule.groups": ["sshd"]}}
        end = START + timedelta(hours=1)
        _client(fake).search_alerts(START, end, query=alert_filter)
        body = fake.bodies[0]
        self.assertEqual(body["query"]["bool"]["filter"], [{"range": {"timestamp": {"gte": START.isoformat(), "lt": end.isoformat()}}}])
        self.assertEqual(body["query"]["bool"]["must"], [alert_filter])
        self.assertEqual([list(s)[0] for s in body["sort"]], ["timestamp", "id"])
        self.assertEqual(body["pit"], {"id": "pit-1", "keep_alive": "2m"})
        self.assertTrue(body["track_total_hits"])

    def test_no_must_without_filter(self):
        fake = FakeIndexer(5)
        _client(fake).search_alerts(START, START + timedelta(hours=1))
        self.assertNotIn("must", fake.bodies[0]["query"]["bool"])

    def test_total_is_counted_on_the_first_page_only(self):
        fake = FakeIndexer(25_000)
        _client(fake).search_alerts(START, START + timedelta(days=1))
        self.assertEqual([b["track_total_hits"] for b in fake.bodies], [True, False, False])

    def test_requests_only_the_given_fields(self):
        fake = FakeIndexer(5)
        alerts = _client(fake).search_alerts(START, START + timedelta(hours=1), source_fields=["timestamp", "rule.level"])
        self.assertEqual(fake.bodies[0]["_source"], ["timestamp", "rule.level"])
        self.assertNotIn("full_log", alerts[0])

    def test_pit_is_closed_when_a_page_fails(self):
        fake = FakeIndexer(25_000)
        fake.fail_on_page = 2
        with self.assertRaises(TransportError):
            _client(fake).search_alerts(START, START + timedelta(days=1))
        self.assertEqual(fake.closed, ["pit-1"])

    def test_cap_keeps_the_most_recent_alerts_and_warns(self):
        fake = FakeIndexer(25_000)
        with self.assertLogs("sonar.wazuh_client", "WARNING") as logs:
            alerts = _client(fake, max_alerts=15_000).search_alerts(START, START + timedelta(days=1))
        self.assertEqual(len(alerts), 15_000)
        self.assertEqual(alerts[-1]["id"], max(fake.docs, key=FakeIndexer._key)["id"])
        self.assertLess(alerts[0]["timestamp"], alerts[-1]["timestamp"])
        self.assertIn("25000", logs.output[0])
        self.assertIn("max_alerts", logs.output[0])

    def test_empty_result(self):
        fake = FakeIndexer(0)
        self.assertEqual(_client(fake).search_alerts(START, START + timedelta(hours=1)), [])
        self.assertEqual(fake.closed, ["pit-1"])


class TestIndexAnomaly(unittest.TestCase):
    DOC = {"anomaly_id": "abc123", "timestamp": "2026-01-01T12:00:00Z", "anomaly_score": float("nan")}

    def test_creates_by_anomaly_id_with_json_safe_body(self):
        fake = MagicMock()
        fake.create.return_value = {"_id": "abc123"}
        self.assertEqual(_client(fake).index_anomaly(dict(self.DOC)), "abc123")
        kwargs = fake.create.call_args.kwargs
        self.assertEqual((kwargs["index"], kwargs["id"]), ("wazuh-anomalies-mvad", "abc123"))
        self.assertIsNone(kwargs["body"]["anomaly_score"])  # NaN is not valid JSON
        fake.index.assert_not_called()

    def test_conflict_counts_as_delivered(self):
        fake = MagicMock()
        fake.create.side_effect = ConflictError(409, "version_conflict_engine_exception", {})
        self.assertEqual(_client(fake).index_anomaly(dict(self.DOC)), "abc123")

    def test_other_errors_still_fail(self):
        fake = MagicMock()
        fake.create.side_effect = TransportError(503, "unavailable")
        with self.assertRaises(TransportError):
            _client(fake).index_anomaly(dict(self.DOC))

    def test_without_id_indexes_a_new_document(self):
        fake = MagicMock()
        fake.index.return_value = {"_id": "generated"}
        self.assertEqual(_client(fake).index_anomaly({"timestamp": "2026-01-01T12:00:00Z"}), "generated")
        fake.create.assert_not_called()

    def test_dry_run_sends_nothing(self):
        fake = MagicMock()
        with patch("sonar.wazuh_client.build_opensearch_client", return_value=fake), patch("sonar.wazuh_client.os.makedirs"):
            client = WazuhIndexerClient(WazuhIndexerConfig(), dry_run=True)
        with patch.object(client, "_save_payload") as save:
            self.assertEqual(client.index_anomaly(dict(self.DOC)), "dryrun-abc123")
        save.assert_called_once()
        fake.create.assert_not_called()
        fake.index.assert_not_called()

    def test_check_connection(self):
        fake = MagicMock()
        fake.ping.return_value = True
        self.assertTrue(_client(fake).check_connection())
        fake.ping.side_effect = ConnectionError("refused")
        self.assertFalse(_client(fake).check_connection())


class TestJsonSafe(unittest.TestCase):
    def test_converts_types_the_indexer_cannot_take(self):
        import numpy as np
        import pandas as pd

        out = json_safe({"t": pd.Timestamp("2026-01-01T12:00:00Z"), "n": np.float64(1.5), "i": np.int64(3), "bad": [math.inf, float("nan")]})
        self.assertEqual(out, {"t": "2026-01-01T12:00:00+00:00", "n": 1.5, "i": 3, "bad": [None, None]})


class TestOneConnection(unittest.TestCase):
    def test_tls_options(self):
        self.assertEqual(tls_options(False), {"verify_certs": False, "ssl_show_warn": False})
        self.assertEqual(tls_options(True), {"verify_certs": True})
        self.assertEqual(tls_options("/etc/sonar/root-ca.pem"), {"verify_certs": True, "ca_certs": "/etc/sonar/root-ca.pem"})

    def test_client_arguments(self):
        cfg = WazuhIndexerConfig(base_url="https://indexer.example:9201/", username="u", password="p", verify_ssl="/ca.pem", timeout_seconds=12)
        with patch("sonar.indexer.OpenSearch") as opensearch:
            build_opensearch_client(cfg)
        kwargs = opensearch.call_args.kwargs
        self.assertEqual(kwargs["hosts"], ["https://indexer.example:9201"])
        self.assertEqual(kwargs["http_auth"], ("u", "p"))
        self.assertEqual(kwargs["timeout"], 12.0)
        self.assertEqual((kwargs["verify_certs"], kwargs["ca_certs"]), (True, "/ca.pem"))

    def test_ca_bundle_reaches_search_and_shipping(self):
        cfg = WazuhIndexerConfig(verify_ssl="/ca.pem")
        with patch("sonar.indexer.OpenSearch") as opensearch:
            WazuhIndexerClient(cfg)
            WazuhDataShipper(cfg, install=False)
        self.assertEqual(opensearch.call_count, 2)
        for call in opensearch.call_args_list:
            self.assertEqual(call.kwargs["ca_certs"], "/ca.pem")


class TestRequiredSourceFields(unittest.TestCase):
    def test_lists_every_field_the_features_read(self):
        cfg = FeatureConfig(
            numeric_fields=("rule.level", "data.cpu_usage_%"),
            max_numeric_fields=("data.cpu_usage_%",),
            categorical_fields=("agent.name",),
            derived_features=["is_ssh_event", "is_memory_high", "is_high_severity"],
        )
        self.assertEqual(
            WazuhFeatureBuilder(cfg).required_source_fields(),
            ["timestamp", "rule.level", "data.cpu_usage_%", "agent.name", "rule.groups", "data.memory_usage_%"],
        )

    def test_every_derived_feature_declares_its_fields(self):
        self.assertEqual(set(DERIVED_FEATURES), set(DERIVED_FEATURE_FIELDS))

    def test_derived_features_need_nothing_else(self):
        # Each predicate gives the same answer on an alert cut down to its declared fields.
        alerts = [
            {"rule": {"level": lvl, "groups": groups, "description": "d"}, "data": {"cpu_usage_%": v, "memory_usage_%": v, "1min_loadAverage": v / 10}, "agent": {"name": "a"}}
            for lvl, groups, v in [
                (3, ["sshd", "authentication_failed"], 50.0),
                (12, ["sudo", "brute_force", "windows_logon"], 99.0),
                (10, ["authentication_success", "su"], 85.0),
            ]
        ]
        for name, fields in DERIVED_FEATURE_FIELDS.items():
            for alert in alerts:
                projected = {}
                for path in fields:
                    value = get_nested_field(alert, path)
                    node = projected
                    *parents, leaf = path.split(".")
                    for part in parents:
                        node = node.setdefault(part, {})
                    node[leaf] = value
                self.assertEqual(DERIVED_FEATURES[name](projected), DERIVED_FEATURES[name](alert), name)

    def test_cli_requests_the_model_fields(self):
        cfg = PipelineConfig()
        cfg.features = FeatureConfig(numeric_fields=("rule.level",), derived_features=["is_ssh_event"], alert_filter={"term": {"agent.name": "a"}})
        client = MagicMock()
        cli._search_alerts(client, START, START + timedelta(hours=1), cfg, debug=False)
        kwargs = client.search_alerts.call_args.kwargs
        self.assertEqual(kwargs["source_fields"], ["timestamp", "rule.level", "rule.groups"])
        self.assertEqual(kwargs["query"], {"term": {"agent.name": "a"}})


if __name__ == "__main__":
    unittest.main()
