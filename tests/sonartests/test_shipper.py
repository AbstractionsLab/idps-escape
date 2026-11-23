"""
Unit tests for the SONAR shipper templates (sonar/shipper/).

The OpenSearch client is mocked; no cluster is contacted.
"""

import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from sonar.config import FeatureConfig, WazuhIndexerConfig
from sonar.backends.mvad import mvad_results_to_points
from sonar.pipeline import MVADPostProcessor
from sonar.shipper.wazuh_base_template import INDEX_PATTERNS, MVAD_COMPONENT, MVAD_COMPONENT_NAME, PRIORITY, SCENARIO_TEMPLATE_PRIORITY
from sonar.shipper.wazuh_data_shipper import WazuhDataShipper, get_template_name_and_pattern


def _make_shipper() -> WazuhDataShipper:
    with patch("sonar.shipper.wazuh_data_shipper.build_opensearch_client"):
        shipper = WazuhDataShipper(WazuhIndexerConfig(), install=False)
    shipper.client = MagicMock()
    return shipper


class TestScenarioTemplate(unittest.TestCase):
    """The per-scenario template must match the stream that detection ships to."""

    def test_pattern_matches_shipped_stream(self):
        shipper = _make_shipper()
        stream = shipper.create_scenario_stream("brute", "Brute")

        self.assertEqual(stream, "sonar_anomalies_mvad_brute")
        self.assertEqual(stream, get_template_name_and_pattern("brute")[1])
        name = shipper.client.indices.put_index_template.call_args.kwargs["name"]
        body = shipper.client.indices.put_index_template.call_args.kwargs["body"]
        self.assertEqual(name, "sonar_stream_template_mvad_brute")
        self.assertEqual(body[INDEX_PATTERNS], ["sonar_anomalies_mvad_brute"])
        self.assertEqual(body[PRIORITY], SCENARIO_TEMPLATE_PRIORITY)
        self.assertGreater(body[PRIORITY], 2)  # above the generic sonar_anomalies_* templates

    def test_no_per_scenario_feature_component(self):
        # Documents carry no feature columns, so a component mapping them would map nothing.
        shipper = _make_shipper()
        shipper.create_scenario_stream("brute", "Brute")
        shipper.client.cluster.put_component_template.assert_not_called()
        body = shipper.client.indices.put_index_template.call_args.kwargs["body"]
        self.assertEqual(body["composed_of"], [MVAD_COMPONENT_NAME])

    def test_sink_ships_to_template_pattern(self):
        from sonar.config import PipelineConfig
        from sonar.sinks.indexer import DataStreamSink

        cfg = PipelineConfig()
        shipper = _make_shipper()
        shipper.client.bulk.return_value = {"items": [{"create": {"status": 201}}]}
        sink = DataStreamSink(cfg.wazuh, cfg.shipping, "brute")
        sink._shipper = shipper
        self.assertTrue(sink.emit([{"anomaly_id": "x", "timestamp": "2026-01-01T00:00:00Z"}]).ok)
        self.assertIn('"_index": "sonar_anomalies_mvad_brute"', shipper.client.bulk.call_args.kwargs["body"])


class TestRetentionPolicy(unittest.TestCase):
    def test_policy_attaches_itself_to_sonar_backing_indices(self):
        from sonar.shipper.wazuh_data_shipper import ism_policy

        policy = ism_policy(rollover_days=3, retention_days=45)["policy"]
        self.assertEqual(policy["ism_template"][0]["index_patterns"], [".ds-sonar_anomalies_*"])
        hot = policy["states"][0]
        self.assertEqual(hot["actions"], [{"rollover": {"min_index_age": "3d"}}])
        self.assertEqual(hot["transitions"], [{"state_name": "delete", "conditions": {"min_index_age": "45d"}}])
        self.assertEqual(policy["states"][1]["actions"], [{"delete": {}}])

    def test_installed_with_the_templates_and_existing_policy_kept(self):
        from opensearchpy.exceptions import ConflictError

        shipper = _make_shipper()
        shipper.client.cluster.health.return_value = {"status": "green"}
        shipper.client.indices.exists_index_template.return_value = True
        shipper.client.transport.perform_request.side_effect = ConflictError(409, "exists", {})
        shipper.install()  # an existing policy is not an error
        method, path = shipper.client.transport.perform_request.call_args.args[:2]
        self.assertEqual((method, path), ("PUT", "/_plugins/_ism/policies/sonar_anomalies_policy"))


class TestMvadMappingMatchesDocument(unittest.TestCase):
    """Every field the MVAD component maps must exist in the documents pipeline.py builds."""

    def test_mapped_fields_exist_in_document(self):
        ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
        results = [{"index": ts, "is_anomaly": True, "score": 0.9, "severity": 0.5, "interpretation": [{"variable_name": "rule.level", "contribution_score": 1.0}]}]
        doc = MVADPostProcessor(FeatureConfig()).build_wazuh_anomaly_docs(mvad_results_to_points(results), {"lookback_minutes": 60})[0]

        def check(props: dict, node: dict, path: str):
            for key, spec in props.items():
                self.assertIn(key, node, f"mapped field {path}{key} missing from document")
                value = node[key]
                if "properties" in spec:
                    for item in value if isinstance(value, list) else [value]:
                        check(spec["properties"], item, f"{path}{key}.")

        check(MVAD_COMPONENT["template"]["mappings"]["properties"], doc, "")


if __name__ == "__main__":
    unittest.main()
