"""Temporal signature/anomaly fusion in radar_ar.py (FusionCorrelator) and the
suspicious_login off-hour anomaly wiring it relies on."""

import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml

from test_radar_ar import _drive_run, load_radar_ar_module

RADAR = Path(__file__).resolve().parents[2]
AR_YAML = RADAR / "scenarios" / "active_responses" / "ar.yaml"
WEBHOOK_LOG = "/var/log/ad_alerts.log"


@pytest.fixture
def radar_ar():
    return load_radar_ar_module()


@pytest.fixture
def shipped():
    return yaml.safe_load(AR_YAML.read_text())["scenarios"]


def _cfg(**over):
    cfg = {
        "ad": {"rule_ids": ["210040"]},
        "signature": {"rule_ids": ["210013", "210020"]},
        "w_ad": 0.3, "w_sig": 0.4, "w_cti": 0.3,
        "signature_impact": 0.7,
        "signature_likelihood": [{"rule_id": ["210013"], "weight": 0.6}, {"rule_id": ["210020"], "weight": 0.4}],
        "tiers": {"tier1_min": 0.15, "tier1_max": 0.33, "tier2_max": 0.55},
        "fusion": {"enabled": True, "window_minutes": 30, "ad_lead_minutes": 10,
                   "key": {"ad": "data.entity_keyword", "signature": ["data.dstuser", "data.srcuser"]}},
    }
    cfg.update(over)
    return cfg


def _sig_alert(user="alice", ts="2026-11-20T10:00:00.000+0000", rule="210013", aid="s1", agent="edge"):
    return {"id": aid, "timestamp": ts, "rule": {"id": rule, "groups": []},
            "agent": {"id": "002", "name": agent}, "data": {"dstuser": user, "srcip": "203.0.113.7"}}


def _ad_alert(user="alice", ts="2026-11-20T10:08:00.000+0000", start="2026-11-20T09:55:00.000Z",
              end="2026-11-20T10:00:00.000Z", grade="0.8", conf="0.9", aid="a1", agent="ad-webhook", location=WEBHOOK_LOG):
    data = {"entity_keyword": user, "anomaly_grade": grade, "anomaly_confidence": conf,
            "period_start": "2026-11-20T10:03:00Z", "period_end": "2026-11-20T10:08:00Z"}
    if start:
        data.update(data_start=start, data_end=end)
    return {"id": aid, "timestamp": ts, "rule": {"id": "210040", "groups": []},
            "agent": {"id": "010", "name": agent}, "location": location, "data": data}


def _correlator(radar_ar, hits=None):
    os_client = Mock(search=Mock(return_value=list(hits or [])))
    logger = Mock()
    return radar_ar.FusionCorrelator(logger, os_client, radar_ar.RiskEngine(logger)), os_client


def _scenario(detection, alert, cfg=None):
    return {"name": "suspicious_login", "detection": detection, "alert": alert, "config": cfg or _cfg()}


class TestSettings:
    def test_valid_settings(self, radar_ar):
        st = radar_ar.FusionCorrelator.settings(_cfg())
        assert st["window"] == 30 and st["lead"] == 10
        assert st["ad_keys"] == ["data.entity_keyword"] and st["sig_keys"] == ["data.dstuser", "data.srcuser"]

    @pytest.mark.parametrize("over", [
        {"fusion": None}, {"fusion": {"enabled": False}}, {"fusion": {"window_minutes": 30}},
        {"fusion": {"enabled": True, "window_minutes": 0}},
        {"w_ad": 0.0}, {"w_sig": 0.0}, {"ad": {"rule_ids": []}}, {"signature": {"rule_ids": []}},
    ])
    def test_fusion_off_unless_fully_configured(self, radar_ar, over):
        assert radar_ar.FusionCorrelator.settings(_cfg(**over)) is None

    def test_only_suspicious_login_ships_with_fusion(self, radar_ar, shipped):
        on = {n for n, c in shipped.items() if radar_ar.FusionCorrelator.settings(c)}
        assert on == {"suspicious_login"}

    @pytest.mark.parametrize("name", ["default", "geoip_detection", "log_volume", "linux_resource_utilization", "scanning_detection"])
    def test_other_shipped_scenarios_never_query(self, radar_ar, shipped, name):
        corr, os_client = _correlator(radar_ar, [_ad_alert()])
        for detection, alert in (("signature", _sig_alert()), ("ad", _ad_alert())):
            assert corr.correlate({"name": name, "detection": detection, "alert": alert, "config": shipped[name]}) is None
        os_client.search.assert_not_called()


class TestComputeWithFusion:
    def test_no_fusion_is_the_single_alert_score(self, radar_ar):
        engine = radar_ar.RiskEngine(Mock())
        s = _scenario("signature", _sig_alert())
        assert engine.compute(s, 0.5, None, None) == engine.compute(s, 0.5, None, None, fusion=None)
        assert "fusion" not in engine.compute(s, 0.5, None, None)["components"]

    def test_anomaly_counterpart_fills_A_on_a_signature_alert(self, radar_ar):
        engine = radar_ar.RiskEngine(Mock())
        out = engine.compute(_scenario("signature", _sig_alert()), 0.0, None, None, fusion={"counterpart": "ad", "value": 0.72})
        # 0.3*0.72 + 0.4*(0.6*0.7) = 0.216 + 0.168
        assert out["risk_score"] == pytest.approx(0.384)
        assert out["components"]["anomaly_intensity_A"] == pytest.approx(0.72)
        assert out["components"]["fusion"]["counterpart"] == "ad"

    def test_signature_counterpart_fills_S_on_an_anomaly_alert(self, radar_ar):
        engine = radar_ar.RiskEngine(Mock())
        out = engine.compute(_scenario("ad", _ad_alert()), 0.0, 0.8, 0.9, fusion={"counterpart": "signature", "value": 0.42})
        assert out["risk_score"] == pytest.approx(0.3 * 0.72 + 0.4 * 0.42)

    def test_fusion_never_lowers_a_term(self, radar_ar):
        engine = radar_ar.RiskEngine(Mock())
        s = _scenario("ad", _ad_alert())
        base = engine.compute(s, 0.0, 0.8, 0.9)
        assert engine.compute(s, 0.0, 0.8, 0.9, fusion={"counterpart": "ad", "value": 0.1})["risk_score"] == base["risk_score"]

    def test_t3_needs_fused_evidence_on_shipped_suspicious_login(self, radar_ar, shipped):
        engine = radar_ar.RiskEngine(Mock())
        cfg = shipped["suspicious_login"]
        best_sig = _scenario("signature", _sig_alert(rule="210013"), cfg)
        assert engine.compute(best_sig, 1.0, None, None)["tier"] == 2
        assert engine.compute(best_sig, 1.0, None, None, fusion={"counterpart": "ad", "value": 0.8})["tier"] == 3


class TestSignatureTriggered:
    def test_matches_trusted_anomaly_on_same_user(self, radar_ar):
        corr, os_client = _correlator(radar_ar, [_ad_alert()])
        best = corr.correlate(_scenario("signature", _sig_alert()))
        assert best["counterpart"] == "ad" and best["alert_id"] == "a1"
        assert best["weight"] == 1.0 and best["value"] == pytest.approx(0.72)
        body = os_client.search.call_args.args[1]
        flat = str(body)
        assert "210040" in flat and "alice" in flat and "data.entity_keyword" in flat
        assert os_client.search.call_args.args[0] == "wazuh-alerts-*"

    def test_anomaly_not_from_the_webhook_is_ignored(self, radar_ar):
        hits = [_ad_alert(agent="edge"), _ad_alert(location="/var/log/auth.log")]
        corr, _ = _correlator(radar_ar, hits)
        assert corr.correlate(_scenario("signature", _sig_alert())) is None

    def test_anomaly_for_another_user_is_ignored(self, radar_ar):
        corr, _ = _correlator(radar_ar, [_ad_alert(user="bob")])
        assert corr.correlate(_scenario("signature", _sig_alert(user="alice"))) is None

    def test_gap_discounts_linearly(self, radar_ar):
        # Signature 15 min after the data window ends: weight 1 - 15/30.
        corr, _ = _correlator(radar_ar, [_ad_alert()])
        best = corr.correlate(_scenario("signature", _sig_alert(ts="2026-11-20T10:15:00.000+0000")))
        assert best["gap_minutes"] == pytest.approx(15) and best["weight"] == pytest.approx(0.5)

    def test_lead_covers_onset_before_the_data_window(self, radar_ar):
        # 09:47 is 8 min before data_start 09:55, inside ad_lead_minutes=10.
        corr, _ = _correlator(radar_ar, [_ad_alert()])
        assert corr.correlate(_scenario("signature", _sig_alert(ts="2026-11-20T09:47:00.000+0000")))["weight"] == 1.0

    def test_outside_window_is_no_evidence(self, radar_ar):
        corr, _ = _correlator(radar_ar, [_ad_alert()])
        assert corr.correlate(_scenario("signature", _sig_alert(ts="2026-11-20T10:31:00.000+0000"))) is None

    def test_strongest_counterpart_wins_not_the_sum(self, radar_ar):
        hits = [_ad_alert(aid="weak", grade="0.3"), _ad_alert(aid="strong", grade="0.9"), _ad_alert(aid="mid", grade="0.5")]
        corr, _ = _correlator(radar_ar, hits)
        best = corr.correlate(_scenario("signature", _sig_alert()))
        assert best["alert_id"] == "strong" and best["value"] == pytest.approx(0.81) and best["candidates"] == 3

    def test_falls_back_to_monitor_period_without_data_window(self, radar_ar):
        corr, _ = _correlator(radar_ar, [_ad_alert(start=None)])
        best = corr.correlate(_scenario("signature", _sig_alert(ts="2026-11-20T10:05:00.000+0000")))
        assert best["gap_minutes"] == 0.0

    def test_alert_without_user_skips_fusion(self, radar_ar):
        corr, os_client = _correlator(radar_ar, [_ad_alert()])
        alert = _sig_alert()
        alert["data"] = {"office365": {"UserId": "alice@example.com"}}
        assert corr.correlate(_scenario("signature", alert)) is None
        os_client.search.assert_not_called()

    def test_search_failure_means_no_fusion(self, radar_ar):
        corr, os_client = _correlator(radar_ar)
        os_client.search.return_value = []
        assert corr.correlate(_scenario("signature", _sig_alert())) is None


class TestAnomalyTriggered:
    def test_matches_signature_on_same_user_with_its_likelihood(self, radar_ar):
        hits = [_sig_alert(rule="210020", aid="s-travel", ts="2026-11-20T09:58:00.000+0000"),
                _sig_alert(rule="210013", aid="s-burst", ts="2026-11-20T10:02:00.000+0000")]
        corr, os_client = _correlator(radar_ar, hits)
        best = corr.correlate(_scenario("ad", _ad_alert()))
        # burst: L=0.6 x I=0.7 = 0.42, 2 min after data_end -> weight 1 - 2/30
        assert best["counterpart"] == "signature" and best["alert_id"] == "s-burst"
        assert best["value"] == pytest.approx(0.42 * (1 - 2 / 30), abs=1e-6)
        rng = os_client.search.call_args.args[1]["query"]["bool"]["filter"][0]["range"]["@timestamp"]
        assert rng["gte"].startswith("2026-11-20T09:15") and rng["lte"].startswith("2026-11-20T10:08")

    def test_signature_for_another_user_is_ignored(self, radar_ar):
        corr, _ = _correlator(radar_ar, [_sig_alert(user="bob")])
        assert corr.correlate(_scenario("ad", _ad_alert(user="alice"))) is None

    def test_trigger_itself_is_never_its_own_counterpart(self, radar_ar):
        alert = _ad_alert()
        corr, _ = _correlator(radar_ar, [dict(_sig_alert(), id=alert["id"])])
        assert corr.correlate(_scenario("ad", alert)) is None

    def test_hybrid_alerts_are_not_fused(self, radar_ar):
        corr, os_client = _correlator(radar_ar, [_sig_alert()])
        assert corr.correlate(_scenario("hybrid", _ad_alert())) is None
        os_client.search.assert_not_called()


class TestRunWithFusion:
    def test_fusion_failure_still_decides(self, radar_ar, monkeypatch):
        captured = {}

        def compute(scenario, t, g, c, fusion=None):
            captured["fusion"] = fusion
            return {"risk_score": 0.2, "tier": 1, "components": {}}
        fusion = Mock(correlate=Mock(side_effect=RuntimeError("boom")))
        ar = _drive_run(radar_ar, monkeypatch, dict(_scenario("signature", _sig_alert()), matched_by="rule_id"),
                        fusion=fusion, compute=compute)
        assert captured["fusion"] is None
        ar.planner.plan.assert_called_once()

    def test_matched_counterpart_is_reported_in_extras(self, radar_ar, monkeypatch):
        matched = {"counterpart": "ad", "value": 0.7, "alert_id": "a1"}
        ar = _drive_run(radar_ar, monkeypatch, dict(_scenario("signature", _sig_alert()), matched_by="rule_id"),
                        fusion=Mock(correlate=Mock(return_value=matched)),
                        compute=lambda s, t, g, c, fusion=None: {"risk_score": 0.7, "tier": 3, "components": {"fusion": fusion}})
        decision = ar.planner.plan.call_args.args[0]
        assert decision["extras"]["fusion"] == matched


class TestSuspiciousLoginAnomaly:
    def test_rule_210040_identifies_suspicious_login_anomaly(self, radar_ar, shipped):
        ident = radar_ar.ScenarioIdentifier(Mock(), {"scenarios": shipped})
        out = ident.identify(_ad_alert())
        assert out["name"] == "suspicious_login" and out["detection"] == "ad"

    def test_rule_210041_off_hours_rule_mode_is_an_ad_alert_of_suspicious_login(self, radar_ar, shipped):
        ident = radar_ar.ScenarioIdentifier(Mock(), {"scenarios": shipped})
        alert = _ad_alert()
        alert["rule"] = dict(alert["rule"], id="210041")
        out = ident.identify(alert)
        assert out["name"] == "suspicious_login" and out["detection"] == "ad"

    def test_ar_binding_covers_every_suspicious_login_rule(self, shipped):
        snippet = (RADAR / "scenarios" / "ossec" / "radar-suspicious-login-ossec-snippet.xml").read_text()
        bound = set(ET.fromstring("<r>" + snippet + "</r>").findtext(".//rules_id").split(","))
        cfg = shipped["suspicious_login"]
        assert bound == set(cfg["signature"]["rule_ids"]) | set(cfg["ad"]["rule_ids"])

    def test_context_is_the_users_events_not_the_webhook_agents(self, radar_ar):
        strategy = radar_ar.SuspiciousLogin(Mock(), Mock())
        strategy._ad_user = "alice"
        filters = strategy.build_filters(*radar_ar.BaseScenario(Mock(), Mock()).resolve_time_window(_scenario("ad", _ad_alert())), None)
        user_filter = filters[-1]["bool"]["should"]
        assert {"term": {"data.dstuser": "alice"}} in user_filter
        assert not any("agent.name" in str(f) for f in filters)

    def test_effective_agent_is_where_the_user_logged_in(self, radar_ar):
        strategy = radar_ar.SuspiciousLogin(Mock(), Mock())
        events = [{"agent": {"name": "edge"}}, {"agent": {"name": "edge"}}, {"agent": {"name": "ad-webhook"}}, {"agent": {"name": "db"}}]
        assert strategy.resolve_effective_agent_name(_scenario("ad", _ad_alert()), events) == "edge"
        assert strategy.resolve_effective_agent_name(_scenario("ad", _ad_alert()), []) is None

    def test_signature_alert_context_is_unchanged(self, radar_ar):
        strategy = radar_ar.SuspiciousLogin(Mock(), Mock())
        base = radar_ar.BaseScenario(Mock(), Mock())
        s = _scenario("signature", _sig_alert())
        t0, t1 = base.resolve_time_window(s)
        assert strategy.build_filters(t0, t1, "edge") == base.build_filters(t0, t1, "edge")
        assert strategy.resolve_effective_agent_name(s, []) == "edge"

    def test_decipher_username_is_the_anomalous_user(self, radar_ar):
        strategy = radar_ar.SuspiciousLogin(Mock(), Mock())
        payload = strategy.build_analyze_payload(_scenario("ad", _ad_alert()), {"iocs": {"user": ["admin"]}, "effective_agent": "edge"})
        assert payload["username"] == "alice" and payload["target_host"] == "edge"

    def test_anomaly_alert_has_no_mitigation_target(self, radar_ar):
        executor = radar_ar.ActionExecutor(Mock(), Mock())
        s = _scenario("ad", _ad_alert())
        assert executor._build_args("lock_user_linux.sh", s, {"user": ["alice"]}) == []
        assert executor._build_args("firewall-drop", s, {"ip": ["203.0.113.7"]}, "") == []


class TestRecalibration:
    def test_geoip_strong_rules_reach_t2(self, radar_ar, shipped):
        engine = radar_ar.RiskEngine(Mock())
        cfg = shipped["geoip_detection"]
        assert cfg["w_cti"] == 0.0
        strong = {"name": "geoip_detection", "detection": "signature", "config": cfg, "alert": {"rule": {"id": "100900"}}}
        weak = dict(strong, alert={"rule": {"id": "100902"}})
        assert engine.compute(strong, 0.0, None, None)["tier"] == 2
        assert engine.compute(weak, 0.0, None, None)["tier"] == 1

    def test_suspicious_login_single_signature_alerts_keep_their_tier(self, radar_ar, shipped):
        # tier2_max moved 0.66 -> 0.55; a signature alert alone never reaches 0.55.
        engine = radar_ar.RiskEngine(Mock())
        cfg = shipped["suspicious_login"]
        for rule in cfg["signature"]["rule_ids"]:
            for t in (0.0, 0.5, 1.0):
                s = {"name": "suspicious_login", "detection": "signature", "config": cfg, "alert": {"rule": {"id": rule}}}
                out = engine.compute(s, t, None, None)
                old = engine.compute(dict(s, config=dict(cfg, tiers=dict(cfg["tiers"], tier2_max=0.66))), t, None, None)
                assert out["tier"] == old["tier"] and out["risk_score"] < 0.55
