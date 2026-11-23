"""Off-hours flagging: config validation, the Python twin of the Painless script, and the rendered pipeline.

The case table in fixtures/off_hours_cases.yaml is shared with the live check
radar-test-framework/checks/off_hours_simulate.py, which runs it through the
real pipeline with _simulate.
"""

import copy
import json
import re
from pathlib import Path

import off_hours as oh
import pytest
import requests
import responses
import yaml

FIXT = Path(__file__).parent / "fixtures"
TABLE = yaml.safe_load((FIXT / "off_hours_cases.yaml").read_text())
RADAR_CONFIG = Path(__file__).resolve().parents[2] / "config.yaml"


@pytest.fixture
def cfg():
    return oh.parse_config(copy.deepcopy(TABLE["config"]))


def _raw(**overrides):
    raw = copy.deepcopy(TABLE["config"])
    raw.update(overrides)
    return raw


# --- case table -------------------------------------------------------------


@pytest.mark.parametrize("case", TABLE["cases"], ids=[c["note"] for c in TABLE["cases"]])
def test_case_table(cfg, case):
    expect = case["expect"]
    if expect == "error":
        with pytest.raises(oh.OffHoursEventError):
            cfg.classify(case["event"])
    elif expect == "absent":
        assert cfg.classify(case["event"]) is None
    else:
        assert cfg.classify(case["event"]) == {"off_hours": expect["off_hours"], "schedule_group": expect["group"], "user": expect["user"]}


def test_table_keeps_the_spec_cases():
    assert len(TABLE["cases"]) >= 18


def test_unlisted_user_is_ignored_without_default_group():
    cfg = oh.parse_config(_raw(default_group=None))
    assert cfg.classify({"@timestamp": "2026-09-18T02:05:00Z", "data": {"user": "mallory"}}) is None
    assert cfg.classify({"@timestamp": "2026-09-18T02:05:00Z", "data": {"user": "bob"}})["off_hours"] == 1


def test_groups_in_mode(cfg):
    assert cfg.groups_in_mode("model") == ["synthetic_admin"]
    assert "synthetic_admin" not in cfg.groups_in_mode("rule")
    assert len(cfg.groups_in_mode("rule")) == 5


def test_every_minute_of_a_week_matches_a_naive_reference(cfg):
    """Brute-force check of the shift arithmetic for a midnight-crossing group."""
    from datetime import datetime, timedelta, timezone

    late = cfg.groups["synthetic_late"]
    t = datetime(2026, 9, 14, tzinfo=timezone.utc)  # Monday
    for _ in range(7 * 24 * 4):
        minute = t.hour * 60 + t.minute
        dow = t.isoweekday()
        evening_shift = minute >= 16 * 60 and dow <= 5
        morning_tail = minute < 3 * 60 and (dow - 1 if dow > 1 else 7) <= 5
        assert late.is_off_hours(t) == (not (evening_shift or morning_tail)), t
        t += timedelta(minutes=15)


# --- validation ---------------------------------------------------------------


def _group(**kw):
    g = {"timezone": "UTC", "workdays": [1, 2, 3, 4, 5], "start": "08:00", "end": "19:00", "mode": "rule"}
    g.update(kw)
    return g


@pytest.mark.parametrize(
    "overrides, fragment",
    [
        ({"groups": {"g": _group(timezone="Mars/Olympus")}, "users": {}, "default_group": None}, "unknown IANA time zone"),
        ({"groups": {"g": _group(start="25:00")}, "users": {}, "default_group": None}, "not a time"),
        ({"groups": {"g": _group(end="24:30")}, "users": {}, "default_group": None}, "not a time"),
        ({"groups": {"g": _group(start="24:00")}, "users": {}, "default_group": None}, "not a time"),
        ({"groups": {"g": _group(start=960)}, "users": {}, "default_group": None}, "quoted"),
        ({"groups": {"g": _group(start="09:00", end="09:00")}, "users": {}, "default_group": None}, "must differ"),
        ({"groups": {"g": _group(workdays=[0, 1])}, "users": {}, "default_group": None}, "ISO weekdays"),
        ({"groups": {"g": _group(workdays=[8])}, "users": {}, "default_group": None}, "ISO weekdays"),
        ({"groups": {"g": _group(mode="tier")}, "users": {}, "default_group": None}, "must be one of rule, model"),
        ({"groups": {"g": _group(tier="rule")}, "users": {}, "default_group": None}, "unknown keys"),
        ({"users": {"bob": "nope"}}, "group 'nope' is not defined"),
        ({"default_group": "nope"}, "'nope' is not a defined group"),
        ({"groups": {}}, "at least one schedule group"),
        ({"users": {"Bob": "synthetic_day", "bob": "synthetic_late"}}, "duplicates 'bob'"),
        ({"ignore_users": ["bob"]}, "also listed in ignore_users"),
        ({"user_fields": []}, "user_fields"),
        ({"rule_mode": {"lookback_minutes": 10}}, "rule_mode: unknown keys ['lookback_minutes']"),
        ({"rule_mode": {"delay_minutes": -1}}, "delay_minutes"),
        ({"rule_mode": {"anomaly_grade": 0}}, "anomaly_grade"),
        ({"model_mode": {"shingle_size": 0}}, "shingle_size"),
        ({"model_mode": {"max_entities": 51}}, "at most 50"),
        ({"model_mode": {"confidence_threshold": 1.5}}, "confidence_threshold"),
        ({"model_mode": {"feature": "avg"}}, "model_mode: unknown keys ['feature']"),
        ({"event_filter": {"field": "decoder.name", "values": "sshd"}}, "event_filter"),
        ({"rule_tier": {}}, "unknown keys ['rule_tier']"),
        ({"backfill_days": 0}, "backfill_days: must be an integer >= 1"),
    ],
)
def test_validation_rejects(overrides, fragment):
    with pytest.raises(oh.OffHoursConfigError) as exc:
        oh.parse_config(_raw(**overrides))
    assert fragment in str(exc.value)
    assert oh.CONFIG_PATH in str(exc.value)


def test_validation_reports_every_problem_at_once():
    with pytest.raises(oh.OffHoursConfigError) as exc:
        oh.parse_config(_raw(default_group="nope", users={"bob": "nope"}))
    assert str(exc.value).count("\n  - ") == 2


def test_defaults():
    cfg = oh.parse_config({"groups": {"g": _group()}})
    assert cfg.enabled and cfg.default_group is None and cfg.users == {} and cfg.event_filter is None
    assert cfg.user_fields == oh.DEFAULT_USER_FIELDS
    assert cfg.backfill_days == oh.DEFAULT_BACKFILL_DAYS == 45
    assert (cfg.rule_mode.interval_minutes, cfg.rule_mode.delay_minutes, cfg.rule_mode.quiet_minutes, cfg.rule_mode.min_events) == (5, 1, 30, 1)
    mm = cfg.model_mode
    assert (mm.interval_minutes, mm.window_delay_minutes, mm.shingle_size) == (30, 10, 1)
    assert (mm.anomaly_grade_threshold, mm.confidence_threshold, mm.min_events, mm.max_entities) == (0.01, 0.01, 1, 10)


def test_empty_event_filter_values_mean_no_filter():
    assert oh.parse_config(_raw(event_filter={"field": "decoder.name", "values": []})).event_filter is None
    ef = oh.parse_config(_raw(event_filter={"field": "decoder.name", "values": ["sshd"]})).event_filter
    assert ef == oh.EventFilter(field="decoder.name", values=("sshd",))


def test_load_config_absent_or_disabled():
    assert oh.load_config({"scenarios": {"suspicious_login": {}}}) is None
    assert oh.load_config({"scenarios": {"suspicious_login": {"off_hours": _raw(enabled=False)}}}) is None


def test_shipped_config_block_is_valid():
    cfg = oh.load_config(yaml.safe_load(RADAR_CONFIG.read_text()))
    assert cfg is not None
    assert cfg.default_group is None  # unlisted users are not evaluated by default
    assert set(cfg.users) == {"alice", "bob", "oscar", "trent"}
    assert cfg.groups_in_mode("model") == ["synthetic_admin"]
    assert not any(name.startswith("test_") for name in cfg.groups)  # test groups live in the test table only


def test_shipped_config_has_no_replaced_detector():
    scenarios = yaml.safe_load(RADAR_CONFIG.read_text())["scenarios"]
    assert "off_hour_login" not in scenarios
    assert not {"features", "categorical_field", "monitor_name", "trigger_name"} & set(scenarios["suspicious_login"])


# --- rendered pipeline ---------------------------------------------------------


def test_pipeline_body_shape(cfg):
    body = oh.pipeline_body(cfg)
    json.dumps(body)  # serialisable as sent to the API
    (proc,) = body["processors"]
    script = proc["script"]
    assert script["lang"] == "painless" and script["source"] == oh.PAINLESS_SOURCE
    assert script["on_failure"] == [{"set": {"field": "radar.off_hours_error", "value": "{{ _ingest.on_failure_message }}"}}]
    params = script["params"]
    assert params["user_fields"] == [["data", "user"], ["data", "srcuser"], ["data", "dstuser"]]
    assert params["groups"]["synthetic_late"] == {"tz": "UTC", "start": 960, "end": 180, "workdays": [1, 2, 3, 4, 5]}
    assert params["groups"]["test_always_off"] == {"tz": "UTC", "start": 0, "end": 1440, "workdays": []}
    assert params["users"]["bob"] == "synthetic_day"
    assert params["ignore_users"] == ["root"]
    assert params["default_group"] == "synthetic_day"


def test_pipeline_is_deterministic(cfg):
    assert json.dumps(oh.pipeline_body(cfg)) == json.dumps(oh.pipeline_body(oh.parse_config(copy.deepcopy(TABLE["config"]))))


def test_painless_avoids_regex_and_writes_only_radar_fields():
    src = oh.PAINLESS_SOURCE
    assert "=~" not in src and "/" not in src.replace("//", "")
    written = set(re.findall(r"(ctx(?:\.\w+|\['[^']+'\])+)\s*=(?!=)", src))
    assert written == {"ctx.radar", "ctx.radar.user", "ctx.radar.schedule_group", "ctx.radar.off_hours"}


def test_cli_validate_and_pipeline(tmp_path, capsys):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"scenarios": {"suspicious_login": {"off_hours": TABLE["config"]}}}))
    assert oh.main(["validate", "--config", str(path)]) == 0
    assert oh.main(["pipeline", "--config", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["processors"][0]["script"]["tag"] == "radar_off_hours"
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump({"scenarios": {"suspicious_login": {"off_hours": {"groups": {}}}}}))
    assert oh.main(["validate", "--config", str(bad)]) == 1


# --- OpenSearch: deploy, backfill, undeploy -----------------------------------------

BASE = "https://os.test:9200"


@pytest.fixture
def cluster():
    return oh.Cluster(session=requests.Session(), base=BASE, verify=False, timeout=5)


def test_template_is_legacy_and_sets_no_pipeline():
    body = oh.template_body()
    assert body["index_patterns"] == ["wazuh-archives-*"] and body["order"] > 0
    assert "settings" not in body  # no final_pipeline: it skips Filebeat events and a missing pipeline would block direct writes
    radar = body["mappings"]["properties"]["radar"]["properties"]
    assert radar == {
        "user": {"type": "keyword"},
        "off_hours": {"type": "byte"},
        "schedule_group": {"type": "keyword"},
        "off_hours_error": {"type": "keyword", "ignore_above": 1024},
    }


@responses.activate
def test_deploy_puts_pipeline_template_and_mapping(cluster, cfg):
    responses.put(f"{BASE}/_ingest/pipeline/radar-off-hours", json={"acknowledged": True})
    responses.put(f"{BASE}/_template/radar-off-hours", json={"acknowledged": True})
    responses.put(f"{BASE}/wazuh-archives-*/_mapping", json={"acknowledged": True})
    oh.deploy(cluster, cfg)
    sent = {c.request.url.replace(BASE, ""): json.loads(c.request.body) for c in responses.calls}
    assert sent["/_ingest/pipeline/radar-off-hours"] == oh.pipeline_body(cfg)
    assert sent["/_template/radar-off-hours"] == oh.template_body()
    assert sent["/wazuh-archives-*/_mapping"] == oh.radar_mapping()


@responses.activate
def test_deploy_without_archive_indices(cluster, cfg):
    responses.put(f"{BASE}/_ingest/pipeline/radar-off-hours", json={"acknowledged": True})
    responses.put(f"{BASE}/_template/radar-off-hours", json={"acknowledged": True})
    responses.put(f"{BASE}/wazuh-archives-*/_mapping", status=404, json={"error": "index_not_found_exception"})
    oh.deploy(cluster, cfg)


@responses.activate
def test_deploy_stops_on_a_rejected_pipeline(cluster, cfg):
    responses.put(f"{BASE}/_ingest/pipeline/radar-off-hours", status=400, json={"error": "script_exception"})
    with pytest.raises(oh.OpenSearchError, match="HTTP 400"):
        oh.deploy(cluster, cfg)
    assert len(responses.calls) == 1


@responses.activate
def test_backfill_polls_the_task(cluster, cfg):
    responses.post(f"{BASE}/wazuh-archives-*/_update_by_query", json={"task": "n1:42"})
    responses.get(f"{BASE}/_tasks/n1:42", json={"completed": False})
    responses.get(f"{BASE}/_tasks/n1:42", json={"completed": True, "response": {"total": 7, "updated": 7, "failures": []}})
    sleeps = []
    result = oh.backfill(cluster, cfg, 45, poll_seconds=2, sleep=sleeps.append)
    assert result["updated"] == 7 and sleeps == [2]
    call = responses.calls[0].request
    assert "pipeline=radar-off-hours" in call.url and "wait_for_completion=false" in call.url and "conflicts=proceed" in call.url
    assert json.loads(call.body) == {"query": oh.backfill_query(cfg, 45)}


@responses.activate
def test_backfill_reports_failures_and_timeouts(cluster, cfg):
    responses.post(f"{BASE}/wazuh-archives-*/_update_by_query", json={"task": "n1:1"})
    responses.get(f"{BASE}/_tasks/n1:1", json={"completed": True, "response": {"failures": [{"cause": "x"}]}})
    with pytest.raises(oh.OpenSearchError, match="failed"):
        oh.backfill(cluster, cfg, 45, sleep=lambda s: None)
    responses.reset()
    responses.post(f"{BASE}/wazuh-archives-*/_update_by_query", json={"task": "n1:2"})
    responses.get(f"{BASE}/_tasks/n1:2", json={"completed": False})
    with pytest.raises(oh.OpenSearchError, match="still running"):
        oh.backfill(cluster, cfg, 45, poll_seconds=10, max_wait_seconds=20, sleep=lambda s: None)


@responses.activate
def test_backfill_without_archive_indices(cluster, cfg):
    responses.post(f"{BASE}/wazuh-archives-*/_update_by_query", status=404, json={"error": "index_not_found_exception"})
    assert oh.backfill(cluster, cfg, 45) == {"total": 0, "updated": 0}


def test_backfill_query_targets_listed_users_without_a_default_group():
    cfg = oh.parse_config(_raw(default_group=None))
    q = oh.backfill_query(cfg, 30)["bool"]
    assert q["filter"] == [{"range": {"@timestamp": {"gte": "now-30d"}}}]
    assert {"term": {"data.dstuser": {"value": "bob", "case_insensitive": True}}} in q["should"]
    assert len(q["should"]) == len(cfg.users) * len(cfg.user_fields)
    assert q["must_not"] == [{"exists": {"field": "radar.off_hours"}}, {"exists": {"field": "radar.off_hours_error"}}]


def test_backfill_query_with_a_default_group_takes_any_user(cfg):
    assert oh.backfill_query(cfg, 45)["bool"]["should"] == [{"exists": {"field": f}} for f in cfg.user_fields]


@responses.activate
def test_undeploy_tolerates_missing_objects(cluster):
    responses.delete(f"{BASE}/_template/radar-off-hours", status=404, json={})
    responses.delete(f"{BASE}/_ingest/pipeline/radar-off-hours", json={"acknowledged": True})
    oh.undeploy(cluster)
    assert len(responses.calls) == 2


@responses.activate
def test_cli_deploy_and_api_errors(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for k in ("OS_URL", "OS_USER", "OS_PASS", "OS_VERIFY_SSL"):
        monkeypatch.delenv(k, raising=False)
    (tmp_path / ".env").write_text(f"OS_URL={BASE}\nOS_USER=u\nOS_PASS=p\nOS_VERIFY_SSL=false\n")
    (tmp_path / "config.yaml").write_text(yaml.safe_dump({"scenarios": {"suspicious_login": {"off_hours": TABLE["config"]}}}))
    responses.put(f"{BASE}/_ingest/pipeline/radar-off-hours", json={})
    responses.put(f"{BASE}/_template/radar-off-hours", json={})
    responses.put(f"{BASE}/wazuh-archives-*/_mapping", status=500, body="boom")
    assert oh.main(["deploy"]) == 2
    (tmp_path / "config.yaml").write_text(yaml.safe_dump({"scenarios": {"suspicious_login": {}}}))
    assert oh.main(["deploy"]) == 0  # absent block: nothing to do, no API call
    assert len(responses.calls) == 3


@responses.activate
def test_summary_reports_flags_per_user(cluster):
    responses.post(
        f"{BASE}/wazuh-archives-*/_search",
        json={
            "aggregations": {
                "users": {
                    "buckets": [
                        {"key": "bob", "doc_count": 12, "group": {"buckets": [{"key": "synthetic_day"}]}, "off_hours": {"value": 2.0}, "last_off": {"at": {"value_as_string": "2026-09-18T02:05:00.000Z"}}},
                        {"key": "alice", "doc_count": 5, "group": {"buckets": [{"key": "synthetic_early"}]}, "off_hours": {"value": 0.0}, "last_off": {"at": {"value": None}}},
                    ]
                }
            }
        },
    )
    responses.post(f"{BASE}/wazuh-archives-*/_count", json={"count": 1})
    report = oh.summary(cluster, 7)
    assert report["errors"] == 1 and report["days"] == 7
    assert report["users"][0] == {"user": "bob", "group": "synthetic_day", "events": 12, "off_hours": 2, "last_off_hours": "2026-09-18T02:05:00.000Z"}
    assert report["users"][1]["last_off_hours"] is None
    assert json.loads(responses.calls[0].request.body)["query"]["bool"]["filter"][0] == {"range": {"@timestamp": {"gte": "now-7d"}}}


@responses.activate
def test_summary_without_archive_indices(cluster):
    responses.post(f"{BASE}/wazuh-archives-*/_search", status=404, json={})
    responses.post(f"{BASE}/wazuh-archives-*/_count", status=404, json={})
    assert oh.summary(cluster, 1) == {"days": 1, "users": [], "errors": 0}


# --- rule mode: bucket monitor -------------------------------------------------------


def _render(template, ctx):
    """Just enough mustache for our templates: {{a.b.0.c}} lookups and {{#list}}...{{/list}} sections."""

    def lookup(scope, path):
        for part in path.split("."):
            if isinstance(scope, list):
                scope = scope[int(part)] if part.isdigit() and int(part) < len(scope) else ""
            else:
                scope = (scope or {}).get(part, "")
        return scope

    def render(text, scopes):
        def section(m):
            items = lookup(scopes[-1], m.group(1))
            if not items:
                items = next((lookup(s, m.group(1)) for s in reversed(scopes) if lookup(s, m.group(1))), [])
            return "".join(render(m.group(2), scopes + [item]) for item in items)

        text = re.sub(r"\{\{#([\w.]+)\}\}(.*?)\{\{/\1\}\}", section, text, flags=re.S)

        def var(m):
            for s in reversed(scopes):
                v = lookup(s, m.group(1))
                if v != "":
                    return str(v)
            return ""

        return re.sub(r"\{\{([\w.]+)\}\}", var, text)

    return render(template, [ctx])


def _user_bucket(user, count, first, last, group):
    """A `users` terms bucket of the rule-mode query, after the bucket_selector kept it."""
    return {
        "key": user,
        "doc_count": count,
        "now": {"doc_count": count, "first": {"value": 0.0, "value_as_string": first}, "last": {"value": 0.0, "value_as_string": last}},
        "before": {"doc_count": 0},
        "group": {"doc_count_error_upper_bound": 0, "sum_other_doc_count": 0, "buckets": [{"key": group, "doc_count": count}]},
    }


def _ctx(*buckets):
    """Action context of a query-level monitor: ctx.results is the search response."""
    return {
        "ctx": {
            "monitor": {"name": oh.RULE_MONITOR_NAME},
            "trigger": {"name": oh.RULE_TRIGGER_NAME},
            "periodStart": "2026-11-21T10:58:50.161Z",
            "periodEnd": "2026-11-21T11:03:50.161Z",
            "results": [{"aggregations": {"users": {"doc_count_error_upper_bound": 0, "sum_other_doc_count": 0, "buckets": list(buckets)}}}],
        }
    }


def _webhook():
    pytest.importorskip("flask")
    import importlib.util

    src = Path(__file__).resolve().parents[2] / "webhook/ad_alerts_webhook.py"
    spec = importlib.util.spec_from_file_location("ad_alerts_webhook_for_off_hours", src)
    wh = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wh)
    return wh


ARASH = _user_bucket("arash", 4, "2026-11-21T11:02:59.325Z", "2026-11-21T11:03:00.884Z", "synthetic_day")


def _filters(query):
    return query["query"]["bool"]["filter"]


def test_rule_monitor_payload(cfg):
    payload = oh.rule_monitor_payload(cfg, "dest-1")
    assert payload["monitor_type"] == "query_level_monitor" and payload["name"] == oh.RULE_MONITOR_NAME
    assert payload["schedule"] == {"period": {"interval": 5, "unit": "MINUTES"}}
    search = payload["inputs"][0]["search"]
    assert search["indices"] == ["wazuh-archives-*"]
    filters = _filters(search["query"])
    assert {"term": {"radar.off_hours": 1}} in filters
    assert {"terms": {"radar.schedule_group": cfg.groups_in_mode("rule")}} in filters
    assert "synthetic_admin" not in json.dumps(filters)  # model-mode users never reach rule mode
    (trigger,) = payload["triggers"]
    assert trigger["name"] == oh.RULE_TRIGGER_NAME and trigger["condition"]["script"]["source"] == oh.RULE_CONDITION
    (action,) = trigger["actions"]
    assert action["destination_id"] == "dest-1" and action["throttle_enabled"] is False


def test_rule_query_windows_abut_and_select_new_bursts(cfg):
    """interval 5, delay 1, quiet 30: current window (t-6m, t-1m], quiet period (t-36m, t-6m]."""
    q = oh.rule_monitor_query(cfg)
    assert _filters(q)[0] == {"range": {"@timestamp": {"gt": "{{period_end}}||-36m", "lte": "{{period_end}}||-1m", "format": "epoch_millis"}}}
    aggs = q["aggregations"]["users"]["aggs"]
    assert q["aggregations"]["users"]["terms"]["field"] == "radar.user"
    assert aggs["now"]["filter"] == {"range": {"@timestamp": {"gt": "{{period_end}}||-6m", "lte": "{{period_end}}||-1m", "format": "epoch_millis"}}}
    assert aggs["before"]["filter"] == {"range": {"@timestamp": {"lte": "{{period_end}}||-6m", "format": "epoch_millis"}}}
    sel = aggs["new_burst"]["bucket_selector"]
    assert sel["buckets_path"] == {"now": "now._count", "before": "before._count"}
    assert sel["script"] == "params.now >= 1 && params.before == 0"


def test_rule_query_without_delay_or_quiet_period():
    cfg = oh.parse_config(_raw(rule_mode={"delay_minutes": 0, "quiet_minutes": 0, "min_events": 3}))
    q = oh.rule_monitor_query(cfg)
    assert _filters(q)[0]["range"]["@timestamp"] == {"gt": "{{period_end}}||-5m", "lte": "{{period_end}}", "format": "epoch_millis"}
    assert q["aggregations"]["users"]["aggs"]["new_burst"]["bucket_selector"]["script"] == "params.now >= 3 && params.before == 0"


def test_rule_query_honours_event_filter():
    cfg = oh.parse_config(_raw(event_filter={"field": "decoder.name", "values": ["sshd", "sudo"]}))
    assert {"terms": {"decoder.name": ["sshd", "sudo"]}} in _filters(oh.rule_monitor_query(cfg))


def _burst_selected(cfg, events_min_ago):
    """Evaluate the query's window logic in Python for events at the given minutes before period_end."""
    rm = cfg.rule_mode
    now = [m for m in events_min_ago if rm.delay_minutes <= m < rm.interval_minutes + rm.delay_minutes]
    before = [m for m in events_min_ago if rm.interval_minutes + rm.delay_minutes <= m < rm.interval_minutes + rm.delay_minutes + rm.quiet_minutes]
    return len(now) >= rm.min_events and not before


def test_a_long_session_notifies_once(cfg):
    """Events every minute for an hour: only the first window with events selects the user."""
    events_at = list(range(0, 60))  # minutes after the session starts
    notified = []
    for run_end in range(0, 90, cfg.rule_mode.interval_minutes):
        ago = [run_end - t for t in events_at if run_end - t >= 0]
        if _burst_selected(cfg, ago):
            notified.append(run_end)
    assert len(notified) == 1


def test_activity_after_a_quiet_period_notifies_again(cfg):
    events_at = [0, 1, 2, 100]  # a short burst, then one event 98 minutes later
    notified = [run_end for run_end in range(0, 130, 5) if _burst_selected(cfg, [run_end - t for t in events_at if run_end - t >= 0])]
    assert len(notified) == 2


def test_rule_trigger_name_matches_rule_210041_only():
    rules = (Path(__file__).resolve().parents[2] / "scenarios/rules/suspicious_login/a3-suspicious-login.xml").read_text()
    assert f"<match>{oh.RULE_TRIGGER_NAME}</match>" in rules
    assert "SuspiciousLogin-OffHour-Detected" not in oh.RULE_TRIGGER_NAME  # rule 210040 (model mode) must not match it


def test_rule_message_renders_to_a_body_the_webhook_accepts(cfg):
    from datetime import datetime

    template = oh.rule_monitor_payload(cfg, "d")["triggers"][0]["actions"][0]["message_template"]["source"]
    body = json.loads(_render(template, _ctx(ARASH)))
    assert body["anomalies"] == [
        {
            "entity": "arash",
            "anomaly_grade": "1.0",
            "anomaly_confidence": "1.0",
            "dataStart": "2026-11-21T11:02:59.325Z",
            "dataEnd": "2026-11-21T11:03:00.884Z",
            "off_hours_count": "4",
            "schedule_group": "synthetic_day",
        },
        None,
    ]
    (line,) = _webhook().build_lines(body, "ad-webhook", datetime(2026, 11, 21, 11, 4))
    assert f'OpenSearchAD {oh.RULE_TRIGGER_NAME}: entity="arash"' in line
    assert 'data_start="2026-11-21T11:02:59.325Z", data_end="2026-11-21T11:03:00.884Z"' in line
    assert 'off_hours_count="4", schedule_group="synthetic_day"' in line


def test_two_new_bursts_in_one_run_give_two_lines(cfg):
    from datetime import datetime

    bob = _user_bucket("bob", 2, "2026-11-21T11:00:00.000Z", "2026-11-21T11:01:00.000Z", "synthetic_day")
    body = json.loads(_render(oh.rule_message_template(cfg), _ctx(ARASH, bob)))
    lines = _webhook().build_lines(body, "ad-webhook", datetime(2026, 11, 21, 11, 4))
    assert sorted(l.split('entity="')[1].split('"')[0] for l in lines) == ["arash", "bob"]


def _monitor_search(hits):
    responses.post(f"{BASE}/_plugins/_alerting/monitors/_search", json={"hits": {"hits": hits}})


@responses.activate
def test_ensure_rule_monitor_creates_then_leaves_it(cluster, cfg):
    _monitor_search([])
    responses.post(f"{BASE}/_plugins/_alerting/monitors", json={"_id": "mon-1"})
    assert oh.ensure_rule_monitor(cluster, cfg, "dest") == "mon-1"
    created = json.loads(responses.calls[-1].request.body)
    responses.reset()
    _monitor_search([{"_id": "mon-1", "_source": {"monitor": created}}])
    responses.get(f"{BASE}/_plugins/_alerting/monitors/mon-1", json={"monitor": created})
    assert oh.ensure_rule_monitor(cluster, cfg, "dest") == "mon-1"
    assert [c.request.method for c in responses.calls] == ["POST", "GET"]  # search and read only: up to date


@responses.activate
def test_ensure_rule_monitor_updates_when_config_changes(cluster, cfg):
    old = oh.rule_monitor_payload(cfg, "dest")
    old["ui_metadata"]["radar_payload_sha256"] = "stale"
    _monitor_search([{"_id": "mon-1", "_source": {"monitor": old}}])
    responses.get(f"{BASE}/_plugins/_alerting/monitors/mon-1", json={"monitor": old})
    responses.put(f"{BASE}/_plugins/_alerting/monitors/mon-1", json={"_id": "mon-1"})
    assert oh.ensure_rule_monitor(cluster, cfg, "dest") == "mon-1"
    assert responses.calls[-1].request.method == "PUT"


@responses.activate
def test_ensure_rule_monitor_replaces_the_old_bucket_monitor(cluster, cfg):
    _monitor_search([{"_id": "old-1", "_source": {"monitor": {"name": oh.RULE_MONITOR_NAME, "monitor_type": "bucket_level_monitor"}}}])
    responses.get(f"{BASE}/_plugins/_alerting/monitors/old-1", json={"monitor": {"monitor_type": "bucket_level_monitor"}})
    responses.delete(f"{BASE}/_plugins/_alerting/monitors/old-1", json={})
    responses.post(f"{BASE}/_plugins/_alerting/monitors", json={"_id": "mon-2"})
    assert oh.ensure_rule_monitor(cluster, cfg, "dest") == "mon-2"
    assert [c.request.method for c in responses.calls] == ["POST", "GET", "DELETE", "POST"]


@responses.activate
def test_ensure_rule_monitor_deletes_when_no_group_uses_rule_mode(cluster):
    cfg = oh.parse_config({"groups": {"admins": _group(mode="model")}})
    _monitor_search([{"_id": "mon-1", "_source": {"monitor": {"name": oh.RULE_MONITOR_NAME}}}])
    responses.get(f"{BASE}/_plugins/_alerting/monitors/mon-1", json={"monitor": {"monitor_type": "query_level_monitor"}})
    responses.delete(f"{BASE}/_plugins/_alerting/monitors/mon-1", json={})
    assert oh.ensure_rule_monitor(cluster, cfg, "dest") is None
    assert responses.calls[-1].request.method == "DELETE"


@responses.activate
def test_dry_run_collects_new_bursts_and_rendered_messages(cluster):
    _monitor_search([{"_id": "mon-1", "_source": {"monitor": {"name": oh.RULE_MONITOR_NAME}}}])
    message = json.dumps({"anomalies": [{"entity": "arash"}, None]})
    responses.post(
        f"{BASE}/_plugins/_alerting/monitors/mon-1/_execute",
        json={
            "input_results": {"results": [{"aggregations": {"users": {"buckets": [ARASH]}}}], "error": None},
            "trigger_results": {"t1": {"name": oh.RULE_TRIGGER_NAME, "triggered": True, "action_results": {"a1": {"output": {"subject": "s", "message": message}}}}},
        },
    )
    out = oh.dry_run_rule_monitor(cluster)
    assert out["input_error"] is None and out["triggered"] == [True]
    assert out["new_bursts"] == [ARASH]
    assert out["messages"] == [{"anomalies": [{"entity": "arash"}, None]}]
    assert "dryrun=true" in responses.calls[-1].request.url


@responses.activate
def test_rule_mode_status_reports_every_hop(cluster):
    _monitor_search([{"_id": "mon-1", "_source": {"monitor": {"name": oh.RULE_MONITOR_NAME}}}])
    responses.get(f"{BASE}/_plugins/_alerting/monitors/mon-1", json={"monitor": {"enabled": True, "last_update_time": 1}})
    responses.get(
        f"{BASE}/_plugins/_alerting/monitors/alerts",
        json={"alerts": [{"state": "ACTIVE", "agg_alert_content": {"bucket_keys": ["arash"]}, "error_message": None, "alert_history": [{"message": "x"}], "action_execution_results": []}]},
    )
    responses.post(f"{BASE}/wazuh-archives-*/_search", json={"hits": {"hits": [{"_source": {"full_log": "ad_alert: ...", "rule": {"id": "210039"}}}]}})
    responses.post(f"{BASE}/wazuh-alerts-*/_search", json={"hits": {"hits": []}})
    out = oh.rule_mode_status(cluster)
    assert out["monitor"]["id"] == "mon-1" and out["monitor_alerts"][0]["state"] == "ACTIVE"
    assert out["webhook_lines"][0]["rule"]["id"] == "210039" and out["wazuh_alerts"] == []
    assert "monitorId=mon-1" in responses.calls[2].request.url and "alertState=ALL" in responses.calls[2].request.url


# --- model mode -----------------------------------------------------------------

DET_SEARCH = f"{BASE}/_plugins/_anomaly_detection/detectors/_search"
DET = f"{BASE}/_plugins/_anomaly_detection/detectors"


def _detector_search(*ids):
    responses.post(DET_SEARCH, json={"hits": {"hits": [{"_id": i} for i in ids]}})


def _detector_get(det_id, detector=None, running=False):
    body = {"anomaly_detector": detector or {}, "anomaly_detector_job": {"enabled": running}}
    responses.get(f"{DET}/{det_id}", json=body)


def _calls():
    return [(c.request.method, c.request.url.split(BASE)[1].split("?")[0]) for c in responses.calls]


def test_model_detector_spec(cfg):
    spec = oh.model_detector_spec(cfg)
    assert spec["name"] == oh.MODEL_DETECTOR_NAME and spec["indices"] == ["wazuh-archives-*"]
    assert spec["category_field"] == ["radar.user"] and spec["time_field"] == "@timestamp"
    assert spec["feature_attributes"] == [{"feature_name": "off_hours_events", "feature_enabled": True, "aggregation_query": {"off_hours_events": {"sum": {"field": "radar.off_hours"}}}}]
    assert spec["filter_query"] == {"bool": {"filter": [{"exists": {"field": "radar.off_hours"}}, {"terms": {"radar.schedule_group": ["synthetic_admin"]}}]}}
    assert spec["detection_interval"]["period"] == {"interval": 30, "unit": "Minutes"}
    assert spec["window_delay"]["period"] == {"interval": 10, "unit": "Minutes"}
    assert spec["shingle_size"] == 1 and spec["result_index"] == oh.MODEL_RESULT_INDEX
    assert spec["result_index"].startswith("opensearch-ad-plugin-result-")  # AD's rule for custom result indices
    assert "imputation_option" not in spec  # intervals without events are skipped, not scored as 0
    assert "minute" not in json.dumps(spec["feature_attributes"])


def test_model_detector_spec_hash_tracks_the_config(cfg):
    same = oh.model_detector_spec(oh.parse_config(copy.deepcopy(TABLE["config"])))
    assert oh.model_detector_spec(cfg)["description"] == same["description"]
    assert oh.SPEC_HASH_MARK in same["description"]
    changed = oh.model_detector_spec(oh.parse_config(_raw(model_mode={"interval_minutes": 60})))
    assert changed["description"] != same["description"]


def test_model_detector_honours_event_filter():
    spec = oh.model_detector_spec(oh.parse_config(_raw(event_filter={"field": "decoder.name", "values": ["sshd"]})))
    assert {"terms": {"decoder.name": ["sshd"]}} in spec["filter_query"]["bool"]["filter"]


def test_model_monitor_payload(cfg):
    import monitor as monitor_mod

    payload = oh.model_monitor_payload(cfg, "det-9", "dest")
    search = payload["inputs"][0]["search"]
    assert search["indices"] == [oh.MODEL_RESULT_INDEX]
    filters = search["query"]["query"]["bool"]["filter"]
    assert {"nested": {"path": "feature_data", "query": {"range": {"feature_data.data": {"gte": 1}}}}} in filters
    assert {"range": {"anomaly_grade": {"gte": 0.01}}} in filters
    assert monitor_mod._extract_detector_id(payload) == "det-9"
    assert payload["name"] == oh.MODEL_MONITOR_NAME and payload["triggers"][0]["name"] == oh.MODEL_TRIGGER_NAME
    assert payload["inputs"][0]["search"]["query"]["size"] == 10
    assert payload["schedule"]["period"]["interval"] == 30


def test_model_trigger_name_is_matched_by_rule_210040():
    rules = (Path(__file__).resolve().parents[2] / "scenarios/rules/suspicious_login/a3-suspicious-login.xml").read_text()
    block = rules[rules.index('<rule id="210040"') : rules.index("</rule>", rules.index('<rule id="210040"'))]
    assert f"<match>{oh.MODEL_TRIGGER_NAME}</match>" in block
    assert oh.MODEL_TRIGGER_NAME not in oh.RULE_TRIGGER_NAME and oh.RULE_TRIGGER_NAME not in oh.MODEL_TRIGGER_NAME


@responses.activate
def test_ensure_model_detector_creates_and_starts(cluster, cfg):
    responses.post(DET_SEARCH, status=404)  # no AD system index yet
    responses.post(DET, json={"_id": "det-1"}, status=201)
    responses.post(f"{DET}/det-1/_start", json={})
    assert oh.ensure_model_detector(cluster, cfg) == "det-1"
    assert _calls() == [("POST", "/_plugins/_anomaly_detection/detectors/_search"), ("POST", "/_plugins/_anomaly_detection/detectors"), ("POST", "/_plugins/_anomaly_detection/detectors/det-1/_start")]
    assert json.loads(responses.calls[1].request.body) == oh.model_detector_spec(cfg)


@responses.activate
def test_ensure_model_detector_leaves_a_current_running_detector(cluster, cfg):
    _detector_search("det-1")
    _detector_get("det-1", oh.model_detector_spec(cfg), running=True)
    assert oh.ensure_model_detector(cluster, cfg) == "det-1"
    assert [m for m, _ in _calls()] == ["POST", "GET"]


@responses.activate
def test_ensure_model_detector_restarts_a_stopped_detector(cluster, cfg):
    _detector_search("det-1")
    _detector_get("det-1", oh.model_detector_spec(cfg), running=False)
    responses.post(f"{DET}/det-1/_start", json={})
    oh.ensure_model_detector(cluster, cfg)
    assert _calls()[-1] == ("POST", "/_plugins/_anomaly_detection/detectors/det-1/_start")


@responses.activate
def test_ensure_model_detector_stops_updates_and_restarts_a_stale_detector(cluster, cfg):
    _detector_search("det-1")
    _detector_get("det-1", {"description": "old"}, running=True)
    responses.post(f"{DET}/det-1/_stop", json={})
    responses.put(f"{DET}/det-1", json={})
    responses.post(f"{DET}/det-1/_start", json={})
    oh.ensure_model_detector(cluster, cfg)
    assert [c for c in _calls()[2:]] == [
        ("POST", "/_plugins/_anomaly_detection/detectors/det-1/_stop"),
        ("PUT", "/_plugins/_anomaly_detection/detectors/det-1"),
        ("POST", "/_plugins/_anomaly_detection/detectors/det-1/_start"),
    ]


@responses.activate
def test_ensure_model_detector_deletes_when_no_group_uses_model_mode(cluster):
    cfg = oh.parse_config({"groups": {"staff": _group()}})
    _detector_search("det-1")
    _detector_get("det-1", running=True)
    responses.post(f"{DET}/det-1/_stop", json={})
    responses.delete(f"{DET}/det-1", json={})
    assert oh.ensure_model_detector(cluster, cfg) is None
    assert [m for m, _ in _calls()] == ["POST", "GET", "POST", "DELETE"]


@responses.activate
def test_ensure_model_monitor_creates_updates_and_deletes(cluster, cfg):
    _monitor_search([])
    responses.post(f"{BASE}/_plugins/_alerting/monitors", json={"_id": "mm-1"})
    assert oh.ensure_model_monitor(cluster, cfg, "det-1", "dest") == "mm-1"
    created = json.loads(responses.calls[-1].request.body)
    responses.reset()
    _monitor_search([{"_id": "mm-1", "_source": {"monitor": created}}])
    assert oh.ensure_model_monitor(cluster, cfg, "det-1", "dest") == "mm-1"
    assert len(responses.calls) == 1  # up to date
    responses.reset()
    _monitor_search([{"_id": "mm-1", "_source": {"monitor": created}}])
    responses.put(f"{BASE}/_plugins/_alerting/monitors/mm-1", json={})
    oh.ensure_model_monitor(cluster, cfg, "det-2", "dest")  # the detector was recreated
    assert responses.calls[-1].request.method == "PUT"
    responses.reset()
    _monitor_search([{"_id": "mm-1", "_source": {"monitor": created}}])
    responses.delete(f"{BASE}/_plugins/_alerting/monitors/mm-1", json={})
    assert oh.ensure_model_monitor(cluster, cfg, None, "") is None
    assert responses.calls[-1].request.method == "DELETE"


LEGACY_MONITOR = {
    "type": "monitor",
    "monitor_type": "query_level_monitor",
    "name": "SuspiciousLogin-OffHour-Monitor",
    "enabled": True,
    "enabled_time": 1700000000000,
    "last_update_time": 1700000000000,
    "schedule": {"period": {"interval": 5, "unit": "MINUTES"}},
    "inputs": [{"search": {"indices": ["x"], "query": {}}}],
    "triggers": [{"query_level_trigger": {"name": "SuspiciousLogin-OffHour-Detected"}}],
    "ui_metadata": {},
}


@responses.activate
def test_retire_legacy_disables_the_old_monitor_and_stops_the_old_detector(cluster):
    responses.post(f"{BASE}/_plugins/_alerting/monitors/_search", json={"hits": {"hits": [{"_id": "old-m", "_source": {"monitor": LEGACY_MONITOR}}]}})
    responses.get(f"{BASE}/_plugins/_alerting/monitors/old-m", json={"monitor": LEGACY_MONITOR})
    responses.put(f"{BASE}/_plugins/_alerting/monitors/old-m", json={})

    def by_name(request):
        name = json.loads(request.body)["query"]["term"]["name.keyword"]
        hits = [{"_id": "old-d"}] if name == "SUSPICIOUS_LOGIN_DETECTOR" else []
        return 200, {}, json.dumps({"hits": {"hits": hits}})

    responses.add_callback(responses.POST, DET_SEARCH, callback=by_name)
    _detector_get("old-d", running=True)
    responses.post(f"{DET}/old-d/_stop", json={})
    done = oh.retire_legacy(cluster)
    assert done == ["disabled monitor SuspiciousLogin-OffHour-Monitor (old-m)", "stopped detector SUSPICIOUS_LOGIN_DETECTOR (old-d)"]
    put = json.loads(next(c for c in responses.calls if c.request.method == "PUT").request.body)
    assert put["enabled"] is False and "enabled_time" not in put and put["triggers"] == LEGACY_MONITOR["triggers"]
    assert not any(c.request.method == "DELETE" for c in responses.calls)  # kept for inspection


@responses.activate
def test_retire_legacy_is_quiet_when_nothing_is_left(cluster):
    responses.post(f"{BASE}/_plugins/_alerting/monitors/_search", json={"hits": {"hits": [{"_id": "old-m", "_source": {"monitor": dict(LEGACY_MONITOR, enabled=False)}}]}})
    responses.get(f"{BASE}/_plugins/_alerting/monitors/old-m", json={"monitor": dict(LEGACY_MONITOR, enabled=False)})
    responses.post(DET_SEARCH, status=404)
    assert oh.retire_legacy(cluster) == []
    assert all(c.request.method in ("POST", "GET") and "_stop" not in c.request.url for c in responses.calls)


def test_sync_order_and_destination(monkeypatch, cluster, cfg):
    log = []
    monkeypatch.setattr(oh, "retire_legacy", lambda c: log.append("retire"))
    monkeypatch.setattr(oh, "ensure_model_detector", lambda c, k: log.append(("detector", k is not None)) or ("det-1" if k else None))
    monkeypatch.setattr(oh, "ensure_model_monitor", lambda c, k, d, dest: log.append(("model_monitor", d, dest)))
    monkeypatch.setattr(oh, "ensure_rule_monitor", lambda c, k, dest: log.append(("rule_monitor", dest)))
    oh.sync(cluster, cfg, lambda: "dest")
    assert log == ["retire", ("detector", True), ("model_monitor", "det-1", "dest"), ("rule_monitor", "dest")]
    log.clear()

    def no_webhook():
        raise AssertionError("no monitor to create, so no webhook lookup")

    oh.sync(cluster, None, no_webhook)  # block absent or disabled: everything is removed
    assert log == ["retire", ("model_monitor", None, ""), ("detector", False), ("rule_monitor", "")]


def test_cli_monitors_runs_sync_even_when_disabled(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    seen = []
    monkeypatch.setattr(oh, "cluster_from_env", lambda: "cluster")
    monkeypatch.setattr(oh, "sync", lambda c, k, dest: seen.append(k))
    (tmp_path / "config.yaml").write_text(yaml.safe_dump({"scenarios": {"suspicious_login": {"off_hours": _raw(enabled=False)}}}))
    assert oh.main(["monitors"]) == 0
    (tmp_path / "config.yaml").write_text(yaml.safe_dump({"scenarios": {"suspicious_login": {"off_hours": _raw()}}}))
    assert oh.main(["monitors"]) == 0
    assert seen[0] is None and seen[1].groups_in_mode("model") == ["synthetic_admin"]


@responses.activate
def test_dry_run_model_monitor(cluster):
    _monitor_search([{"_id": "mm-1", "_source": {"monitor": {"name": oh.MODEL_MONITOR_NAME}}}])
    hit = {"entity": [{"name": "radar.user", "value": "trent"}], "anomaly_grade": 0.8, "feature_data": [{"data": 30.0}]}
    responses.post(
        f"{BASE}/_plugins/_alerting/monitors/mm-1/_execute",
        json={"input_results": {"results": [{"hits": {"hits": [{"_source": hit}]}}]}, "trigger_results": {"t": {"triggered": True, "action_results": {"a": {"output": {"message": '{"anomalies": [null]}'}}}}}},
    )
    out = oh.dry_run_model_monitor(cluster)
    assert out["anomalies"] == [hit] and out["triggered"] == [True] and out["messages"] == [{"anomalies": [None]}]


@responses.activate
def test_model_mode_status(cluster):
    _detector_search("det-1")
    _detector_get("det-1", running=True)
    responses.get(f"{DET}/det-1/_profile/state,error,total_entities,active_entities", json={"state": "RUNNING", "total_entities": 1})
    responses.post(f"{BASE}/{oh.MODEL_RESULT_INDEX}*/_search", json={"hits": {"hits": [{"_source": {"anomaly_grade": 0.8}}]}})
    responses.post(f"{BASE}/_plugins/_alerting/monitors/_search", status=404)
    responses.post(f"{BASE}/wazuh-archives-*/_search", json={"hits": {"hits": []}})
    responses.post(f"{BASE}/wazuh-alerts-*/_search", json={"hits": {"hits": [{"_source": {"rule": {"id": "210040"}}}]}})
    out = oh.model_mode_status(cluster)
    assert out["detector"] == {"id": "det-1", "running": True, "profile": {"state": "RUNNING", "total_entities": 1}}
    assert out["anomalies"] == [{"anomaly_grade": 0.8}] and out["monitor"] is None
    assert out["wazuh_alerts"][0]["rule"]["id"] == "210040"
    assert json.loads(responses.calls[-1].request.body)["query"] == {"term": {"rule.id": "210040"}}
