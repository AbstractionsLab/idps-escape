from pathlib import Path
import responses
from anomaly_detector import monitor as mon

FIXT = Path(__file__).with_suffix("").parent / "fixtures"

def write_env(tmp_path):
    (tmp_path / ".env").write_text((FIXT / "envfile").read_text())

def write_cfg(tmp_path):
    (tmp_path / "config.yaml").write_text((FIXT / "config.yaml").read_text())


@responses.activate
def test_monitor_find_existing_then_print_id(tmp_path, monkeypatch, capsys):
    write_env(tmp_path)
    write_cfg(tmp_path)
    monkeypatch.chdir(tmp_path)

    os_base = "http://indexer:9200"

    # ensure_webhook path (destinations list returns existing)
    responses.add(
        responses.GET,
        f"{os_base}/_plugins/_notifications/configs",
        json={"items": []},
        status=200,
    )

    responses.add(
        responses.POST,
        f"{os_base}/_plugins/_notifications/configs",
        json={"config_id": "dest-1"},
        status=200,
    )

    # search monitor returns the monitor RADAR would deploy now (same fingerprint)
    stored = _current_payload("det-12345")
    responses.add(
        responses.POST,
        f"{os_base}/_plugins/_alerting/monitors/_search",
        json={"hits": {"hits": [{"_id": "mon-42", "_source": {"monitor": stored}}]}},
        status=200,
    )

    mon.sys.argv = ["monitor.py", "suspicious_login", "det-12345"]
    mon.main()

    assert capsys.readouterr().out.strip() == "mon-42"
    assert not [r for r in responses.calls if r.request.method == "PUT"]


def _current_payload(detector_id):
    import yaml
    scn = yaml.safe_load((FIXT / "config.yaml").read_text())["scenarios"]["suspicious_login"]
    payload = mon.monitor_payload("suspicious_login", scn, detector_id, "dest-1")
    payload["name"] = "suspicious_login-monitor"
    payload["ui_metadata"][mon.PAYLOAD_HASH_KEY] = mon.payload_hash(payload)
    return payload


@responses.activate
def test_monitor_with_stale_fingerprint_is_updated(tmp_path, monkeypatch, capsys):
    write_env(tmp_path)
    write_cfg(tmp_path)
    monkeypatch.chdir(tmp_path)
    os_base = "http://indexer:9200"
    responses.add(responses.GET, f"{os_base}/_plugins/_notifications/configs", json={"items": []}, status=200)
    responses.add(responses.POST, f"{os_base}/_plugins/_notifications/configs", json={"config_id": "dest-1"}, status=200)
    stored = _current_payload("det-12345")
    stored["ui_metadata"][mon.PAYLOAD_HASH_KEY] = "an-older-payload"
    responses.add(responses.POST, f"{os_base}/_plugins/_alerting/monitors/_search",
                  json={"hits": {"hits": [{"_id": "mon-42", "_source": {"monitor": stored}}]}}, status=200)
    responses.add(responses.PUT, f"{os_base}/_plugins/_alerting/monitors/mon-42", json={"_id": "mon-42"}, status=200)

    mon.sys.argv = ["monitor.py", "suspicious_login", "det-12345"]
    mon.main()

    assert capsys.readouterr().out.strip() == "mon-42"
    assert len([r for r in responses.calls if r.request.method == "PUT"]) == 1


def test_detector_id_is_read_from_a_stored_monitor():
    assert mon._extract_detector_id(_current_payload("det-9")) == "det-9"


def test_query_reports_every_qualifying_entity():
    query = mon.monitor_payload("s", {"result_index": "r", "anomaly_grade_threshold": 0.6, "confidence_threshold": 0.7,
                                      "monitor_max_entities": 7}, "det", "dest")["inputs"][0]["search"]["query"]
    assert query["size"] == 7
    filters = query["query"]["bool"]["filter"]
    assert {"range": {"anomaly_grade": {"gte": 0.6}}} in filters
    assert {"range": {"confidence": {"gte": 0.7}}} in filters


def test_message_template_renders_valid_json_with_legacy_keys():
    import json
    import re
    src = mon.message_template()
    loop = re.search(r"\{\{#ctx\.results\.0\.hits\.hits\}\}(.*)\{\{/ctx\.results\.0\.hits\.hits\}\}", src).group(1)
    # Render the mustache loop for two hits, then every remaining tag as a plain value.
    rendered = src.replace(re.search(r"\{\{#.*\{\{/ctx\.results\.0\.hits\.hits\}\}", src).group(0), loop * 2)
    body = json.loads(re.sub(r"\{\{[^}]+\}\}", "v", rendered))
    assert {"entity", "anomaly_grade", "anomaly_confidence", "periodStart", "periodEnd", "dataStart", "dataEnd"} <= set(body)
    assert len(body["anomalies"]) == 3 and body["anomalies"][-1] is None
    assert set(body["anomalies"][0]) == {"entity", "anomaly_grade", "anomaly_confidence", "dataStart", "dataEnd"}


@responses.activate
def test_monitor_reattaches_to_new_detector(tmp_path, monkeypatch, capsys):
    write_env(tmp_path)
    write_cfg(tmp_path)
    monkeypatch.chdir(tmp_path)

    os_base = "http://indexer:9200"

    responses.add(
        responses.GET,
        f"{os_base}/_plugins/_notifications/configs",
        json={"items": []},
        status=200,
    )

    responses.add(
        responses.POST,
        f"{os_base}/_plugins/_notifications/configs",
        json={"config_id": "dest-1"},
        status=200,
    )

    # search monitor returns one with a stale detector_id
    responses.add(
        responses.POST,
        f"{os_base}/_plugins/_alerting/monitors/_search",
        json={"hits": {"hits": [{"_id": "mon-42", "_source": {"monitor": _current_payload("det-OLD")}}]}},
        status=200,
    )

    responses.add(
        responses.PUT,
        f"{os_base}/_plugins/_alerting/monitors/mon-42",
        json={"_id": "mon-42"},
        status=200,
    )

    mon.sys.argv = ["monitor.py", "suspicious_login", "det-12345"]
    mon.main()

    assert capsys.readouterr().out.strip() == "mon-42"
    import json
    put_body = json.loads([r for r in responses.calls if r.request.method == "PUT"][0].request.body)
    filters = put_body["inputs"][0]["search"]["query"]["query"]["bool"]["filter"]
    assert any(f.get("term", {}).get("detector_id", {}).get("value") == "det-12345" for f in filters)


@responses.activate
def test_monitor_create_when_missing(tmp_path, monkeypatch, capsys):
    write_env(tmp_path)
    write_cfg(tmp_path)
    monkeypatch.chdir(tmp_path)

    os_base = "http://indexer:9200"

    responses.add(
        responses.GET,
        f"{os_base}/_plugins/_notifications/configs",
        json={"items": []},
        status=200,
    )
    responses.add(
        responses.POST,
        f"{os_base}/_plugins/_notifications/configs",
        json={"config_id": "dest-1"},
        status=200,
    )

    responses.add(
        responses.POST,
        f"{os_base}/_plugins/_alerting/monitors/_search",
        json={"hits": {"hits": []}},
        status=200,
    )

    responses.add(
        responses.POST,
        f"{os_base}/_plugins/_alerting/monitors",
        json={"_id": "mon-77"},
        status=200,
    )

    mon.sys.argv = ["monitor.py", "suspicious_login", "det-12345"]
    mon.main()

    assert capsys.readouterr().out.strip() == "mon-77"