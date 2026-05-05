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

    # search monitor returns one
    responses.add(
        responses.POST,
        f"{os_base}/_plugins/_alerting/monitors/_search",
        json={"hits": {"hits": [{"_id": "mon-42", "_source": {"monitor": {"name": "suspicious_login-monitor", "inputs": [{"search": {"query": {"bool": {"filter": [{"term": {"detector_id": {"value": "det-12345"}}}]}}}}]}}}]}},
        status=200,
    )

    mon.sys.argv = ["monitor.py", "suspicious_login", "det-12345"]
    mon.main()

    assert capsys.readouterr().out.strip() == "mon-42"


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
        json={"hits": {"hits": [{"_id": "mon-42", "_source": {"monitor": {"name": "suspicious_login-monitor", "inputs": [{"search": {"query": {"bool": {"filter": [{"term": {"detector_id": {"value": "det-OLD"}}}]}}}}]}}}]}},
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