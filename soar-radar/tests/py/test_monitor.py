import os
from pathlib import Path
import responses
import monitor as mon

FIXT = Path(__file__).with_suffix("").parent / "fixtures"

def write_env(tmp_path):
    (tmp_path/".env").write_text((FIXT/"envfile").read_text())

def write_cfg(tmp_path):
    (tmp_path/"config.yaml").write_text((FIXT/"config.yaml").read_text())

@responses.activate
def test_monitor_find_existing_then_print_id(tmp_path, monkeypatch, capsys):
    write_env(tmp_path); write_cfg(tmp_path)
    monkeypatch.chdir(tmp_path)

    base = "http://dash:5601"
    # ensure_webhook path (destinations list returns existing)
    responses.add(responses.GET, f"{base}/api/alerting/destinations", json={"destinations":[{"name":"RADAR Hook","id":"dest-1"}]}, status=200)
    # search monitor returns one
    responses.add(responses.POST, f"{base}/api/alerting/monitors/_search",
                  json={"hits":{"hits":[{"_id":"mon-42","_source":{"name":"suspicious_login-monitor"}}]}}, status=200)

    # argv: scenario + detector id
    monkeypatch.setenv("PYTHONPATH", str(Path.cwd()))
    monkeypatch.setenv("DASHBOARD_URL", base)

    mon.sys.argv = ["monitor.py","suspicious_login","det-12345"]
    mon.main()
    assert capsys.readouterr().out.strip() == "mon-42"

@responses.activate
def test_monitor_create_when_missing(tmp_path, monkeypatch, capsys):
    write_env(tmp_path); write_cfg(tmp_path)
    monkeypatch.chdir(tmp_path)
    base = "http://dash:5601"

    responses.add(responses.GET, f"{base}/api/alerting/destinations", json={"destinations":[]}, status=200)
    responses.add(responses.POST, f"{base}/api/alerting/destinations", json={"id":"dest-1"}, status=200)
    responses.add(responses.POST, f"{base}/api/alerting/monitors/_search", json={"hits":{"hits":[]}}, status=200)
    responses.add(responses.POST, f"{base}/api/alerting/monitors", json={"_id":"mon-77"}, status=200)

    mon.sys.argv = ["monitor.py","suspicious_login","det-12345"]
    mon.main()
    assert capsys.readouterr().out.strip() == "mon-77"
