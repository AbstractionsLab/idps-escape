import os, io, json
from pathlib import Path
import responses
from anomaly_detector import detector as det

FIXT = Path(__file__).with_suffix("").parent / "fixtures"

def write_env(tmp_path):
    (tmp_path/".env").write_text((FIXT/"envfile").read_text())

def write_cfg(tmp_path):
    (tmp_path/"config.yaml").write_text((FIXT/"config.yaml").read_text())

def test_index_pattern_and_spec(tmp_path, monkeypatch):
    write_env(tmp_path); write_cfg(tmp_path)
    monkeypatch.chdir(tmp_path)

    cfg = det.load_yaml(Path("config.yaml"))
    name, scn = det.pick_scenario(cfg, None)
    assert name == "suspicious_login"
    assert det.index_pattern(scn) == "wazuh-ad-suspicious-login-*"

    spec = det.detector_spec(name, scn)
    assert spec["indices"] == ["wazuh-ad-suspicious-login-*"]
    assert spec["time_field"] == "@timestamp"
    assert spec["feature_attributes"][0]["feature_enabled"] is True

@responses.activate
def test_find_create_start_happy_path(tmp_path, monkeypatch, capsys):
    write_env(tmp_path); write_cfg(tmp_path)
    monkeypatch.chdir(tmp_path)

    base = "http://indexer:9200"
    # search -> none
    responses.add(
        responses.POST, f"{base}/_plugins/_anomaly_detection/detectors/_search",
        json={"hits":{"hits":[]}}, status=200)
    # create
    responses.add(
        responses.POST, f"{base}/_plugins/_anomaly_detection/detectors",
        json={"_id":"det-12345"}, status=201)
    # start
    responses.add(
        responses.POST, f"{base}/_plugins/_anomaly_detection/detectors/det-12345/_start",
        json={}, status=200)

    det.sys.argv = ["detector.py", "suspicious_login"]
    det.main()
    out = capsys.readouterr().out.strip()
    assert out == "det-12345"

@responses.activate
def test_find_existing_skips_create(tmp_path, monkeypatch, capsys):
    write_env(tmp_path); write_cfg(tmp_path)
    monkeypatch.chdir(tmp_path)

    base = "http://indexer:9200"
    responses.add(
        responses.POST, f"{base}/_plugins/_anomaly_detection/detectors/_search",
        json={"hits":{"hits":[{"_id":"det-999"}]}}, status=200)
    responses.add(
        responses.POST, f"{base}/_plugins/_anomaly_detection/detectors/det-999/_start",
        json={}, status=200)

    det.sys.argv = ["detector.py", "suspicious_login"]
    det.main()
    assert capsys.readouterr().out.strip() == "det-999"
