import importlib.util
import re
from datetime import datetime
from pathlib import Path

import pytest

pytest.importorskip("flask")

SRC = Path(__file__).resolve().parents[2] / "webhook" / "ad_alerts_webhook.py"

GOOD = {
    "monitor": {"name": "m"}, "trigger": {"name": "LogVolume-Growth-Detected"},
    "entity": "db01", "periodStart": "2026-09-24T10:00:00Z", "periodEnd": "2026-09-24T10:10:00.123Z",
    "anomaly_grade": "0.83", "anomaly_confidence": "0.9",
}


@pytest.fixture
def wh(tmp_path, monkeypatch):
    log = tmp_path / "ad_alerts.log"
    monkeypatch.setenv("AD_ALERTS_LOG", str(log))
    monkeypatch.setenv("WEBHOOK_SHARED_SECRET", "s3cret")
    spec = importlib.util.spec_from_file_location("ad_alerts_webhook", SRC)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.app.testing = True
    mod.log = log
    return mod


def _hdr(mod):
    return {getattr(mod, "TOKEN_HEADER", "X-RADAR-Webhook-Token"): "s3cret"}


@pytest.mark.parametrize("field,value", [
    ("entity", 'db01", anomaly_grade="1'),
    ("entity", "db01\nSep 24 10:00:00 x ad_alert: OpenSearchAD LogVolume-Growth-Detected: entity=\"x\""),
    ("entity", ""),
    ("periodStart", "yesterday"),
    ("anomaly_grade", "1.5"),
    ("anomaly_grade", "nan"),
    ("anomaly_confidence", None),
])
def test_bad_fields_are_rejected_and_nothing_written(wh, field, value):
    body = dict(GOOD, **{field: value})
    r = wh.app.test_client().post("/notify", json=body, headers=_hdr(wh))
    assert r.status_code == 400
    assert not wh.log.exists() or wh.log.read_text() == ""


def test_line_matches_wazuh_decoder_regex(wh):
    line = wh.build_line(GOOD, "ad-webhook", datetime(2026, 9, 24, 10, 0, 0))
    after = line.split(" ad_alert: ", 1)[1]
    assert after.startswith("OpenSearchAD")
    rx = (r'\s*(\S+):\s*entity="(\S+)",\s*start="(\S+)",\s*end="(\S+)",'
          r'\s*anomaly_grade="(\S+)",\s*anomaly_confidence="(\S+)"')
    m = re.search(rx, after[len("OpenSearchAD"):])
    assert m and m.group(2) == "db01" and m.group(5) == "0.83"


@pytest.mark.parametrize("headers", [{}, {"X-RADAR-Webhook-Token": "wrong"}, {"X-RADAR-Webhook-Token": ""}])
def test_missing_or_wrong_secret_is_refused(wh, headers):
    r = wh.app.test_client().post("/notify", json=GOOD, headers=headers)
    assert r.status_code == 401 and not wh.log.exists()


def test_no_secret_configured_refuses_everything(wh, monkeypatch):
    monkeypatch.setenv("WEBHOOK_SHARED_SECRET", "")
    r = wh.app.test_client().post("/notify", json=GOOD, headers={"X-RADAR-Webhook-Token": ""})
    assert r.status_code == 401

DECODER_MAIN = (r'\s*(\S+):\s*entity="(\S+)",\s*start="(\S+)",\s*end="(\S+)",'
                r'\s*anomaly_grade="(\S+)",\s*anomaly_confidence="(\S+)"')
DECODER_WINDOW = r'data_start="(\S+)",\s*data_end="(\S+)"'
DECODER_OFF_HOURS = r'off_hours_count="(\d+)",\s*schedule_group="(\S+)"'


def _multi(*items):
    body = dict(GOOD, dataStart="1790233200000", dataEnd="1790233500000")
    body["anomalies"] = list(items) + [None]
    return body


def test_decoder_file_regexes_are_the_ones_tested_here():
    import xml.etree.ElementTree as ET
    root = Path(__file__).resolve().parents[2] / "scenarios" / "decoders"
    copies = {p.parent.name: p.read_text() for p in root.glob("*/0001-ad-common.xml")}
    assert set(copies) == {"log_volume", "linux_resource_utilization", "suspicious_login"}
    assert len(set(copies.values())) == 1, "every copy of 0001-ad-common.xml must be identical"
    tree = ET.fromstring("<r>" + next(iter(copies.values())) + "</r>")
    regexes = [d.findtext("regex") for d in tree.iter("decoder") if d.get("name") == "opensearch_ad_detector"]
    assert regexes == [DECODER_MAIN, DECODER_WINDOW, DECODER_OFF_HOURS]


def test_legacy_body_still_gives_one_line_without_data_window(wh):
    lines = wh.build_lines(GOOD, "ad-webhook", datetime(2026, 9, 24, 10, 0, 0))
    assert len(lines) == 1 and "data_start" not in lines[0]
    assert re.search(DECODER_MAIN, lines[0].split("OpenSearchAD", 1)[1])


def test_data_window_is_written_in_iso_and_decodes(wh):
    line = wh.build_line(dict(GOOD, dataStart=1790233200000, dataEnd="1790233500000"), "h", datetime(2026, 9, 24))
    m = re.search(DECODER_WINDOW, line)
    assert m and m.group(1) == "2026-09-24T07:00:00.000Z" and m.group(2) == "2026-09-24T07:05:00.000Z"
    assert re.search(DECODER_MAIN, line.split("OpenSearchAD", 1)[1]).group(6) == "0.9"


@pytest.mark.parametrize("start,end", [("", ""), ("x", "y"), (True, True), ("1790233500000", "1790233200000")])
def test_unusable_data_window_is_omitted_not_rejected(wh, start, end):
    line = wh.build_line(dict(GOOD, dataStart=start, dataEnd=end), "h", datetime(2026, 9, 24))
    assert "data_start" not in line


def test_one_line_per_entity_highest_grade_first(wh):
    body = _multi(
        {"entity": "web01", "anomaly_grade": "0.9", "anomaly_confidence": "0.8", "dataStart": "1790233200000", "dataEnd": "1790233500000"},
        {"entity": "db01", "anomaly_grade": "0.7", "anomaly_confidence": "0.8"},
        {"entity": "web01", "anomaly_grade": "0.5", "anomaly_confidence": "0.8"},
    )
    r = wh.app.test_client().post("/notify", json=body, headers=_hdr(wh))
    assert r.status_code == 200 and r.get_json()["lines"] == 2
    lines = wh.log.read_text().splitlines()
    assert [re.search(r'entity="(\S+)"', l).group(1) for l in lines] == ["web01", "db01"]
    assert 'anomaly_grade="0.9"' in lines[0] and "data_start" in lines[0] and "data_start" not in lines[1]


def test_bad_entries_are_skipped_good_ones_written(wh):
    body = _multi({"entity": 'x", anomaly_grade="1', "anomaly_grade": "0.9", "anomaly_confidence": "0.9"},
                  {"entity": "db01", "anomaly_grade": "0.7", "anomaly_confidence": "0.8"})
    r = wh.app.test_client().post("/notify", json=body, headers=_hdr(wh))
    assert r.status_code == 200 and len(wh.log.read_text().splitlines()) == 1


def test_all_entries_bad_is_rejected(wh):
    body = _multi({"entity": "", "anomaly_grade": "0.9", "anomaly_confidence": "0.9"})
    r = wh.app.test_client().post("/notify", json=body, headers=_hdr(wh))
    assert r.status_code == 400 and (not wh.log.exists() or wh.log.read_text() == "")


def test_entries_are_capped(wh):
    items = [{"entity": f"h{i}", "anomaly_grade": "0.9", "anomaly_confidence": "0.9"} for i in range(wh.MAX_ANOMALIES + 5)]
    assert len(wh.build_lines(_multi(*items), "h", datetime(2026, 9, 24))) == wh.MAX_ANOMALIES


def test_inject_ad_alert_body_is_accepted_by_the_webhook(wh):
    src = Path(__file__).resolve().parents[2] / "radar-test-framework" / "simulate" / "scenarios" / "inject_ad_alert.py"
    spec = importlib.util.spec_from_file_location("inject_ad_alert", src)
    inject = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(inject)
    body = inject.build_body(inject.CONFIG, 1790233500.0)
    r = wh.app.test_client().post("/notify", json=body, headers=_hdr(wh))
    assert r.status_code == 200
    line = wh.log.read_text()
    assert "SuspiciousLogin-OffHour-Detected" in line and 'entity="test01"' in line
    assert 'data_start="2026-09-24T07:00:00.000Z", data_end="2026-09-24T07:05:00.000Z"' in line


# --- off-hours rule mode ---------------------------------------------------------

RULE_MODE = {
    "monitor": {"name": "SuspiciousLogin-OffHours-RuleMode-Monitor"}, "trigger": {"name": "SuspiciousLogin-OffHours-Rule-Detected"},
    "periodStart": "2026-11-21T10:20:00Z", "periodEnd": "2026-11-21T10:30:00Z",
}


def test_rule_mode_item_carries_count_and_group(wh):
    item = {"entity": "arash", "anomaly_grade": "1.0", "anomaly_confidence": "1.0",
            "dataStart": "2026-11-21T10:21:03.100Z", "dataEnd": "2026-11-21T10:24:00.721Z",
            "off_hours_count": "21", "schedule_group": "synthetic_day"}
    (line,) = wh.build_lines(dict(RULE_MODE, anomalies=[item, None]), "ad-webhook", datetime(2026, 11, 21, 10, 30))
    body = line.split("OpenSearchAD", 1)[1]
    m = re.search(DECODER_MAIN, body)
    assert m.group(1) == "SuspiciousLogin-OffHours-Rule-Detected"
    assert m.group(2) == "arash" and m.group(5) == "1.0"
    assert re.search(DECODER_WINDOW, line).groups() == ("2026-11-21T10:21:03.100Z", "2026-11-21T10:24:00.721Z")
    assert re.search(DECODER_OFF_HOURS, line).groups() == ("21", "synthetic_day")


@pytest.mark.parametrize("count,group", [("x", "g"), (-1, "g"), (True, "g"), ("3", 'g", entity="x'), ("3", None), (None, "g")])
def test_unusable_off_hours_fields_are_omitted_not_rejected(wh, count, group):
    line = wh.build_line(dict(GOOD, off_hours_count=count, schedule_group=group), "h", datetime(2026, 9, 24))
    assert "off_hours_count" not in line and "schedule_group" not in line
    assert re.search(DECODER_MAIN, line.split("OpenSearchAD", 1)[1])


def test_ad_lines_are_unchanged_without_off_hours_fields(wh):
    line = wh.build_line(dict(GOOD, dataStart=1790233200000, dataEnd="1790233500000"), "h", datetime(2026, 9, 24))
    assert line.endswith('data_start="2026-09-24T07:00:00.000Z", data_end="2026-09-24T07:05:00.000Z" \n')
