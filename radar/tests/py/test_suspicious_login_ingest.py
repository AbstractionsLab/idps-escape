"""Synthetic history for suspicious_login: shifts land on the right days and never look off hours;
only the administrator trent has off-hours events (evenings and one burst), for model mode."""

import importlib.util
import random
from collections import Counter
from datetime import date, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import off_hours as oh
import pytest
import yaml

RADAR = Path(__file__).resolve().parents[2]
SCRIPT = RADAR / "scenarios/ingest_scripts/suspicious_login/wazuh_ingest.py"


@pytest.fixture
def ingest(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # the script reads ./.env at import; keep it away from radar/.env
    spec = importlib.util.spec_from_file_location("sl_ingest", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def shipped():
    return yaml.safe_load((RADAR / "config.yaml").read_text())


@pytest.fixture
def events(ingest, shipped):
    random.seed(7)
    cfg = dict(shipped["scenarios"]["suspicious_login"]["ingest"], history_days=28, future_days=0)
    return ingest.generate_archive_events(cfg)


def _local(doc, tz="Europe/Luxembourg"):
    return datetime.fromisoformat(doc["@timestamp"]).astimezone(ZoneInfo(tz))


def _trent_extra(doc):
    """Trent's evening work (21:00-24:00 local) or the burst (02:00-02:30 local)."""
    t = _local(doc)
    return t.hour >= 21 or (t.hour == 2 and t.minute < 30)


def test_synthetic_shifts_are_never_off_hours(events, shipped):
    cfg = oh.load_config(shipped)
    flags = Counter()
    for _, doc in events:
        result = cfg.classify(doc)
        assert result is not None, doc
        flags[(result["user"], result["off_hours"])] += 1
        if result["user"] == "trent":
            assert result["off_hours"] == (1 if _trent_extra(doc) else 0), doc
        else:
            assert result["off_hours"] == 0, doc
    assert {user for user, _ in flags} == {"alice", "bob", "oscar", "trent"}
    assert flags[("trent", 1)] > 30  # the burst plus some evenings


def test_trent_burst_is_one_interval_at_two_in_the_morning_late_in_the_history(ingest, events):
    burst = [_local(doc) for _, doc in events if doc["data"]["user"] == "trent" and _local(doc).hour < 8]
    assert len(burst) == 30
    assert len({t.date() for t in burst}) == 1 and burst[0].isoweekday() <= 5
    assert all(t.hour == 2 and t.minute < 30 for t in burst)
    days_ago = (date.today() - burst[0].date()).days
    assert 7 <= days_ago <= 28 // 3 + 2  # the last third of a 28-day history


def test_trent_works_about_two_evenings_a_week(events):
    evenings = {_local(doc).date() for _, doc in events if doc["data"]["user"] == "trent" and _local(doc).hour >= 21}
    assert all(d.isoweekday() <= 5 for d in evenings)
    assert 3 <= len(evenings) <= 16  # 20 workdays at 2 in 5


def test_trent_keeps_local_hours_across_the_summer_time_change(ingest, shipped):
    random.seed(3)
    cfg_ingest = dict(shipped["scenarios"]["suspicious_login"]["ingest"], history_days=21, future_days=0)
    events = ingest.generate_archive_events(cfg_ingest, today=date(2026, 4, 10))  # spans 2026-03-29
    cfg = oh.load_config(shipped)
    ordinary = [doc for _, doc in events if doc["data"]["user"] == "trent" and not _trent_extra(doc)]
    offsets = {datetime.fromisoformat(doc["@timestamp"]).astimezone(ZoneInfo("Europe/Luxembourg")).utcoffset().seconds // 3600 for doc in ordinary}
    assert offsets == {1, 2}
    assert ordinary and all(cfg.classify(doc)["off_hours"] == 0 for doc in ordinary)
    assert all(8 <= _local(doc).hour < 19 for doc in ordinary)


def test_burst_day_moves_back_to_a_workday(ingest):
    assert ingest._burst_day(date(2026, 11, 23), 1) == date(2026, 11, 20)  # Sunday -> Friday
    assert ingest._burst_day(date(2026, 11, 23), 3) == date(2026, 11, 20)


def test_late_shift_crosses_midnight_onto_the_next_day(events):
    oscar = [datetime.fromisoformat(doc["@timestamp"]) for _, doc in events if doc["data"]["user"] == "oscar"]
    after_midnight = [t for t in oscar if t.hour < 3]
    assert after_midnight
    assert {t.isoweekday() for t in after_midnight} <= {2, 3, 4, 5, 6}  # Tue-Sat: tails of Mon-Fri shifts
    assert any(t.isoweekday() == 6 for t in after_midnight)


def test_index_follows_the_event_date(events):
    for index, doc in events:
        assert index == "wazuh-archives-4.x-" + doc["@timestamp"][:10].replace("-", ".")


def test_indices_match_the_wazuh_template(ingest, shipped):
    """Only Wazuh's `wazuh` template (wazuh-archives-4.x-*) maps strings as keyword. A
    dynamically mapped wazuh-archives-* index makes agent.name `text`, and AD then refuses
    linux_resource_utilization's detector (category field agent.name on wazuh-archives-*)."""
    assert shipped["scenarios"]["suspicious_login"]["ingest"]["archives_index_prefix"] == "wazuh-archives-4.x"
    cfg = {"users": [{"name": "alice", "start_hour": 9, "end_hour": 17}], "history_days": 7, "future_days": 0}
    indices = {index for index, _ in ingest.generate_archive_events(cfg)}
    assert indices and all(index.startswith("wazuh-archives-4.x-") for index in indices)


def test_bulk_requests_name_the_off_hours_pipeline(ingest, monkeypatch):
    urls = []

    class Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"errors": False}

    monkeypatch.setattr(ingest.requests, "post", lambda url, **kw: urls.append(url) or Resp())
    ingest.bulk_index_archive_events([("wazuh-archives-2026.09.18", {"a": 1})], ingest.OFF_HOURS_PIPELINE)
    ingest.bulk_index_archive_events([("wazuh-archives-2026.09.18", {"a": 1})])
    assert urls[0].endswith("/_bulk?refresh=true&pipeline=radar-off-hours")
    assert urls[1].endswith("/_bulk?refresh=true")
    assert ingest.OFF_HOURS_PIPELINE == oh.PIPELINE_NAME
