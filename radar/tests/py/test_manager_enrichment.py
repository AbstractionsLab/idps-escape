import os
import re
import sys
from collections import deque
from pathlib import Path

import pytest

_MANAGER_ENRICHMENT_DIR = Path(__file__).resolve().parents[2] / "manager-enrichment"
if str(_MANAGER_ENRICHMENT_DIR) not in sys.path:
    sys.path.insert(0, str(_MANAGER_ENRICHMENT_DIR))

import enrichment as enrichment_mod
import geoip as geoip_mod
from state_store import UserStateStore


class FakeMaxMindReader:
    """Same fixture shape as test_radar_helper.py's, keyed by IP."""

    def __init__(self, mapping):
        self.mapping = mapping

    def get(self, ip):
        return self.mapping.get(ip)


def make_city_record(country, region, city, lat, lon):
    return {
        "country": {"iso_code": country},
        "subdivisions": [{"names": {"en": region}}] if region else [],
        "city": {"names": {"en": city}} if city else {},
        "location": {"latitude": lat, "longitude": lon},
    }


def make_asn_record(asn):
    return {"autonomous_system_number": asn}


@pytest.fixture
def store(tmp_path):
    return UserStateStore(db_path=str(tmp_path / "user_state.sqlite3"))


def _make_enricher(store, geo_by_ip):
    """geo_by_ip: {ip: (country, region, city, lat, lon, asn_or_none)}"""
    city_reader = FakeMaxMindReader({ip: make_city_record(*rec[:5]) for ip, rec in geo_by_ip.items()})
    asn_reader = FakeMaxMindReader({ip: make_asn_record(rec[5]) for ip, rec in geo_by_ip.items() if rec[5]})
    return enrichment_mod.RadarEnricher(store, city_reader, asn_reader)

def test_geo_lookup_basic_fields():
    city_reader = FakeMaxMindReader({
        "1.2.3.4": make_city_record("LU", "Luxembourg", "Luxembourg", 49.6, 6.1),
    })
    asn_reader = FakeMaxMindReader({"1.2.3.4": make_asn_record(56665)})

    country, region, city, lat, lon, asn = geoip_mod.geo_lookup(city_reader, asn_reader, "1.2.3.4")

    assert country == "LU"
    assert region == "Luxembourg"
    assert city == "Luxembourg"
    assert lat == 49.6 and lon == 6.1
    assert asn == "56665"


def test_geo_lookup_unknown_ip_returns_empty_fields():
    country, region, city, lat, lon, asn = geoip_mod.geo_lookup(
        FakeMaxMindReader({}), FakeMaxMindReader({}), "9.9.9.9"
    )
    assert (country, region, city, asn) == ("", "", "", "")
    assert lat is None and lon is None


def test_geo_lookup_survives_reader_exceptions():
    class BoomReader:
        def get(self, ip):
            raise RuntimeError("boom")

    country, region, city, lat, lon, asn = geoip_mod.geo_lookup(BoomReader(), BoomReader(), "1.2.3.4")
    assert (country, region, city, asn) == ("", "", "", "")
    assert lat is None and lon is None


def test_haversine_km_basic():
    d = enrichment_mod.haversine_km(0.0, 0.0, 0.0, 1.0)
    assert 110.0 < d < 112.5


def test_parse_auth_line_detects_success():
    line = "Aug 07 10:19:59 edge.vm sshd[1169457]: Accepted publickey for test01 from 8.8.8.8 port 60850 ssh2"
    result = enrichment_mod.parse_auth_line(line)
    assert result is not None
    ts, user, srcip, outcome = result
    assert user == "test01"
    assert srcip == "8.8.8.8"
    assert outcome == "success"


def test_parse_auth_line_detects_failure():
    line = "Aug 07 10:19:11 edge.vm sshd[1169457]: Failed password for test01 from 8.8.8.8 port 1045 ssh2"
    result = enrichment_mod.parse_auth_line(line)
    assert result is not None
    _, user, srcip, outcome = result
    assert user == "test01"
    assert outcome == "failure"


def test_parse_auth_line_handles_invalid_user_failure():
    line = "Aug 07 10:19:11 edge.vm sshd[1169457]: Failed password for invalid user root from 8.8.8.8 port 22 ssh2"
    result = enrichment_mod.parse_auth_line(line)
    assert result is not None
    _, user, srcip, outcome = result
    assert user == "root"
    assert outcome == "failure"


def test_parse_auth_line_returns_none_for_unrelated_line():
    assert enrichment_mod.parse_auth_line("some unrelated line") is None


def test_parse_auth_line_returns_none_without_valid_header():
    assert enrichment_mod.parse_auth_line("Accepted password for root from 1.2.3.4 port 22 ssh2") is None

def test_first_login_has_zero_velocity_and_no_country_change(store):
    geo = {"1.2.3.4": ("US", "California", "Mountain View", 37.4, -122.1, "15169")}
    enricher = _make_enricher(store, geo)

    fields = enricher.enrich("alice", "1.2.3.4", event_ts=1_700_000_000.0, outcome="success")

    assert fields["geo_velocity_kmh"] == 0.0
    assert fields["country_change_i"] == 0
    assert fields["asn_novelty_i"] == 1  # first time this ASN is seen for alice
    assert fields["asn_placeholder_flag"] == "false"
    assert fields["country"] == "US"


def test_country_change_detected_on_second_login(store):
    geo = {
        "1.2.3.4": ("US", "California", "Mountain View", 37.4, -122.1, "15169"),
        "5.6.7.8": ("LU", "Luxembourg", "Luxembourg", 49.6, 6.1, "56665"),
    }
    enricher = _make_enricher(store, geo)

    enricher.enrich("alice", "1.2.3.4", event_ts=1_700_000_000.0, outcome="success")
    fields = enricher.enrich("alice", "5.6.7.8", event_ts=1_700_003_600.0, outcome="success")

    assert fields["country_change_i"] == 1


def test_velocity_calculation_between_two_logins(store):
    geo = {
        "1.2.3.4": ("US", "", "", 40.0, -74.0, "1"),    # New York-ish
        "5.6.7.8": ("US", "", "", 34.0, -118.2, "2"),   # LA-ish, ~3900+ km away
    }
    enricher = _make_enricher(store, geo)

    enricher.enrich("bob", "1.2.3.4", event_ts=0.0, outcome="success")
    fields = enricher.enrich("bob", "5.6.7.8", event_ts=3600.0, outcome="success")  # 1h later

    assert fields["geo_velocity_kmh"] > 900  # clearly "impossible travel"


def test_asn_novelty_is_per_user_not_global(store):
    geo = {"1.2.3.4": ("US", "", "", 1.0, 1.0, "111")}
    enricher = _make_enricher(store, geo)

    first_alice = enricher.enrich("alice", "1.2.3.4", event_ts=0.0, outcome="success")
    first_bob = enricher.enrich("bob", "1.2.3.4", event_ts=0.0, outcome="success")
    second_alice = enricher.enrich("alice", "1.2.3.4", event_ts=100.0, outcome="success")

    assert first_alice["asn_novelty_i"] == 1
    assert first_bob["asn_novelty_i"] == 1   # bob's own history, independently novel
    assert second_alice["asn_novelty_i"] == 0  # alice has seen ASN 111 before


def test_asn_placeholder_flag_when_asn_missing(store):
    city_reader = FakeMaxMindReader({"1.2.3.4": make_city_record("US", "", "", 1.0, 1.0)})
    asn_reader = FakeMaxMindReader({})  # ASN lookup returns nothing
    enricher = enrichment_mod.RadarEnricher(store, city_reader, asn_reader)

    fields = enricher.enrich("carol", "1.2.3.4", event_ts=0.0, outcome="failure")

    assert fields["asn"] == ""
    assert fields["asn_placeholder_flag"] == "true"
    assert fields["asn_novelty_i"] == 0


def test_drop_old_expires_asn_history_past_90_days():
    asn_hist = deque([("111", 0)])
    asn_set = {"111"}
    ninety_one_days_later = 91 * 24 * 3600

    enrichment_mod.drop_old(asn_hist, asn_set, ninety_one_days_later)

    assert "111" not in asn_set
    assert len(asn_hist) == 0


def test_drop_old_keeps_asn_still_referenced_by_newer_entry():
    asn_hist = deque([("111", 0), ("111", 91 * 24 * 3600)])
    asn_set = {"111"}

    enrichment_mod.drop_old(asn_hist, asn_set, 91 * 24 * 3600)

    assert "111" in asn_set
    assert len(asn_hist) == 1


def test_velocity_is_calculated_across_two_different_source_endpoints(store):
    geo_a = {"10.0.0.1": ("US", "", "", 40.7, -74.0, "64500")}   # endpoint A's local view
    geo_b = {"10.0.0.2": ("LU", "", "", 49.6, 6.1, "64501")}     # endpoint B's local view

    enricher_endpoint_a = _make_enricher(store, geo_a)
    enricher_endpoint_b = _make_enricher(store, geo_b)

    # Login on endpoint A.
    first = enricher_endpoint_a.enrich("dave", "10.0.0.1", event_ts=0.0, outcome="success")
    # Login on endpoint B, 1 hour later.
    second = enricher_endpoint_b.enrich("dave", "10.0.0.2", event_ts=3600.0, outcome="success")

    assert first["geo_velocity_kmh"] == 0.0    # nothing to compare against yet
    assert second["country_change_i"] == 1     # US -> LU, correctly detected
    assert second["geo_velocity_kmh"] > 900    # correctly flagged as impossible travel
    assert second["asn_novelty_i"] == 1        # dave's first time on ASN 64501


def test_state_store_persists_across_new_instances(tmp_path):
    db_path = str(tmp_path / "user_state.sqlite3")

    store1 = UserStateStore(db_path=db_path)
    us = store1.get("erin")
    us.last_ts = 123.0
    us.last_lat, us.last_lon = 10.0, 20.0
    us.last_country = "FR"
    us.asn_hist.append(("999", 100))
    us.asn_set.add("999")
    store1.save("erin", us)

    # Simulate a manager/container restart: a brand new UserStateStore
    # pointed at the same (bind-mounted) db file.
    store2 = UserStateStore(db_path=db_path)
    us2 = store2.get("erin")

    assert us2.last_ts == 123.0
    assert us2.last_lat == 10.0 and us2.last_lon == 20.0
    assert us2.last_country == "FR"
    assert "999" in us2.asn_set


def test_state_store_creates_db_group_writable(tmp_path):
    import stat

    db_path = str(tmp_path / "user_state.sqlite3")
    UserStateStore(db_path=db_path)

    mode = stat.S_IMODE(os.stat(db_path).st_mode)
    assert mode == 0o660


def test_state_store_ensure_group_writable_tolerates_files_it_does_not_own(tmp_path, monkeypatch):
    db_path = str(tmp_path / "user_state.sqlite3")

    real_chmod = os.chmod

    def fake_chmod(path, mode):
        if path == db_path:
            raise PermissionError("Operation not permitted")
        return real_chmod(path, mode)

    monkeypatch.setattr(os, "chmod", fake_chmod)

    # Must not raise, despite chmod failing for the main db file.
    store = UserStateStore(db_path=db_path)
    us = store.get("someone")
    assert us.last_ts is None


def test_state_store_unknown_user_returns_fresh_state(store):
    us = store.get("nobody-has-logged-in-as-this-user")
    assert us.last_ts is None
    assert us.asn_set == set()
    assert len(us.asn_hist) == 0


def test_enriched_tail_matches_success_decoder_regex(store):
    fields = _make_enricher(
        store, {"1.2.3.4": ("LU", "Luxembourg", "Luxembourg", 49.6, 6.1, "56665")}
    ).enrich("root", "1.2.3.4", event_ts=0.0, outcome="success")

    full_log = "Accepted password for root from 1.2.3.4 port 1066 ssh2" + fields["tail"]

    assert re.match(r"^Accepted", full_log)
    rest = full_log[len("Accepted"):]

    # Mirrors sshd-success-with-radar's <regex> in 0310-ssh.xml.
    pattern = (
        r"^ \S+ for (\S+) from (\S+) port (\S+).*"
        r"RADAR outcome='([^']*)' asn='([^']*)' asn_placeholder_flag='([^']*)' "
        r"country='([^']*)' region='([^']*)' city='([^']*)' "
        r"geo_velocity_kmh='([^']*)' country_change_i='([^']*)' asn_novelty_i='([^']*)'$"
    )
    m = re.match(pattern, rest)
    assert m, f"decoder regex did not match enriched line: {full_log!r}"

    (user, srcip, _srcport, outcome, asn, _asn_ph, country, _region, _city,
     _velocity, _country_change, _asn_novelty) = m.groups()
    assert user == "root"
    assert srcip == "1.2.3.4"
    assert outcome == "success"
    assert asn == "56665"
    assert country == "LU"


def test_enriched_tail_matches_generic_failed_decoder_regex(store):
    fields = _make_enricher(
        store, {"9.9.9.9": ("US", "", "", 1.0, 1.0, "111")}
    ).enrich("root", "9.9.9.9", event_ts=0.0, outcome="failure")

    full_log = "Failed password for root from 9.9.9.9 port 1045 ssh2" + fields["tail"]

    # Mirrors ssh-failed-with-radar's <prematch>/<regex> in 0310-ssh.xml.
    assert re.match(r"^Failed \S+ ", full_log)
    rest = re.sub(r"^Failed \S+ ", "", full_log)
    pattern = (
        r"^for (\S+) from (\S+) port (\d+).*"
        r"\sRADAR outcome='([^']*)' asn='([^']*)' asn_placeholder_flag='([^']*)' "
        r"country='([^']*)' region='([^']*)' city='([^']*)' "
        r"geo_velocity_kmh='([^']*)' country_change_i='([^']*)' asn_novelty_i='([^']*)'$"
    )
    m = re.match(pattern, rest)
    assert m, f"decoder regex did not match enriched line: {full_log!r}"
    assert m.group(4) == "failure"  # outcome


def test_enriched_tail_matches_invalid_user_decoder_regex_with_port(store):
    fields = _make_enricher(
        store, {"192.168.0.1": ("", "", "", None, None, None)}
    ).enrich("linux", "192.168.0.1", event_ts=0.0, outcome="failure")

    full_log = "Invalid user linux from 192.168.0.1 port 54806" + fields["tail"]

    assert re.match(r"^Invalid user", full_log)
    rest = re.sub(r"^Invalid user", "", full_log)
    pattern = (
        r"^ (\S+) from (\S+)(?: port (\d+))?.*"
        r"\sRADAR outcome='([^']*)' asn='([^']*)' asn_placeholder_flag='([^']*)' "
        r"country='([^']*)' region='([^']*)' city='([^']*)' "
        r"geo_velocity_kmh='([^']*)' country_change_i='([^']*)' asn_novelty_i='([^']*)'$"
    )
    m = re.match(pattern, rest)
    assert m, f"decoder regex did not match enriched line: {full_log!r}"
    assert m.group(1) == "linux"
    assert m.group(2) == "192.168.0.1"
    assert m.group(3) == "54806"
    assert m.group(4) == "failure"


def test_enriched_tail_matches_invalid_user_decoder_regex_without_port(store):
    """Older OpenSSH omits the port entirely -- the decoder must still match."""
    fields = _make_enricher(
        store, {"127.0.0.1": ("", "", "", None, None, None)}
    ).enrich("abc", "127.0.0.1", event_ts=0.0, outcome="failure")

    full_log = "Invalid user abc from 127.0.0.1" + fields["tail"]

    rest = re.sub(r"^Invalid user", "", full_log)
    pattern = (
        r"^ (\S+) from (\S+)(?: port (\d+))?.*"
        r"\sRADAR outcome='([^']*)' asn='([^']*)' asn_placeholder_flag='([^']*)' "
        r"country='([^']*)' region='([^']*)' city='([^']*)' "
        r"geo_velocity_kmh='([^']*)' country_change_i='([^']*)' asn_novelty_i='([^']*)'$"
    )
    m = re.match(pattern, rest)
    assert m, f"decoder regex did not match enriched line: {full_log!r}"
    assert m.group(3) is None  # no port captured, and that's fine
    assert m.group(4) == "failure"