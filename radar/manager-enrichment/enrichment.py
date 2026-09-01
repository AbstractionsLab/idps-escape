"""
Core enrichment logic.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from math import asin, cos, radians, sin, sqrt

from geoip import geo_lookup
from state_store import UserStateStore

WIN_90D_SEC = 90 * 24 * 3600
DT_EPS_H = 1e-9

_SYSLOG_TS_RE = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})$")
_MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
           "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}

RX_HEAD = re.compile(
    r"^(?P<ts>("
    r"\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}"
    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{2}:\d{2}"
    r"))\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<prog>sshd(?:-session)?|sudo)(?:\[\d+\])?:\s*"
    r"(?P<msg>.*)$"
)
RX_ACCEPT = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<srcip>\S+) port (?P<port>\d+)")
RX_FAILED = re.compile(r"Failed \S+ for (?:(?:invalid|illegal) user )?(?P<user>\S+) from (?P<srcip>\S+) port (?P<port>\d+)")


def parse_event_ts(ts_str: str) -> float:
    if "T" in ts_str and (ts_str.endswith("Z") or "+" in ts_str[-6:] or "-" in ts_str[-6:]):
        try:
            return datetime.fromisoformat(ts_str).timestamp()
        except Exception:
            pass
    m = _SYSLOG_TS_RE.match(ts_str)
    if m:
        mon = _MONTHS.get(m.group("mon"), 1)
        day, h, mi, s = int(m.group("day")), int(m.group("h")), int(m.group("m")), int(m.group("s"))
        local_tz = datetime.now().astimezone().tzinfo or timezone.utc
        return datetime(datetime.now().year, mon, day, h, mi, s, tzinfo=local_tz).timestamp()
    return datetime.now(timezone.utc).timestamp()


def parse_auth_line(full_log: str):
    """(event_ts, user, srcip, outcome) parsed from full_log directly, or None -- independent of Wazuh's decoded fields, which 0310-ssh.xml only populates once a RADAR tail is already present."""
    mhead = RX_HEAD.match(full_log)
    if not mhead:
        return None
    msg = mhead.group("msg")
    m = RX_ACCEPT.search(msg)
    outcome = "success"
    if not m:
        m = RX_FAILED.search(msg)
        outcome = "failure"
    if not m:
        return None
    return parse_event_ts(mhead.group("ts")), m.group("user"), m.group("srcip"), outcome


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0088
    p1, l1, p2, l2 = map(radians, (lat1, lon1, lat2, lon2))
    dp, dl = p2 - p1, l2 - l1
    a = sin(dp / 2) ** 2 + cos(p1) * cos(p2) * sin(dl / 2) ** 2
    return 2 * r * asin(sqrt(a))


def drop_old(asn_hist, asn_set, now_sec: int) -> None:
    """Mutates asn_hist/asn_set in place."""
    cutoff = now_sec - WIN_90D_SEC
    while asn_hist and asn_hist[0][1] < cutoff:
        old_asn, _ = asn_hist.popleft()
        if all(a != old_asn for a, _ in asn_hist):
            asn_set.discard(old_asn)


def format_radar_tail(fields: dict) -> str:
    return (
        f" RADAR outcome='{fields['outcome']}' asn='{fields['asn']}' "
        f"asn_placeholder_flag='{fields['asn_placeholder_flag']}' "
        f"country='{fields['country']}' region='{fields['region']}' city='{fields['city']}' "
        f"geo_velocity_kmh='{fields['geo_velocity_kmh']:.3f}' "
        f"country_change_i='{fields['country_change_i']}' "
        f"asn_novelty_i='{fields['asn_novelty_i']}'"
    )


class RadarEnricher:
    def __init__(self, store: UserStateStore, city_reader, asn_reader):
        self.store = store
        self.city_reader = city_reader
        self.asn_reader = asn_reader

    def enrich(self, username: str, ip: str, event_ts: float, outcome: str) -> dict:
        event_ts_i = int(event_ts)
        country, region, city, lat, lon, asn = geo_lookup(self.city_reader, self.asn_reader, ip)

        us = self.store.get(username)
        drop_old(us.asn_hist, us.asn_set, event_ts_i)

        geo_velocity_kmh = 0.0
        if (
            us.last_ts is not None
            and us.last_lat is not None
            and us.last_lon is not None
            and lat is not None
            and lon is not None
        ):
            dt_h = (event_ts - us.last_ts) / 3600.0
            dt_h = abs(dt_h) if abs(dt_h) >= DT_EPS_H else DT_EPS_H
            geo_velocity_kmh = haversine_km(us.last_lat, us.last_lon, lat, lon) / dt_h

        country_change_i = 1 if (us.last_country is not None and country and country != us.last_country) else 0

        asn_novelty_i = 0
        asn_placeholder_flag = "false"
        if asn:
            if asn not in us.asn_set:
                asn_novelty_i = 1
                us.asn_set.add(asn)
            us.asn_hist.append((asn, event_ts_i))
        else:
            asn_placeholder_flag = "true"

        us.last_ts = event_ts
        if lat is not None and lon is not None:
            us.last_lat, us.last_lon = lat, lon
        if country:
            us.last_country = country

        self.store.save(username, us)

        fields = {
            "outcome": outcome,
            "asn": asn,
            "asn_placeholder_flag": asn_placeholder_flag,
            "country": country,
            "region": region,
            "city": city,
            "geo_velocity_kmh": geo_velocity_kmh,
            "country_change_i": country_change_i,
            "asn_novelty_i": asn_novelty_i,
        }
        fields["tail"] = format_radar_tail(fields)
        return fields