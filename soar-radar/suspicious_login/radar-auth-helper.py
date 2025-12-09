#!/usr/bin/env python3
import os
import re
import time
import math
import logging
from logging.handlers import WatchedFileHandler
from collections import deque, defaultdict
from datetime import datetime
import maxminddb

AUTH_LOG = "/var/log/auth.log"
OUT_LOG  = "/var/log/suspicious_login.log"

CITY_DB  = "/usr/share/GeoIP/GeoLite2-City.mmdb"
ASN_DB   = "/usr/share/GeoIP/GeoLite2-ASN.mmdb"

WIN_90D_SEC = 90 * 24 * 3600
VEL_CAP_KMH= 2000.0

RX_HEAD = re.compile(
    r'^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<prog>sshd|sudo)(?:\[\d+\])?:'
    r'(?P<msg>.*)$' 
)

RX_ACCEPT = re.compile(
    r" Accepted \S+ for (?P<user>\S+) from (?P<srcip>\S+) port (?P<port>\d+)"
)
RX_FAILED = re.compile(
    r" Failed \S+ for (?:(?:invalid|illegal) user )?(?P<user>\S+) from (?P<srcip>\S+) port (?P<port>\d+)"
)

def haversine_km(lat1, lon1, lat2, lon2):
    R = 6371.0088
    from math import radians, sin, cos, asin, sqrt
    p1, l1, p2, l2 = map(radians, (lat1, lon1, lat2, lon2))
    dp, dl = p2 - p1, l2 - l1
    a = sin(dp/2)**2 + cos(p1)*cos(p2)*sin(dl/2)**2
    return 2 * R * asin(sqrt(a))

class UserState:
    __slots__ = ("last_ts","last_lat","last_lon","last_country","asn_hist","asn_set")
    def __init__(self):
        self.last_ts = None
        self.last_lat = None
        self.last_lon = None
        self.last_country = None
        self.asn_hist = deque()
        self.asn_set  = set()

USERS = defaultdict(UserState)

def drop_old(us: UserState, now_sec: int):
    """Keep ASN history to 90 days for novelty calc."""
    while us.asn_hist and us.asn_hist[0][1] < now_sec - WIN_90D_SEC:
        old_asn, _ = us.asn_hist.popleft()
        if all(a != old_asn for a,_ in us.asn_hist):
            us.asn_set.discard(old_asn)

def geo_lookup(ip, city_reader, asn_reader):
    """Return (country, region, city, lat, lon, asn). Empty strings if missing."""
    country = region = city = ""
    lat = lon = None
    asn = ""
    try:
        c = city_reader.get(ip) or {}
        country = (c.get("country") or {}).get("iso_code") or ""
        subs = c.get("subdivisions") or []
        if subs and isinstance(subs, list):
            region = (subs[0].get("names") or {}).get("en") or ""
        city = ((c.get("city") or {}).get("names") or {}).get("en") or ""
        loc = c.get("location") or {}
        lat = loc.get("latitude")
        lon = loc.get("longitude")
    except Exception:
        pass
    try:
        a = asn_reader.get(ip) or {}
        asn = str(a.get("autonomous_system_number") or "")
    except Exception:
        pass
    return country, region, city, lat, lon, asn

def classify_outcome(msg_part: str) -> str:
    if "Accepted " in msg_part: return "success"
    if "Failed "   in msg_part: return "failure"
    return "info"

def tail_follow(path):
    """Tail -F style follower with inode rotation handling."""
    f = None; ino = None
    while True:
        try:
            if f is None:
                f = open(path, "r")
                f.seek(0, os.SEEK_END)
                ino = os.fstat(f.fileno()).st_ino
            line = f.readline()
            if not line:
                try:
                    if os.stat(path).st_ino != ino:
                        nf = open(path, "r")
                        f.close()
                        f = nf
                        ino = os.fstat(f.fileno()).st_ino
                except FileNotFoundError:
                    pass
                time.sleep(0.2)
                continue
            yield line.rstrip("\n")
        except Exception:
            time.sleep(0.5)

def setup_logger():
    lg = logging.getLogger("radar")
    lg.setLevel(logging.INFO)
    h = WatchedFileHandler(OUT_LOG)
    h.setFormatter(logging.Formatter("%(message)s"))
    lg.addHandler(h)
    return lg

def main():
    os.makedirs(os.path.dirname(OUT_LOG) or "/", exist_ok=True)

    log = setup_logger()
    try:
        city_reader = maxminddb.open_database(CITY_DB)
        asn_reader  = maxminddb.open_database(ASN_DB)
    except FileNotFoundError as e:
        raise SystemExit(f"[FATAL] Missing MaxMind DB file: {e}")

    for line in tail_follow(AUTH_LOG):
        mhead = RX_HEAD.match(line)
        if not mhead:
            continue

        ts_orig   = mhead.group("ts")
        host_orig = mhead.group("host")
        prog_orig = mhead.group("prog")
        msg_part  = mhead.group("msg")  

        m = RX_ACCEPT.search(msg_part) or RX_FAILED.search(msg_part)
        if not m:
            continue

        user = m.group("user")
        ip   = m.group("srcip")
        now  = time.time()
        now_i = int(now)

        country, region, city, lat, lon, asn = geo_lookup(ip, city_reader, asn_reader)

        us = USERS[user]
        drop_old(us, now_i)

        geo_velocity_kmh = 0.0
        country_change_i = 0

        if (
            us.last_ts is not None and
            us.last_lat is not None and us.last_lon is not None and
            lat is not None and lon is not None
        ):
            dt_h = max((now - us.last_ts) / 3600.0, 1e-6)
            dist_km = haversine_km(us.last_lat, us.last_lon, lat, lon)
            geo_velocity_kmh = min(dist_km / dt_h, VEL_CAP_KMH)

        if us.last_country is not None and country and country != us.last_country:
            country_change_i = 1

        asn_novelty_i = 0
        asn_placeholder_flag = "false"
        if asn:
            if asn not in us.asn_set:
                asn_novelty_i = 1
                us.asn_set.add(asn)
            us.asn_hist.append((asn, now_i))
        else:
            asn_placeholder_flag = "true"

        us.last_ts = now
        if lat is not None and lon is not None:
            us.last_lat, us.last_lon = lat, lon
        if country:
            us.last_country = country

        outcome = classify_outcome(msg_part)

        radar_tail = (
            f" RADAR outcome='{outcome}' asn='{asn}' asn_placeholder_flag='{asn_placeholder_flag}' "
            f"country='{country}' region='{region}' city='{city}' "
            f"geo_velocity_kmh='{geo_velocity_kmh:.3f}' country_change_i='{country_change_i}' "
            f"asn_novelty_i='{asn_novelty_i}'"
        )

        msg_body = msg_part.lstrip()
        out_line = f"{line}{radar_tail}"
        log.info(out_line)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass