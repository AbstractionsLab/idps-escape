#!/usr/bin/env python3
import os
import re
import time
import logging
from logging.handlers import WatchedFileHandler
from collections import deque, defaultdict
from math import radians, sin, cos, asin, sqrt
import threading
from datetime import datetime, timezone

import maxminddb

# ------------------------------------------------------------
# Paths / constants
# ------------------------------------------------------------

DEBUG_LOG = "/var/log/radar-helper-debug.log" ## /var/log/

_SYSLOG_TS_RE = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})$")
_MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}


class RadarLogger:
    def __init__(self, debug_path: str):
        self.debug_path = debug_path
        self._debug_logger = self._build_debug_logger()

    def _build_debug_logger(self):
        os.makedirs(os.path.dirname(self.debug_path) or "/", exist_ok=True)
        lg = logging.getLogger("radar.debug")
        lg.setLevel(logging.DEBUG)
        if not any(isinstance(h, WatchedFileHandler) and getattr(h, "_radar_path", None) == self.debug_path for h in lg.handlers):
            h = WatchedFileHandler(self.debug_path)
            h.setLevel(logging.DEBUG)
            h.setFormatter(logging.Formatter(
                "%(asctime)s %(levelname)s [%(threadName)s] %(name)s: %(message)s"
            ))
            h._radar_path = self.debug_path
            lg.addHandler(h)
        lg.propagate = False
        return lg

    @staticmethod
    def build_out_logger(name: str, out_path: str):
        os.makedirs(os.path.dirname(out_path) or "/", exist_ok=True)
        lg = logging.getLogger(name)
        lg.setLevel(logging.INFO)
        if not any(isinstance(h, WatchedFileHandler) and getattr(h, "_radar_path", None) == out_path for h in lg.handlers):
            h = WatchedFileHandler(out_path)
            h.setFormatter(logging.Formatter("%(message)s"))
            h._radar_path = out_path
            lg.addHandler(h)
        lg.propagate = False
        return lg

    @property
    def debug(self):
        return self._debug_logger


RADAR_LOG = RadarLogger(DEBUG_LOG)
RADAR_LOG.debug.debug("=== radar-helper starting up ===")


def parse_event_ts(ts_str: str) -> float:
    if "T" in ts_str and (ts_str.endswith("Z") or ("+" in ts_str[-6:] or "-" in ts_str[-6:])):
        try:
            return datetime.fromisoformat(ts_str).timestamp()
        except Exception:
            pass

    m = _SYSLOG_TS_RE.match(ts_str)
    if m:
        mon = _MONTHS.get(m.group("mon"), 1)
        day = int(m.group("day"))
        h = int(m.group("h"))
        mi = int(m.group("m"))
        s = int(m.group("s"))
        year = datetime.now().year
        local_tz = datetime.now().astimezone().tzinfo or timezone.utc
        return datetime(year, mon, day, h, mi, s, tzinfo=local_tz).timestamp()

    return time.time()


class UserState:
    __slots__ = ("last_ts", "last_lat", "last_lon", "last_country", "asn_hist", "asn_set")

    def __init__(self):
        self.last_ts = None
        self.last_lat = None
        self.last_lon = None
        self.last_country = None
        self.asn_hist = deque()
        self.asn_set = set()

# ------------------------------------------------------------
# Core base class
# ------------------------------------------------------------

class BaseLogWatcher(threading.Thread):
    def __init__(self, in_path: str, out_path: str, logger_name: str, radar_logger: RadarLogger):
        super().__init__(daemon=True)
        self.in_path = in_path
        self.out_path = out_path
        self.logger = radar_logger.build_out_logger(logger_name, out_path)
        self.debug = radar_logger.debug
        self._stop_evt = threading.Event()

    def stop(self):
        self._stop_evt.set()

    def tail_follow(self):
        f = None
        ino = None
        while not self._stop_evt.is_set():
            try:
                if f is None:
                    f = open(self.in_path, "r")
                    f.seek(0, os.SEEK_END)
                    ino = os.fstat(f.fileno()).st_ino

                line = f.readline()
                if not line:
                    try:
                        st = os.stat(self.in_path)
                        if st.st_ino != ino:
                            nf = open(self.in_path, "r")
                            f.close()
                            f = nf
                            ino = os.fstat(f.fileno()).st_ino
                    except FileNotFoundError:
                        pass
                    time.sleep(0.2)
                    continue

                yield line.rstrip("\n")
            except Exception as e:
                self.debug.error("[%s] tail_follow error on %s: %s", self.__class__.__name__, self.in_path, e, exc_info=True)
                time.sleep(0.5)

        if f is not None:
            try:
                f.close()
            except Exception:
                pass

    def run(self):
        for line in self.tail_follow():
            if self._stop_evt.is_set():
                break
            try:
                self.handle_line(line)
            except Exception:
                self.debug.error("[%s] Error while processing line: %r", self.__class__.__name__, line, exc_info=True)
                self.logger.exception("Error while processing line")

    def handle_line(self, line: str):
        raise NotImplementedError

# ------------------------------------------------------------
# Auth log watcher
# ------------------------------------------------------------

class AuthLogWatcher(BaseLogWatcher):
    AUTH_LOG = "/var/log/auth.log" # /var/log/

    OUT_AUTH_LOG  = "/var/log/suspicious_login.log" # /var/log/
    CITY_DB  = "/usr/share/GeoIP/GeoLite2-City.mmdb"
    ASN_DB   = "/usr/share/GeoIP/GeoLite2-ASN.mmdb"
    WIN_90D_SEC = 90 * 24 * 3600
    DT_EPS_H = 1e-9

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

    def __init__(self, radar_logger: RadarLogger, in_path: str = None, out_path: str = None):
        super().__init__(
            in_path or self.AUTH_LOG,
            out_path or self.OUT_AUTH_LOG,
            logger_name="radar.auth",
            radar_logger=radar_logger,
        )
        try:
            self.city_reader = maxminddb.open_database(self.CITY_DB)
            self.asn_reader = maxminddb.open_database(self.ASN_DB)
        except FileNotFoundError as e:
            raise SystemExit(f"[FATAL] Missing MaxMind DB file: {e}")
        self.users = defaultdict(UserState)

    @staticmethod
    def haversine_km(lat1, lon1, lat2, lon2):
        r = 6371.0088
        p1, l1, p2, l2 = map(radians, (lat1, lon1, lat2, lon2))
        dp, dl = p2 - p1, l2 - l1
        a = sin(dp / 2) ** 2 + cos(p1) * cos(p2) * sin(dl / 2) ** 2
        return 2 * r * asin(sqrt(a))

    def drop_old(self, us: UserState, now_sec: int):
        cutoff = now_sec - self.WIN_90D_SEC
        hist = us.asn_hist
        aset = us.asn_set
        while hist and hist[0][1] < cutoff:
            old_asn, _ = hist.popleft()
            if all(a != old_asn for a, _ in hist):
                aset.discard(old_asn)

    def geo_lookup(self, ip):
        country = region = city = ""
        lat = lon = None
        asn = ""

        try:
            c = self.city_reader.get(ip) or {}
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
            a = self.asn_reader.get(ip) or {}
            asn = str(a.get("autonomous_system_number") or "")
        except Exception:
            pass

        return country, region, city, lat, lon, asn

    @staticmethod
    def classify_outcome(msg_part: str) -> str:
        if "Accepted " in msg_part:
            return "success"
        if "Failed " in msg_part:
            return "failure"
        return "info"

    def handle_line(self, line: str):
        mhead = self.RX_HEAD.match(line)
        if not mhead:
            return

        event_ts = parse_event_ts(mhead.group("ts"))
        event_ts_i = int(event_ts)

        msg_part = mhead.group("msg")
        m = self.RX_ACCEPT.search(msg_part) or self.RX_FAILED.search(msg_part)
        if not m:
            return

        user = m.group("user")
        ip = m.group("srcip")

        country, region, city, lat, lon, asn = self.geo_lookup(ip)
        us = self.users[user]
        self.drop_old(us, event_ts_i)

        geo_velocity_kmh = 0.0
        if us.last_ts is not None and us.last_lat is not None and us.last_lon is not None and lat is not None and lon is not None:
            dt_h = (event_ts - us.last_ts) / 3600.0
            if abs(dt_h) < self.DT_EPS_H:
                dt_h = self.DT_EPS_H
            else:
                dt_h = abs(dt_h)
            geo_velocity_kmh = self.haversine_km(us.last_lat, us.last_lon, lat, lon) / dt_h

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

        outcome = self.classify_outcome(msg_part)

        radar_tail = (
            f" RADAR outcome='{outcome}' asn='{asn}' asn_placeholder_flag='{asn_placeholder_flag}' "
            f"country='{country}' region='{region}' city='{city}' "
            f"geo_velocity_kmh='{geo_velocity_kmh:.3f}' country_change_i='{country_change_i}' "
            f"asn_novelty_i='{asn_novelty_i}'"
        )
        self.logger.info(f"{line}{radar_tail}")


class AuditLogWatcher(BaseLogWatcher):
    AUDIT_LOG = "/var/log/audit/audit.log"
    OUT_AUDIT_LOG = "/var/log/audit_volume.log"

    def __init__(self, radar_logger: RadarLogger, in_path: str = None, out_path: str = None):
        super().__init__(
            in_path or self.AUDIT_LOG,
            out_path or self.OUT_AUDIT_LOG,
            logger_name="radar.audit",
            radar_logger=radar_logger,
        )

    def handle_line(self, line: str):
        return

# ------------------------------------------------------------
# main
# ------------------------------------------------------------

def main():
    auth_watcher = AuthLogWatcher(RADAR_LOG)
    auth_watcher.start()
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        auth_watcher.stop()
        auth_watcher.join(timeout=5.0)


if __name__ == "__main__":
    main()
