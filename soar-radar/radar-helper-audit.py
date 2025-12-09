#!/usr/bin/env python3
import os
import re
import time
import logging
from logging.handlers import WatchedFileHandler
from collections import deque, defaultdict
from math import radians, sin, cos, asin, sqrt
import threading

import maxminddb

# ------------------------------------------------------------
# Paths / constants
# ------------------------------------------------------------

AUTH_LOG = "/var/log/auth.log"
AUDIT_LOG = "/var/log/audit/audit.log"

OUT_AUTH_LOG  = "/var/log/suspicious_login.log"
OUT_AUDIT_LOG = "/var/log/audit_volume.log"

CITY_DB  = "/usr/share/GeoIP/GeoLite2-City.mmdb"
ASN_DB   = "/usr/share/GeoIP/GeoLite2-ASN.mmdb"

DEBUG_LOG = "/var/log/radar-helper-debug.log"

WIN_90D_SEC = 90 * 24 * 3600
VEL_CAP_KMH = 2000.0

# ------------------------------------------------------------
# Debug logger
# ------------------------------------------------------------

def _setup_debug_logger():
    os.makedirs(os.path.dirname(DEBUG_LOG) or "/", exist_ok=True)
    lg = logging.getLogger("radar.debug")
    lg.setLevel(logging.DEBUG)

    if not any(isinstance(h, WatchedFileHandler) and getattr(h, "_radar_path", None) == DEBUG_LOG for h in lg.handlers):
        h = WatchedFileHandler(DEBUG_LOG)
        h.setLevel(logging.DEBUG)
        h.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s [%(threadName)s] %(name)s: %(message)s"
        ))
        h._radar_path = DEBUG_LOG
        lg.addHandler(h)

    lg.propagate = False
    return lg

DEBUG_LOGGER = _setup_debug_logger()
DEBUG_LOGGER.debug("=== radar-helper starting up ===")

# ------------------------------------------------------------
# Common helpers
# ------------------------------------------------------------

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

class UserState:
    __slots__ = ("last_ts","last_lat","last_lon","last_country","asn_hist","asn_set")
    def __init__(self):
        self.last_ts = None
        self.last_lat = None
        self.last_lon = None
        self.last_country = None
        self.asn_hist = deque()
        self.asn_set  = set()

def haversine_km(lat1, lon1, lat2, lon2):
    R = 6371.0088
    p1, l1, p2, l2 = map(radians, (lat1, lon1, lat2, lon2))
    dp, dl = p2 - p1, l2 - l1
    a = sin(dp/2)**2 + cos(p1)*cos(p2)*sin(dl/2)**2
    return 2 * R * asin(sqrt(a))

# ------------------------------------------------------------
# Core base class
# ------------------------------------------------------------

class BaseLogWatcher(threading.Thread):
    """
    Abstract base class for 'tail -F'-style log processors.
    Subclasses must implement handle_line().
    """
    def __init__(self, in_path: str, out_path: str, logger_name: str):
        super().__init__(daemon=True)
        self.in_path = in_path
        self.out_path = out_path
        self.logger = self._setup_logger(logger_name, out_path)
        self.debug = DEBUG_LOGGER
        self._stop_evt = threading.Event()
        self.debug.debug(
            "[%s] initialized: in_path=%s out_path=%s",
            self.__class__.__name__, self.in_path, self.out_path
        )

    def _setup_logger(self, name: str, out_path: str):
        os.makedirs(os.path.dirname(out_path) or "/", exist_ok=True)
        lg = logging.getLogger(name)
        lg.setLevel(logging.INFO)
        if not any(
            isinstance(h, WatchedFileHandler)
            and getattr(h, "_radar_path", None) == out_path
            for h in lg.handlers
        ):
            h = WatchedFileHandler(out_path)
            h.setFormatter(logging.Formatter("%(message)s"))
            h._radar_path = out_path
            lg.addHandler(h)
        return lg

    def stop(self):
        self.debug.debug("[%s] stop() called", self.__class__.__name__)
        self._stop_evt.set()

    def tail_follow(self):
        """Tail -F style follower with inode rotation handling."""
        f = None
        ino = None
        self.debug.debug(
            "[%s] tail_follow starting on %s",
            self.__class__.__name__, self.in_path
        )
        while not self._stop_evt.is_set():
            try:
                if f is None:
                    self.debug.debug(
                        "[%s] opening %s for reading",
                        self.__class__.__name__, self.in_path
                    )
                    f = open(self.in_path, "r")
                    f.seek(0, os.SEEK_END)
                    ino = os.fstat(f.fileno()).st_ino
                    self.debug.debug(
                        "[%s] opened %s (ino=%s), seeked to end",
                        self.__class__.__name__, self.in_path, ino
                    )

                line = f.readline()
                if not line:
                    # Check rotation
                    try:
                        st = os.stat(self.in_path)
                        if st.st_ino != ino:
                            self.debug.debug(
                                "[%s] detected rotation for %s (old ino=%s, new ino=%s)",
                                self.__class__.__name__, self.in_path, ino, st.st_ino
                            )
                            nf = open(self.in_path, "r")
                            f.close()
                            f = nf
                            ino = os.fstat(f.fileno()).st_ino
                    except FileNotFoundError:
                        self.debug.debug(
                            "[%s] %s not found (FileNotFoundError), will retry",
                            self.__class__.__name__, self.in_path
                        )
                    time.sleep(0.2)
                    continue

                stripped = line.rstrip("\n")
                self.debug.debug(
                    "[%s] READ line from %s: %r",
                    self.__class__.__name__, self.in_path, stripped
                )
                yield stripped

            except Exception as e:
                self.debug.error(
                    "[%s] tail_follow error on %s: %s",
                    self.__class__.__name__, self.in_path, e,
                    exc_info=True
                )
                time.sleep(0.5)

        if f is not None:
            self.debug.debug(
                "[%s] closing file %s",
                self.__class__.__name__, self.in_path
            )
            try:
                f.close()
            except Exception:
                pass

    def run(self):
        self.debug.debug("[%s] thread started", self.__class__.__name__)
        for line in self.tail_follow():
            if self._stop_evt.is_set():
                self.debug.debug("[%s] stop event set, breaking loop", self.__class__.__name__)
                break
            try:
                self.handle_line(line)
            except Exception:
                self.debug.error(
                    "[%s] Error while processing line: %r",
                    self.__class__.__name__, line,
                    exc_info=True
                )
                self.logger.exception("Error while processing line")

        self.debug.debug("[%s] thread exiting", self.__class__.__name__)

    def handle_line(self, line: str):
        """Override in subclasses with actual parsing/enrichment."""
        raise NotImplementedError

# ------------------------------------------------------------
# Auth log watcher
# ------------------------------------------------------------

class AuthLogWatcher(BaseLogWatcher):
    def __init__(self, in_path: str = AUTH_LOG, out_path: str = OUT_AUTH_LOG):
        DEBUG_LOGGER.debug(
            "[AuthLogWatcher.__init__] in_path=%s out_path=%s",
            in_path, out_path
        )
        super().__init__(in_path, out_path, logger_name="radar.auth")
        try:
            DEBUG_LOGGER.debug(
                "[AuthLogWatcher.__init__] opening MaxMind DBs: %s, %s",
                CITY_DB, ASN_DB
            )
            self.city_reader = maxminddb.open_database(CITY_DB)
            self.asn_reader  = maxminddb.open_database(ASN_DB)
            DEBUG_LOGGER.debug("[AuthLogWatcher.__init__] MaxMind DBs opened successfully")
        except FileNotFoundError as e:
            DEBUG_LOGGER.error("[AuthLogWatcher.__init__] Missing MaxMind DB file: %s", e, exc_info=True)
            raise SystemExit(f"[FATAL] Missing MaxMind DB file: {e}")
        except Exception as e:
            DEBUG_LOGGER.error("[AuthLogWatcher.__init__] Error opening MaxMind DBs: %s", e, exc_info=True)
            raise

        self.users = defaultdict(UserState)
        DEBUG_LOGGER.debug("[AuthLogWatcher.__init__] users state dict initialized")

    def drop_old(self, us: UserState, now_sec: int):
        """Keep ASN history to 90 days for novelty calc."""
        DEBUG_LOGGER.debug("[AuthLogWatcher.drop_old] now_sec=%s hist_len=%d", now_sec, len(us.asn_hist))
        while us.asn_hist and us.asn_hist[0][1] < now_sec - WIN_90D_SEC:
            old_asn, _ = us.asn_hist.popleft()
            DEBUG_LOGGER.debug("[AuthLogWatcher.drop_old] popped old ASN=%s", old_asn)
            if all(a != old_asn for a,_ in us.asn_hist):
                us.asn_set.discard(old_asn)
                DEBUG_LOGGER.debug("[AuthLogWatcher.drop_old] removed ASN from set=%s", old_asn)

    def geo_lookup(self, ip):
        """Return (country, region, city, lat, lon, asn). Empty strings if missing."""
        DEBUG_LOGGER.debug("[AuthLogWatcher.geo_lookup] ip=%s", ip)
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
            DEBUG_LOGGER.debug(
                "[AuthLogWatcher.geo_lookup] city result: country=%s region=%s city=%s lat=%s lon=%s",
                country, region, city, lat, lon
            )
        except Exception as e:
            DEBUG_LOGGER.error("[AuthLogWatcher.geo_lookup] city lookup error: %s", e, exc_info=True)
        try:
            a = self.asn_reader.get(ip) or {}
            asn = str(a.get("autonomous_system_number") or "")
            DEBUG_LOGGER.debug("[AuthLogWatcher.geo_lookup] ASN result: %s", asn)
        except Exception as e:
            DEBUG_LOGGER.error("[AuthLogWatcher.geo_lookup] ASN lookup error: %s", e, exc_info=True)
        return country, region, city, lat, lon, asn

    @staticmethod
    def classify_outcome(msg_part: str) -> str:
        if "Accepted " in msg_part: return "success"
        if "Failed "   in msg_part: return "failure"
        return "info"

    def handle_line(self, line: str):
        DEBUG_LOGGER.debug("[AuthLogWatcher.handle_line] raw line=%r", line)

        mhead = RX_HEAD.match(line)
        if not mhead:
            DEBUG_LOGGER.debug("[AuthLogWatcher.handle_line] RX_HEAD no match, skipping line")
            return

        msg_part = mhead.group("msg")
        DEBUG_LOGGER.debug("[AuthLogWatcher.handle_line] msg_part=%r", msg_part)

        m = RX_ACCEPT.search(msg_part) or RX_FAILED.search(msg_part)
        if not m:
            DEBUG_LOGGER.debug("[AuthLogWatcher.handle_line] no ACCEPT/FAILED match, skipping line")
            return

        user = m.group("user")
        ip   = m.group("srcip")
        port = m.group("port")
        DEBUG_LOGGER.debug(
            "[AuthLogWatcher.handle_line] parsed: user=%s ip=%s port=%s",
            user, ip, port
        )

        now  = time.time()
        now_i = int(now)

        country, region, city, lat, lon, asn = self.geo_lookup(ip)

        us = self.users[user]
        self.drop_old(us, now_i)

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
            DEBUG_LOGGER.debug(
                "[AuthLogWatcher.handle_line] geo calc: dist_km=%s dt_h=%s vel=%s",
                dist_km, dt_h, geo_velocity_kmh
            )

        if us.last_country is not None and country and country != us.last_country:
            country_change_i = 1
            DEBUG_LOGGER.debug(
                "[AuthLogWatcher.handle_line] country change: %s -> %s",
                us.last_country, country
            )

        asn_novelty_i = 0
        asn_placeholder_flag = "false"
        if asn:
            if asn not in us.asn_set:
                asn_novelty_i = 1
                us.asn_set.add(asn)
                DEBUG_LOGGER.debug(
                    "[AuthLogWatcher.handle_line] new ASN seen for user=%s: %s",
                    user, asn
                )
            us.asn_hist.append((asn, now_i))
        else:
            asn_placeholder_flag = "true"
            DEBUG_LOGGER.debug(
                "[AuthLogWatcher.handle_line] no ASN for ip=%s (placeholder=true)",
                ip
            )

        us.last_ts = now
        if lat is not None and lon is not None:
            us.last_lat, us.last_lon = lat, lon
        if country:
            us.last_country = country

        outcome = self.classify_outcome(msg_part)
        DEBUG_LOGGER.debug(
            "[AuthLogWatcher.handle_line] outcome=%s user=%s ip=%s",
            outcome, user, ip
        )

        radar_tail = (
            f" RADAR outcome='{outcome}' asn='{asn}' asn_placeholder_flag='{asn_placeholder_flag}' "
            f"country='{country}' region='{region}' city='{city}' "
            f"geo_velocity_kmh='{geo_velocity_kmh:.3f}' country_change_i='{country_change_i}' "
            f"asn_novelty_i='{asn_novelty_i}'"
        )

        out_line = f"{line}{radar_tail}"
        DEBUG_LOGGER.debug(
            "[AuthLogWatcher.handle_line] writing enriched line to %s: %r",
            self.out_path, out_line
        )
        self.logger.info(out_line)

# ------------------------------------------------------------
# Auditd watcher
# ------------------------------------------------------------

RX_AUDIT_SYSCALL = re.compile(
    r'^type=SYSCALL msg=audit\((?P<ts>[^)]+)\): (?P<rest>.*)$'
)

class AuditVolumeWatcher(BaseLogWatcher):
    """
    For each SYSCALL record extract:
      - uid
      - exe
      - syscall
      - exit (treated as bytes transferred, if >0)
    and write an enriched line.
    """
    def __init__(self, in_path: str = AUDIT_LOG, out_path: str = OUT_AUDIT_LOG):
        DEBUG_LOGGER.debug(
            "[AuditVolumeWatcher.__init__] in_path=%s out_path=%s",
            in_path, out_path
        )
        super().__init__(in_path, out_path, logger_name="radar.audit")

    @staticmethod
    def _parse_kv(rest: str):
        """
        Parse key=value tokens from the 'rest' of an audit message.
        """
        result = {}
        for token in rest.split():
            if "=" not in token:
                continue
            k, v = token.split("=", 1)
            if v.startswith('"') and v.endswith('"'):
                v = v[1:-1]
            result[k] = v
        return result

    def handle_line(self, line: str):
        DEBUG_LOGGER.debug("[AuditVolumeWatcher.handle_line] raw line=%r", line)

        m = RX_AUDIT_SYSCALL.match(line)
        if not m:
            DEBUG_LOGGER.debug("[AuditVolumeWatcher.handle_line] no SYSCALL match, skipping line")
            return

        rest = m.group("rest")
        DEBUG_LOGGER.debug("[AuditVolumeWatcher.handle_line] rest=%r", rest)
        kv = self._parse_kv(rest)

        uid     = kv.get("uid", "?")
        exe     = kv.get("exe", "?")
        syscall = kv.get("syscall", "?")
        exit_v  = kv.get("exit", "0")

        try:
            bytes_xfer = int(exit_v)
        except ValueError:
            bytes_xfer = 0

        direction = "unknown"
        if syscall in {"0", "3"}:      # read / readv
            direction = "read"
        elif syscall in {"1", "4"}:    # write / writev
            direction = "write"

        DEBUG_LOGGER.debug(
            "[AuditVolumeWatcher.handle_line] parsed: uid=%s exe=%s syscall=%s exit=%s bytes_xfer=%s dir=%s",
            uid, exe, syscall, exit_v, bytes_xfer, direction
        )

        radar_tail = (
            f" RADAR bytes='{bytes_xfer}' direction='{direction}' uid='{uid}' "
            f"exe='{exe}' syscall='{syscall}'"
        )

        out_line = f"{line}{radar_tail}"
        DEBUG_LOGGER.debug(
            "[AuditVolumeWatcher.handle_line] writing enriched line to %s: %r",
            self.out_path, out_line
        )
        self.logger.info(out_line)

# ------------------------------------------------------------
# main
# ------------------------------------------------------------

def main():
    DEBUG_LOGGER.debug("[main] creating watchers for AUTH_LOG=%s, AUDIT_LOG=%s", AUTH_LOG, AUDIT_LOG)

    auth_watcher  = AuthLogWatcher()
    audit_watcher = AuditVolumeWatcher()

    watchers = [auth_watcher, audit_watcher]

    for w in watchers:
        DEBUG_LOGGER.debug("[main] starting watcher thread: %s", w.__class__.__name__)
        w.start()

    try:
        DEBUG_LOGGER.debug("[main] entering main loop")
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        DEBUG_LOGGER.debug("[main] KeyboardInterrupt received, stopping watchers")
    except Exception as e:
        DEBUG_LOGGER.error("[main] unexpected exception in main loop: %s", e, exc_info=True)
    finally:
        for w in watchers:
            w.stop()
        for w in watchers:
            DEBUG_LOGGER.debug("[main] joining watcher thread: %s", w.__class__.__name__)
            w.join(timeout=5.0)
        DEBUG_LOGGER.debug("[main] all watcher threads joined, exiting")

if __name__ == "__main__":
    main()
