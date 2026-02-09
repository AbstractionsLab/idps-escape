#!/usr/bin/env python3
import os
import json
import math
import hashlib
import random
import time
import requests
import subprocess
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from setup.config_loader import AppConfig  # your existing loader

# ----------- Constants / Tunables -----------
WIN_90D = 90 * 24 * 3600
VEL_CAP = 2000.0
IMPOSSIBLE_KMH = 900.0

WAZUH_LOCALFILE = os.getenv("WAZUH_LOCALFILE", "/var/log/suspicious_login.json")
WAZUH_AGENT_CONTAINER = os.getenv("WAZUH_AGENT_CONTAINER", "agent.suspicious")

# For synthetic geo/ASN enrichment used by both real and synthetic events
COUNTRY_CENTROIDS = {
    "PL": (51.9194, 19.1451),
    "US": (39.8283, -98.5795),
    "AU": (-25.2744, 133.7751),
    "GB": (55.3781, -3.4360),
    "BR": (-14.2350, -51.9253),
    "JP": (36.2048, 138.2529),
    "CA": (56.1304, -106.3468),
    "FR": (46.2276, 2.2137),
}

COUNTRY_IP = {
    "PL": "213.180.193.3",
    "US": "8.8.8.8",
    "AU": "139.130.4.5",
    "GB": "81.2.69.142",
    "BR": "200.160.2.3",
    "JP": "210.130.1.1",
    "CA": "142.250.72.14",
    "FR": "51.15.0.1",
}

DEV_VARIANTS = [
    ("Windows 11", "Chrome 118", "desktop"),
    ("Android 13", "Chrome Mobile 116", "mobile"),
    ("macOS 13", "Safari 16", "desktop"),
]
ASN_VARIANTS = ["15169", "4808", "1221", "20940", "7303"]


# ------------- Small helpers -------------
def country_centroid(code: str):
    return COUNTRY_CENTROIDS.get(code.upper())


def haversine_km(p1, l1, p2, l2):
    R = 6371.0088
    p1, l1, p2, l2 = map(math.radians, (p1, l1, p2, l2))
    dp, dl = p2 - p1, l2 - l1
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


def asn_is_placeholder(asn: str) -> bool:
    try:
        return int(asn) >= 500000
    except Exception:
        return True


def device_fingerprint(os_name: str, browser_name: str, dtype: str) -> str:
    base = f"{os_name or 'NA'}|{browser_name or 'NA'}|{dtype or 'NA'}"
    return hashlib.sha1(base.encode("utf-8")).hexdigest()[:16]


class UserState:
    __slots__ = ("last_ts", "last_country", "asn_hist", "asn_set", "dev_hist", "dev_set")

    def __init__(self):
        self.last_ts = None
        self.last_country = None
        self.asn_hist = deque()  # (asn, ts)
        self.asn_set = set()
        self.dev_hist = deque()  # (fp, ts)
        self.dev_set = set()


def remove_90d(us: UserState, now_sec: int):
    while us.asn_hist and us.asn_hist[0][1] < now_sec - WIN_90D:
        old, _ = us.asn_hist.popleft()
        if all(a != old for a, _ in us.asn_hist):
            us.asn_set.discard(old)
    while us.dev_hist and us.dev_hist[0][1] < now_sec - WIN_90D:
        old, _ = us.dev_hist.popleft()
        if all(d != old for d, _ in us.dev_hist):
            us.dev_set.discard(old)


# ------------- Simulator -------------
class SuspiciousLoginSimulator:
    def __init__(self, app_config: AppConfig):
        # Keycloak config (real mode)
        self.keycloak_admin_user = app_config.keycloak_admin_user
        self.keycloak_admin_pass = app_config.keycloak_admin_pass
        self.username = app_config.keycloak_username
        self.password = app_config.keycloak_password 
        self.realm = app_config.keycloak_realm
        self.keycloak_url = app_config.keycloak_base_url.rstrip("/")

        # Per-user feature state
        self.users: Dict[str, UserState] = defaultdict(UserState)

        # Attack plan for impossible travel (successful logins)
        self._attack_path: List[str] = ["PL", "US", "AU", "GB", "BR", "JP"]
        self._target_speed_kmh: float = float(os.getenv("IT_SPEED_KMH", "1200.0"))

    # -------- Keycloak real login attempt (should fail with bad password) --------
    def _auth_attempt_keycloak(self, username: str, password: str) -> bool:
        """
        Returns True if login succeeds, False on 4xx failure.
        Treats network/server errors as failures for test convenience.
        """
        url = f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token"
        data = {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": username,
            "password": password,
        }
        try:
            r = requests.post(url, data=data, timeout=10)
            if r.status_code == 200:
                return True
            if 400 <= r.status_code < 500:
                return False
            r.raise_for_status()
            return False
        except requests.RequestException:
            return False

    # -------- Event engineering --------
    def _engineer_doc(
        self,
        user_id: str,
        when_dt: datetime,
        event_hour: int,
        ip: str,
        country: str,
        region: str,
        city: str,
        os_name: str,
        browser: str,
        dtype: str,
        asn: str = "15169",
        login_successful: bool = True,
    ) -> dict:
        iso_ts = when_dt.replace(tzinfo=timezone.utc).isoformat()
        ts_sec = int(when_dt.replace(tzinfo=timezone.utc).timestamp())

        us = self.users[user_id]
        remove_90d(us, ts_sec)

        dev_fp = device_fingerprint(os_name, browser, dtype)
        dev_nov = 1 if dev_fp not in us.dev_set else 0
        us.dev_hist.append((dev_fp, ts_sec))
        us.dev_set.add(dev_fp)

        asn_ph = asn_is_placeholder(asn)
        asn_nov = 0
        if not asn_ph:
            asn_nov = 1 if asn not in us.asn_set else 0
            us.asn_hist.append((asn, ts_sec))
            us.asn_set.add(asn)

        prev_country = us.last_country
        country_change = 0
        geo_v_kmh = 0.0
        if prev_country is not None:
            country_change = 1 if country != prev_country else 0
            c1 = country_centroid(prev_country)
            c2 = country_centroid(country)
            if c1 and c2 and us.last_ts is not None:
                dist_km = haversine_km(c1[0], c1[1], c2[0], c2[1])
                dt_h = max((ts_sec - us.last_ts) / 3600.0, 1e-6)
                geo_v_kmh = min(dist_km / dt_h, VEL_CAP)

        us.last_ts = ts_sec
        us.last_country = country

        return {
            "Login Timestamp": when_dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "User ID": user_id,
            "Round-Trip Time [ms]": "",
            "IP Address": ip,
            "Country": country,
            "Region": region or "-",
            "City": city or "-",
            "ASN": asn or "-",
            "User Agent String": browser or "Simulated",
            "Browser Name and Version": browser or "Simulated",
            "OS Name and Version": os_name or "Simulated",
            "Device Type": dtype or "desktop",
            "Login Successful": "True" if login_successful else "False",

            "Is Attack IP": "False",
            "Is Account Takeover": "False",

            "@timestamp": iso_ts,
            "event_hour": event_hour,
            "agent_name": "agent.suspicious",

            "user_id": user_id,
            "asn": asn or "-",
            "asn_placeholder_flag": bool(asn_ph),
            "country": country,
            "region": region or "-",
            "city": city or "-",
            "os_name": os_name or "SimOS",
            "browser_name": browser or "SimBrowser",
            "device_type": dtype or "desktop",
            "device_fp": dev_fp,
            "is_success": bool(login_successful),

            "geo_velocity_kmh": float(geo_v_kmh),
            "country_change_i": int(country_change),
            "asn_novelty_i": int(asn_nov),
            "device_novelty_i": int(dev_nov),
        }

    # -------- Impossible travel (successful logins, synthetic write only) --------
    def _synthesize_impossible_travel(
        self,
        user_id: str,
        attack_path: Optional[List[str]] = None,
        target_speed_kmh: float = 1200.0,
    ) -> List[dict]:
        path = attack_path or self._attack_path
        now = datetime.utcnow().replace(second=0, microsecond=0, tzinfo=timezone.utc)
        curr_time = now
        docs: List[dict] = []

        # First login
        first_cty = path[0]
        docs.append(
            self._engineer_doc(
                user_id=user_id,
                when_dt=curr_time,
                event_hour=curr_time.hour,
                ip=COUNTRY_IP[first_cty],
                country=first_cty,
                region="-",
                city="-",
                os_name="Windows 10",
                browser="Chrome 118",
                dtype="desktop",
                asn="15169",
                login_successful=True,
            )
        )

        # Jumps at >900 km/h
        for cty in path[1:]:
            prev_cty = self.users[user_id].last_country or first_cty
            c1 = country_centroid(prev_cty)
            c2 = country_centroid(cty)
            if not (c1 and c2):
                delta = timedelta(minutes=2)
            else:
                dist_km = haversine_km(c1[0], c1[1], c2[0], c2[1])
                dt_hours = max(dist_km / target_speed_kmh, 1 / 3600)  # >=1s
                delta = timedelta(seconds=int(dt_hours * 3600))

            curr_time = curr_time + delta
            os_name, browser, dtype = random.choice(DEV_VARIANTS)
            asn = random.choice(ASN_VARIANTS)

            docs.append(
                self._engineer_doc(
                    user_id=user_id,
                    when_dt=curr_time,
                    event_hour=curr_time.hour,
                    ip=COUNTRY_IP[cty],
                    country=cty,
                    region="-",
                    city="-",
                    os_name=os_name,
                    browser=browser,
                    dtype=dtype,
                    asn=asn,
                    login_successful=True,
                )
            )

        return docs

    # -------- Failed-burst via REAL Keycloak attempts (wrong password) --------
    def _synthesize_failed_burst_REAL(
        self,
        user_id: str,
        failures: int,
        timeframe_sec: int,
        bad_password: str = "definitely-wrong",
        country: str = "PL",
        stick_device: bool = True,
        per_attempt_sleep_s: float = 0.05,  # tiny, avoid hammering
    ) -> List[dict]:
        now = datetime.utcnow().replace(microsecond=0, tzinfo=timezone.utc)
        start = now

        if stick_device:
            os_name, browser, dtype = random.choice(DEV_VARIANTS)
            asn = random.choice(ASN_VARIANTS)

        docs: List[dict] = []
        step = 0 if failures <= 1 else max(1, timeframe_sec // (failures - 1))

        for i in range(failures):
            t = start + timedelta(seconds=i * step)

            
            ok = self._auth_attempt_keycloak(user_id, bad_password)

            if not stick_device:
                os_name, browser, dtype = random.choice(DEV_VARIANTS)
                asn = random.choice(ASN_VARIANTS)

            d = self._engineer_doc(
                user_id=user_id,
                when_dt=t,
                event_hour=t.hour,
                ip=COUNTRY_IP.get(country, "8.8.8.8"),
                country=country,
                region="-",
                city="-",
                os_name=os_name,
                browser=browser,
                dtype=dtype,
                asn=asn,
                login_successful=False,
            )
            d["Login Successful"] = "False"
            d["is_success"] = False

            docs.append(d)
            time.sleep(per_attempt_sleep_s)

        return docs

    # -------- Ship NDJSON into the agent container --------
    def _ship_to_wazuh_localfile(self, docs: List[dict], path: str = WAZUH_LOCALFILE):
        cmd = [
            "docker",
            "exec",
            "-i",
            WAZUH_AGENT_CONTAINER,
            "sh",
            "-c",
            f"mkdir -p \"$(dirname '{path}')\" && cat >> '{path}'",
        ]
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, text=True)
            for d in docs:
                proc.stdin.write(json.dumps(d, ensure_ascii=False) + "\n")
            proc.stdin.close()
            rc = proc.wait()
            if rc != 0:
                raise RuntimeError(f"docker exec exited with {rc}")
            print(f"[✓] Wrote {len(docs)} events to {WAZUH_AGENT_CONTAINER}:{path}")
        except Exception as e:
            print(f"[!] Could not write to {WAZUH_AGENT_CONTAINER}:{path}: {e}")

    # -------- Entrypoint --------
    def simulate_logins(self):
        """
        1) Generate a realistic impossible-travel sequence (successful logins) and ship it.
        2) Generate two real failed bursts: 5 in 120s and 10 in 300s, ship them.
        """
        # 1) Impossible travel (success) — synthetic write with geo/velocity
        it_docs = self._synthesize_impossible_travel(
            user_id=self.username,
            attack_path=self._attack_path,
            target_speed_kmh=self._target_speed_kmh,
        )
        self._ship_to_wazuh_localfile(it_docs)
        print(f"[IT] Generated {len(it_docs)} impossible-travel success events.")

        # 2) Failed bursts (REAL Keycloak-driven)
        burst_5_docs = self._synthesize_failed_burst_REAL(
            user_id=self.username,
            failures=int(os.getenv("BURST5_COUNT", "5")),
            timeframe_sec=int(os.getenv("BURST5_WINDOW_S", "120")),
            bad_password=os.getenv("BURST_BAD_PASSWORD", "definitely-wrong"),
            country=os.getenv("BURST_COUNTRY", "PL"),
            stick_device=True,
            per_attempt_sleep_s=float(os.getenv("BURST_SLEEP_S", "0.05")),
        )
        self._ship_to_wazuh_localfile(burst_5_docs)
        print(f"[BURST] Generated {len(burst_5_docs)} failed attempts (5 in 120s).")

        burst_10_docs = self._synthesize_failed_burst_REAL(
            user_id=self.username,
            failures=int(os.getenv("BURST10_COUNT", "10")),
            timeframe_sec=int(os.getenv("BURST10_WINDOW_S", "300")),
            bad_password=os.getenv("BURST_BAD_PASSWORD", "definitely-wrong"),
            country=os.getenv("BURST_COUNTRY", "PL"),
            stick_device=True,
            per_attempt_sleep_s=float(os.getenv("BURST_SLEEP_S", "0.05")),
        )
        self._ship_to_wazuh_localfile(burst_10_docs)
        print(f"[BURST] Generated {len(burst_10_docs)} failed attempts (10 in 300s).")

