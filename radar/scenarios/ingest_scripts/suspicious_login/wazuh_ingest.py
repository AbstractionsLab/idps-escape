#!/usr/bin/env python3
import csv, glob, json, os, math, hashlib, random
from collections import defaultdict, deque
from datetime import datetime, date, timedelta, timezone
import requests
from requests.auth import HTTPBasicAuth

# ────────────────────────────
# Config
# ────────────────────────────
ES_URL = "https://wazuh.indexer:9200"
AUTH = HTTPBasicAuth("admin", "SecretPassword")
CA_CERT = "config/wazuh_indexer_ssl_certs/root-ca.pem"
CHUNK_SIZE = 200
REQUEST_TIMEOUT = 60
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

INDEX_PREFIX = "wazuh-ad-suspicious-login"
DATE_FIELD = "Login Timestamp"
DATE_FMT = "%Y-%m-%d %H:%M:%S.%f"

# Travel/novelty knobs
WIN_90D = 90 * 24 * 3600   # seconds
VEL_CAP = 2000.0           # km/h
IMPOSSIBLE_KMH = 900.0

# Dataset field names
FIELD_USER    = "User ID"
FIELD_SUCCESS = "Login Successful"
FIELD_ASN     = "ASN"
FIELD_COUNTRY = "Country"
FIELD_REGION  = "Region"
FIELD_CITY    = "City"
FIELD_OS      = "OS Name"
FIELD_BROWSER = "Browser Name"
FIELD_DTYPE   = "Device Type"

COUNTRY_CENTROIDS = {
    "LUXEMBOURG": (49.8153, 6.1296), "LU": (49.8153, 6.1296),
    "NORWAY": (60.4720, 8.4689),     "NO": (60.4720, 8.4689),
    "GERMANY": (51.1657, 10.4515),   "DE": (51.1657, 10.4515),
    "NETHERLANDS": (52.1326, 5.2913),"NL": (52.1326, 5.2913),
    "FRANCE": (46.2276, 2.2137),     "FR": (46.2276, 2.2137),
    "TURKEY": (38.9637, 35.2433),    "TR": (38.9637, 35.2433),
    "KAZAKHSTAN": (48.0196, 66.9237),"KZ": (48.0196, 66.9237),
    "AZERBAIJAN": (40.1431, 47.5769),"AZ": (40.1431, 47.5769),
    "UNITED KINGDOM": (55.3781, -3.4360), "UK": (55.3781, -3.4360), "GB": (55.3781, -3.4360),
    "SPAIN": (40.4637, -3.7492),     "ES": (40.4637, -3.7492),
    "ITALY": (41.8719, 12.5674),     "IT": (41.8719, 12.5674),
    "SWEDEN": (60.1282, 18.6435),    "SE": (60.1282, 18.6435),
    "FINLAND": (61.9241, 25.7482),   "FI": (61.9241, 25.7482),
    "POLAND": (51.9194, 19.1451),    "PL": (51.9194, 19.1451),
    "UNITED STATES": (39.8283, -98.5795), "US": (39.8283, -98.5795),
    "CANADA": (56.1304, -106.3468),  "CA": (56.1304, -106.3468),
}

# ────────────────────────────
# Helpers
# ────────────────────────────
def send_bulk(lines):
    data = "\n".join(lines) + "\n"
    resp = requests.post(f"{ES_URL}/_bulk?refresh=true",
        auth=AUTH, headers={"Content-Type": "application/x-ndjson"},
        data=data, verify=CA_CERT, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    result = resp.json()
    if result.get("errors"):
        print("Bulk errors (first 2 shown):", result["items"][:2])
    else:
        print(f"Indexed chunk of {len(lines)//2} docs")

def bool_from_any(v):
    if isinstance(v, bool): return v
    s = str(v).strip().lower()
    return s in ("1","true","t","yes","y")

def asn_is_placeholder(asn):
    try: return int(asn) >= 500000
    except: return True

def device_fingerprint(os_name, browser_name, dtype):
    base = f"{os_name or 'NA'}|{browser_name or 'NA'}|{dtype or 'NA'}"
    return hashlib.sha1(base.encode("utf-8")).hexdigest()[:16]

def haversine_km(p1, l1, p2, l2):
    R = 6371.0088
    p1, l1, p2, l2 = map(math.radians, (p1, l1, p2, l2))
    dp, dl = p2 - p1, l2 - l1
    a = math.sin(dp/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    return 2*R*math.asin(math.sqrt(a))

def country_centroid(country: str):
    if not country: return None
    key = country.strip().upper()
    return COUNTRY_CENTROIDS.get(key)

def syslog_stamp(dt_local: datetime) -> str:
    #"Nov 11 14:49:44"
    return dt_local.strftime("%b %e %H:%M:%S")

def make_sshd_full_log(dt_local: datetime, host: str, user: str, srcip: str, port: int, success: bool) -> str:
    pid = random.randint(20000, 99999)
    if success:
        return (f"{syslog_stamp(dt_local)} {host} sshd[{pid}]: Accepted publickey for {user} "
                f"from {srcip} port {port} ssh2")
    else:
        return (f"{syslog_stamp(dt_local)} {host} sshd[{pid}]: Failed password for {user} "
                f"from {srcip} port {port} ssh2")

# ────────────────────────────
# Per-user state for novelty/velocity
# ────────────────────────────
class UserState:
    __slots__ = ("last_ts","last_country","asn_hist","asn_set","dev_hist","dev_set")
    def __init__(self):
        self.last_ts = None
        self.last_country = None
        self.asn_hist = deque() 
        self.asn_set  = set()
        self.dev_hist = deque()
        self.dev_set  = set()

USERS = defaultdict(UserState)

def remove_90d(us: UserState, now_sec: int):
    while us.asn_hist and us.asn_hist[0][1] < now_sec - WIN_90D:
        old,_ = us.asn_hist.popleft()
        if all(a != old for a,_ in us.asn_hist): us.asn_set.discard(old)
    while us.dev_hist and us.dev_hist[0][1] < now_sec - WIN_90D:
        old,_ = us.dev_hist.popleft()
        if all(d != old for d,_ in us.dev_hist): us.dev_set.discard(old)

# ────────────────────────────
# Ingest
# ────────────────────────────
def shift_and_bulk(file_pattern, day_shift):
    target_date = date.today() + timedelta(days=day_shift)
    mode = "Training" if day_shift < 0 else "Simulation"

    host = "agent.suspicious"
    default_srcip = "192.0.2.10"
    default_port  = 60000

    for path in glob.glob(file_pattern):
        buffer = []
        print(f"{mode} load from {path}")

        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # time shift
                orig = datetime.strptime(row[DATE_FIELD], DATE_FMT)
                new_ts_local = datetime.combine(target_date, orig.time())
                utc_ts = new_ts_local.astimezone(timezone.utc)
                ts_sec = int(utc_ts.timestamp())
                iso_ts = utc_ts.isoformat()

                # CSV fields
                user_id = row.get(FIELD_USER) or "unknown"
                success = bool_from_any(row.get(FIELD_SUCCESS))
                asn     = row.get(FIELD_ASN, "")
                country = (row.get(FIELD_COUNTRY) or "").strip() or "NA"
                region  = row.get(FIELD_REGION) or ""
                city    = row.get(FIELD_CITY) or ""
                os_name = row.get(FIELD_OS) or ""
                browser = row.get(FIELD_BROWSER) or ""
                dtype   = row.get(FIELD_DTYPE) or ""
                dev_fp  = device_fingerprint(os_name, browser, dtype)

                srcip = row.get("IP") or default_srcip
                try:
                    port = int(row.get("Port") or default_port)
                except:
                    port = default_port

                # novelty state
                us = USERS[user_id]
                remove_90d(us, ts_sec)

                asn_ph = asn_is_placeholder(asn)
                asn_nov = False
                if not asn_ph:
                    asn_nov = (asn not in us.asn_set)
                    us.asn_hist.append((asn, ts_sec))
                    us.asn_set.add(asn)

                dev_nov = (dev_fp not in us.dev_set)
                us.dev_hist.append((dev_fp, ts_sec))
                us.dev_set.add(dev_fp)

                # country change + centroid velocity
                country_change = False
                geo_v_kmh = None
                prev_country = us.last_country
                if prev_country is not None:
                    country_change = (country != prev_country)
                    c1 = country_centroid(prev_country)
                    c2 = country_centroid(country)
                    if c1 and c2 and us.last_ts is not None:
                        dist_km = haversine_km(c1[0], c1[1], c2[0], c2[1])
                        dt_h = max((ts_sec - us.last_ts)/3600.0, 1e-6)
                        geo_v_kmh = min(dist_km/dt_h, VEL_CAP)

                us.last_ts = ts_sec
                us.last_country = country

                full_log = make_sshd_full_log(new_ts_local, host, user_id, srcip, port, success)

                out = {
                    "@timestamp": iso_ts,
                    "decoder": {"name": "sshd"},
                    "predecoder": {"program_name": "sshd"},
                    "location": "/var/log/auth.log",
                    "agent": {"name": host},

                    # Fields Wazuh decoders set for sshd:
                    "data": {
                        "user": user_id,
                        "srcip": srcip,
                        "port": str(port),
                        "radar_outcome": "success" if success else "failure",
                        "radar_asn": asn,
                        "radar_asn_placeholder_flag": bool(asn_ph),
                        "radar_country": country,
                        "radar_region": region,
                        "radar_city": city,
                        "radar_geo_velocity_kmh": float(geo_v_kmh) if geo_v_kmh is not None else 0.0,
                        "radar_country_change_i": 1 if country_change else 0,
                        "radar_asn_novelty_i": 1 if asn_nov else 0
                    },

                    # Original syslog line
                    "full_log": full_log,

                }

                idx = f"{INDEX_PREFIX}-{new_ts_local.strftime('%Y.%m.%d')}"
                buffer.append(json.dumps({"index": {"_index": idx}}))
                buffer.append(json.dumps(out))

                if len(buffer) >= CHUNK_SIZE * 2:
                    send_bulk(buffer); buffer.clear()

        if buffer: send_bulk(buffer)
        print(f" → Completed {mode}, indexed into {idx}")

if __name__ == "__main__":
    to_load = [
        ("rba-dataset-3.csv", -3),
        ("rba-dataset-2.csv", -2),
        ("rba-dataset-1.csv", -1),
        ("rba-dataset+0.csv", 0),
        ("rba-dataset+1.csv", 1),
        ("rba-dataset+2.csv", 2),
        ("rba-dataset+3.csv", 3),
    ]
    for filename, shift in to_load:
        file_pattern = os.path.join(BASE_DIR, "dataset", filename)
        shift_and_bulk(file_pattern, day_shift=shift)
