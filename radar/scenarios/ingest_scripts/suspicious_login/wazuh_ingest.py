#!/usr/bin/env python3
import json
import os
import random
import re
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import requests
import yaml
from requests.auth import HTTPBasicAuth


def _parse_env_value(raw: str):
    raw = raw.strip()
    if raw.startswith("'"):
        end = raw.find("'", 1)
        if end < 0:
            return None
        rest = raw[end + 1 :].strip()
        return raw[1:end] if (not rest or rest.startswith("#")) else None
    if raw.startswith('"'):
        out, i = [], 1
        while i < len(raw):
            ch = raw[i]
            if ch == "\\" and i + 1 < len(raw) and raw[i + 1] in '\\"$`':
                out.append(raw[i + 1])
                i += 2
                continue
            if ch == '"':
                rest = raw[i + 1 :].strip()
                return "".join(out) if (not rest or rest.startswith("#")) else None
            out.append(ch)
            i += 1
        return None
    return re.split(r"\s+#", raw, maxsplit=1)[0].strip()


# end _parse_env_value


_ENV_LINE_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def load_env(env_path: Path) -> None:
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _ENV_LINE_RE.match(line)
        if not m:
            continue
        value = _parse_env_value(m.group(2))
        if value is not None:
            os.environ.setdefault(m.group(1), value)


# ────────────────────────────
# Config
# ────────────────────────────
ES_URL = "https://wazuh.indexer:9200"
AUTH = HTTPBasicAuth("admin", "SecretPassword")
CA_CERT = "config/wazuh_indexer_ssl_certs/root-ca.pem"
CHUNK_SIZE = 200
REQUEST_TIMEOUT = 60


load_env(Path(".env"))
if os.environ.get("OS_URL"):
    ES_URL = os.environ["OS_URL"].rstrip("/")
if os.environ.get("OS_USER") or os.environ.get("OS_PASS"):
    AUTH = HTTPBasicAuth(os.environ.get("OS_USER", ""), os.environ.get("OS_PASS", ""))
OS_VERIFY_SSL = os.environ.get("OS_VERIFY_SSL", "true").lower() in ("1", "true", "yes", "on")


def _load_full_config():
    cfg_path = Path(__file__).resolve().parent.parent / "config.yaml"
    with cfg_path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _get_ingest_cfg(cfg):
    return cfg.get("scenarios", {}).get("suspicious_login", {}).get("ingest", {})


# ────────────────────────────
# Bulk indexing
# ────────────────────────────
# Same name as off_hours.PIPELINE_NAME (this script runs without /app on its import path).
OFF_HOURS_PIPELINE = "radar-off-hours"
# Must match Wazuh's legacy `wazuh` template (wazuh-archives-4.x-*), which maps strings as
# keyword. Under any other wazuh-archives-* name, dynamic mapping makes agent.name `text`,
# and AD then refuses every detector on wazuh-archives-* that uses it as a category field.
DEFAULT_ARCHIVES_INDEX_PREFIX = "wazuh-archives-4.x"


def send_bulk(lines, pipeline=None):
    data = "\n".join(lines) + "\n"
    params = "refresh=true" + (f"&pipeline={pipeline}" if pipeline else "")
    resp = requests.post(
        f"{ES_URL}/_bulk?{params}",
        auth=AUTH,
        headers={"Content-Type": "application/x-ndjson"},
        data=data,
        verify=OS_VERIFY_SSL,
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    result = resp.json()
    if result.get("errors"):
        print("Bulk errors (first 2 shown):", result["items"][:2])
    else:
        print(f"Indexed chunk of {len(lines)//2} docs")


# ────────────────────────────
# Off-hour activity generator
# ────────────────────────────
ACTIVITY_DECODERS = {
    "auth_success": "sshd",
    "file_access": "auditd",
    "process_exec": "auditd",
    "web_request": "nginx",
}


def _sample_shift_anchor_hour(start_h: float, end_h: float, drift_min: float) -> float:
    """Hours after local midnight of the day the shift starts. Not wrapped at 24:
    the part of a shift that crosses midnight lands on the next calendar day."""
    drift_h = drift_min / 60.0
    span = end_h - start_h if start_h <= end_h else (24 - start_h) + end_h
    return start_h + random.uniform(0, span) + random.uniform(-drift_h, drift_h)


def _to_utc_iso(day: date, hour_float: float, tz=timezone.utc) -> str:
    """`hour_float` hours of wall-clock time after midnight of `day` in `tz`, as UTC.
    Aware datetime arithmetic is wall-clock arithmetic, so summer time is respected."""
    when = datetime.combine(day, time(0), tzinfo=tz) + timedelta(hours=hour_float)
    return when.astimezone(timezone.utc).replace(second=0, microsecond=0).isoformat()


def _workday(day: date) -> bool:
    return day.weekday() < 5  # Mon-Fri only, matches the shift model itself


def _burst_day(today: date, days_ago: int) -> date:
    """The workday closest to `days_ago` days before today, looking further back."""
    day = today - timedelta(days=days_ago)
    while not _workday(day):
        day -= timedelta(days=1)
    return day


def generate_archive_events(ingest_cfg: dict, today: date | None = None) -> list:
    history_days = int(ingest_cfg.get("history_days", 45))
    future_days = int(ingest_cfg.get("future_days", 14))
    agent_name = ingest_cfg.get("agent_name", "edge.vm")
    index_prefix = ingest_cfg.get("archives_index_prefix", DEFAULT_ARCHIVES_INDEX_PREFIX)
    activity_types = ingest_cfg.get("activity_types", ["auth_success"])
    events_min = int(ingest_cfg.get("events_per_login_min", 1))
    events_max = int(ingest_cfg.get("events_per_login_max", 1))
    users = ingest_cfg.get("users", [])

    today = today or date.today()
    out = []

    def add(name: str, day: date, hour: float, tz) -> None:
        activity = random.choice(activity_types)
        iso_ts = _to_utc_iso(day, hour, tz)
        doc = {
            "@timestamp": iso_ts,
            "timestamp": iso_ts,
            "agent": {"name": agent_name},
            "predecoder": {"program_name": activity},
            "decoder": {"name": ACTIVITY_DECODERS.get(activity, "generic")},
            "data": {
                "user": name,
                "action": activity,
            },
            "full_log": f"synthetic off-hour training event: user={name} activity={activity}",
        }
        out.append((f"{index_prefix}-{iso_ts[:10].replace('-', '.')}", doc))

    for u in users:
        name = u["name"]
        tz = ZoneInfo(u["timezone"]) if u.get("timezone") else timezone.utc
        start_h, end_h = float(u["start_hour"]), float(u["end_hour"])
        drift_min = float(u.get("drift_minutes", 45))
        evenings = u.get("evenings") or {}

        for day_offset in range(-history_days, future_days):
            day = today + timedelta(days=day_offset)  # a calendar day in the user's time zone
            if not _workday(day):
                continue
            for _ in range(random.randint(events_min, events_max)):
                add(name, day, _sample_shift_anchor_hour(start_h, end_h, drift_min), tz)
            # Occasional evening work: per_week of the five workdays on average.
            if evenings and random.random() < float(evenings.get("per_week", 2)) / 5.0:
                for _ in range(random.randint(int(evenings.get("events_min", 1)), int(evenings.get("events_max", 3)))):
                    add(name, day, random.uniform(float(evenings["start_hour"]), float(evenings["end_hour"])), tz)

        burst = u.get("burst")
        if burst and 0 < int(burst.get("days_ago", 7)) <= history_days:
            day = _burst_day(today, int(burst.get("days_ago", 7)))
            start = float(burst.get("local_hour", 2.0))
            for _ in range(int(burst.get("events", 30))):
                add(name, day, start + random.uniform(0, 25) / 60.0, tz)  # inside one 30-minute interval

    return out


def bulk_index_archive_events(events: list, pipeline=None) -> None:
    buffer = []
    indexed = 0
    for index_name, doc in events:
        buffer.append(json.dumps({"index": {"_index": index_name}}))
        buffer.append(json.dumps(doc))
        if len(buffer) >= CHUNK_SIZE * 2:
            send_bulk(buffer, pipeline)
            indexed += len(buffer) // 2
            buffer.clear()
    if buffer:
        send_bulk(buffer, pipeline)
        indexed += len(buffer) // 2
    print(f"Indexed {indexed} synthetic archive events across " f"{len({idx for idx, _ in events})} daily indices")


def run_off_hour_ingest():
    cfg = _load_full_config()
    ingest_cfg = _get_ingest_cfg(cfg)
    if not ingest_cfg.get("users"):
        print("No scenarios.suspicious_login.ingest.users configured in config.yaml; nothing to ingest")
        return
    events = generate_archive_events(ingest_cfg)
    off_hours_cfg = cfg.get("scenarios", {}).get("suspicious_login", {}).get("off_hours") or {}
    pipeline = OFF_HOURS_PIPELINE if off_hours_cfg and off_hours_cfg.get("enabled", True) else None
    bulk_index_archive_events(events, pipeline)


if __name__ == "__main__":
    run_off_hour_ingest()
