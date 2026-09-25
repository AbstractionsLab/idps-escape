#!/usr/bin/env python3
import re
import os
import sys
import json
import time
from datetime import datetime, timedelta, timezone

import requests
import yaml
from pathlib import Path
from requests.auth import HTTPBasicAuth


def _load_config():
    cfg_path = Path(__file__).resolve().parent.parent / "config.yaml"
    with cfg_path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def _get_ingest_cfg(cfg, scenario):
    return cfg["scenarios"][scenario]["ingest"]


def _parse_env_value(raw: str):
    raw = raw.strip()
    if raw.startswith("'"):
        end = raw.find("'", 1)
        if end < 0:
            return None
        rest = raw[end + 1:].strip()
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
                rest = raw[i + 1:].strip()
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


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def os_post(url, auth, verify_tls, body):
    r = requests.post(
        url,
        json=body,
        auth=auth,
        verify=verify_tls,
        timeout=30,
        headers={"Content-Type": "application/json"},
    )
    if r.status_code not in (200, 201):
        raise RuntimeError(f"OpenSearch POST failed {r.status_code}: {r.text}")
    return r.json()


def _extract_log_bytes(hit):
    v = hit.get("_source", {}).get("data", {}).get("log_bytes", None)
    return None if v is None else int(v)


def query_last_values(os_url, auth, verify, index_pattern, agent_name, size):
    for field in ("agent.name", "agent.name.keyword"):
        search_body = {
            "size": size,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "_source": ["data.log_bytes"],
            "query": {"bool": {"filter": [
                {"term": {field: agent_name}},
            ]}},
        }
        stats = os_post(f"{os_url}/{index_pattern}/_search", auth, verify, search_body)
        hits = stats.get("hits", {}).get("hits", [])
        if hits:
            return hits
    return []


def main():
    load_env(Path(".env"))

    os_url = os.environ.get("OS_URL", "").rstrip("/")
    os_user = os.environ.get("OS_USER", "")
    os_pass = os.environ.get("OS_PASS", "")
    os_verify = os.environ.get("OS_VERIFY_SSL", "true").lower() in ("1", "true", "yes", "on")

    if not os_url or not os_user or not os_pass:
        print("Missing OS_URL / OS_USER / OS_PASS. Put them into .env or export them.", file=sys.stderr)
        sys.exit(2)

    cfg = _load_config()
    lv = _get_ingest_cfg(cfg, "log_volume")

    agent_id           = str(lv["agent_id"])
    agent_name         = str(lv["agent_name"])
    program            = str(lv["program"])
    log_path           = str(lv["log_path"])
    index_prefix       = str(lv["index_prefix"])
    minutes            = int(lv["history_minutes"])
    step_s             = int(lv["step_seconds"])
    delta_min_docs     = int(lv["delta_min_docs"])
    fallback_delta     = int(lv["fallback_delta"])
    first_value_seed   = int(lv["baseline_bytes"])

    index_pattern = f"{index_prefix}-*"
    auth = HTTPBasicAuth(os_user, os_pass)

    hits = query_last_values(os_url, auth, os_verify, index_pattern, agent_name, delta_min_docs)

    if not hits:
        print(
            f"No existing data.log_bytes found yet for agent '{agent_name}' in "
            f"'{index_pattern}' -- waiting 60s and checking once more...",
            file=sys.stderr,
        )
        time.sleep(60)
        hits = query_last_values(os_url, auth, os_verify, index_pattern, agent_name, delta_min_docs)

    if not hits:
        print(
            f"ERROR: still no data.log_bytes for agent '{agent_name}' in '{index_pattern}' "
            f"after waiting 60s. This scenario needs real log_volume_metric events already "
            f"flowing before it can continue their pattern. Check:\n"
            f"  1. Is '{agent_name}' actually enrolled in the log_volume Wazuh group? "
            f"(python3 -m wazuh_api.cli resolve-agent --name {agent_name})\n"
            f"  2. Has the manager-side log_volume deploy fully applied? "
            f"(bash radar_deploy/manager-health.sh)\n"
            f"  3. Is the agent's radar-log-volume.timer actually running and writing to "
            f"/var/log/radar/log_volume_metric.log on the endpoint?\n"
            f"Falling back to the static baseline_bytes seed for now, but this almost "
            f"certainly means the scenario isn't wired up correctly yet.",
            file=sys.stderr,
        )
        first_value = first_value_seed
        delta = fallback_delta
        second_value = first_value + delta
    elif len(hits) >= 2:
        v1 = _extract_log_bytes(hits[0])
        v2 = _extract_log_bytes(hits[1])
        if v1 is None or v2 is None:
            print("Missing data.log_bytes in the most recent docs. Falling back.", file=sys.stderr)
            first_value = first_value_seed
            delta = fallback_delta
            second_value = first_value + delta
        else:
            first_value = v1
            second_value = v2
            delta = first_value - second_value
            if delta <= 0:
                delta = fallback_delta
                second_value = first_value + delta
    else:
        v1 = _extract_log_bytes(hits[0])
        if v1 is None:
            print("Only one recent doc found and it has no data.log_bytes. Falling back.", file=sys.stderr)
            first_value = first_value_seed
        else:
            print(
                "Only one recent doc found -- using its value as the baseline and "
                "fallback_delta as the growth rate (can't compute a real delta from a single point).",
                file=sys.stderr,
            )
            first_value = v1
        delta = fallback_delta
        second_value = first_value + delta

    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=minutes)
    index_name = f"{index_prefix}-{now.strftime('%Y.%m.%d')}"
    bulk_url = f"{os_url}/_bulk"

    total_points = max(1, (minutes * 60) // step_s)
    start_value = first_value - delta * (total_points - 1)

    lines = []
    for i in range(total_points):
        ts = start + timedelta(seconds=i * step_s)
        val = max(0, start_value + delta * i)
        doc = {
            "@timestamp": iso(ts),
            "agent": {"name": agent_name, "id": agent_id},
            "data": {"log_path": log_path, "log_bytes": int(val)},
            "predecoder": {"program_name": program},
        }
        lines.append(json.dumps({"index": {"_index": index_name}}))
        lines.append(json.dumps(doc))

    ts2 = now + timedelta(seconds=step_s)
    doc2 = {
        "@timestamp": iso(ts2),
        "agent": {"name": agent_name, "id": agent_id},
        "data": {"log_path": log_path, "log_bytes": int(second_value)},
        "predecoder": {"program_name": program},
    }
    lines.append(json.dumps({"index": {"_index": index_name}}))
    lines.append(json.dumps(doc2))

    payload = "\n".join(lines) + "\n"
    r = requests.post(
        bulk_url,
        data=payload.encode("utf-8"),
        headers={"Content-Type": "application/x-ndjson"},
        auth=auth,
        verify=os_verify,
        timeout=30,
    )

    if r.status_code not in (200, 201):
        print("Bulk ingest failed:", r.status_code, r.text, file=sys.stderr)
        sys.exit(1)

    resp = r.json()
    if resp.get("errors"):
        bad = [it for it in resp.get("items", []) if list(it.values())[0].get("error")]
        print(f"Bulk completed with errors. Bad items: {len(bad)}")
        print(json.dumps(bad[:3], indent=2))
        sys.exit(1)

    print(f"Computed first_value={first_value} second_value={second_value} delta={delta}")
    print(f"Generated start_value={start_value} -> end_value={first_value} over {total_points} points")
    print(f"Ingested {total_points + 1} docs into {index_name}")


if __name__ == "__main__":
    main()