#!/usr/bin/env python3
import os
import sys
import json
from datetime import datetime, timedelta, timezone

import requests
from pathlib import Path
from requests.auth import HTTPBasicAuth


def load_env(env_path: Path) -> None:
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


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


def main():
    load_env(Path(".env"))

    os_url = os.environ.get("OS_URL", "").rstrip("/")
    os_user = os.environ.get("OS_USER", "")
    os_pass = os.environ.get("OS_PASS", "")
    os_verify = os.environ.get("OS_VERIFY_SSL", "true").lower() in ("1", "true", "yes", "on")

    if not os_url or not os_user or not os_pass:
        print("Missing OS_URL / OS_USER / OS_PASS. Put them into .env or export them.", file=sys.stderr)
        sys.exit(2)

    agent_id = "001"
    agent_name = "edge.vm"
    program = "log_volume_metric"
    log_path = "/var/log"

    minutes = 240
    step_s = 20

    index_pattern = "wazuh-ad-log-volume-*"
    fallback_delta = 20000

    query_filters = [
        {"range": {"@timestamp": {"gte": "now-10m"}}},
        {"term": {"agent.name": agent_name}},
    ]

    search_body = {
        "size": 2,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": ["data.log_bytes"],
        "query": {"bool": {"filter": query_filters}},
    }

    stats = os_post(
        os_url + f"/{index_pattern}/_search",
        HTTPBasicAuth(os_user, os_pass),
        os_verify,
        search_body
    )

    first_value = 228654752
    hits = stats.get("hits", {}).get("hits", [])
    if len(hits) < 2:
        print("Need at least 2 recent docs in last 10m to compute delta. Falling back.", file=sys.stderr)
        delta = fallback_delta
        second_value = first_value + delta
    else:
        v1 = hits[0].get("_source", {}).get("data", {}).get("log_bytes", None)
        v2 = hits[1].get("_source", {}).get("data", {}).get("log_bytes", None)
        if v1 is None or v2 is None:
            print("Missing data.log_bytes in recent docs. Falling back.", file=sys.stderr)
            delta = fallback_delta
            second_value = first_value + delta
        else:
            first_value = int(v1)
            second_value = int(v2)
            delta = first_value - second_value
            if delta <= 0:
                delta = fallback_delta
                second_value = first_value + delta

    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=minutes)

    index_name = f"wazuh-ad-log-volume-{now.strftime('%Y.%m.%d')}"
    bulk_url = os_url + "/_bulk"

    total_points = max(1, (minutes * 60) // step_s)
    start_value = first_value - delta * (total_points - 1)

    lines = []
    for i in range(total_points):
        ts = start + timedelta(seconds=i * step_s)
        val = start_value + delta * i
        if val < 0:
            val = 0

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
        "predecoder": {"program_name": program}
    }
    lines.append(json.dumps({"index": {"_index": index_name}}))
    lines.append(json.dumps(doc2))

    payload = "\n".join(lines) + "\n"

    r = requests.post(
        bulk_url,
        data=payload.encode("utf-8"),
        headers={"Content-Type": "application/x-ndjson"},
        auth=HTTPBasicAuth(os_user, os_pass),
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