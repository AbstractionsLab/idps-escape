#!/usr/bin/env python3
import json
import os
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
import yaml

SCENARIO = "linux_resource_utilization"
DETECTOR_NAME = "LINUX_RESOURCE_UTILIZATION_DETECTOR"
PROGRAM = "resource_usage_metric"
CA_CERT = "config/wazuh_indexer_ssl_certs/root-ca.pem"

SEED_MAPPING = {
    "settings": {"number_of_replicas": 0},
    "mappings": {"properties": {
        "@timestamp": {"type": "date"},
        "timestamp": {"type": "date"},
        "radar_seed": {"type": "boolean"},
        "location": {"type": "keyword"},
        "agent": {"properties": {"id": {"type": "keyword"}, "name": {"type": "keyword"}}},
        "predecoder": {"properties": {"program_name": {"type": "keyword"}}},
        "data": {"properties": {"cpu_usage_pct": {"type": "keyword"}, "mem_usage_pct": {"type": "keyword"}}},
    }},
}


def load_ingest_cfg():
    cfg_path = Path(__file__).resolve().parent.parent / "config.yaml"
    with cfg_path.open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    scn = cfg["scenarios"][SCENARIO]
    return scn["ingest"], scn.get("index_prefix", "wazuh-archives")


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


class OS:
    def __init__(self, url, user, password, verify):
        self.url = url.rstrip("/")
        self.auth = (user, password)
        self.verify = verify

    def request(self, method, path, body=None, ok=(200, 201), **kw):
        r = requests.request(method, f"{self.url}{path}", json=body, auth=self.auth,
                             verify=self.verify, timeout=60, **kw)
        if r.status_code not in ok:
            raise RuntimeError(f"OpenSearch {method} {path} failed {r.status_code}: {r.text[:500]}")
        return r

    def search(self, index, body):
        return self.request("POST", f"/{index}/_search", body).json()


def agent_ids(os_client, pattern, window, agent_names):
    """Agents with real (non-seed) samples in the window: {agent_name: agent_id}."""
    filters = [{"exists": {"field": "data.mem_usage_pct"}},
               {"range": {"@timestamp": {"gte": window}}}]
    if agent_names:
        filters.append({"terms": {"agent.name": agent_names}})
    body = {"size": 0, "query": {"bool": {"filter": filters, "must_not": [{"term": {"radar_seed": True}}]}},
            "aggs": {"agents": {"terms": {"field": "agent.name", "size": 500},
                                "aggs": {"recent": {"top_hits": {
                                    "size": 1, "sort": [{"@timestamp": "desc"}],
                                    "_source": ["agent.id"]}}}}}}
    res = os_client.search(pattern, body)
    out = {}
    for b in res.get("aggregations", {}).get("agents", {}).get("buckets", []):
        hits = b["recent"]["hits"]["hits"]
        out[b["key"]] = str(hits[0]["_source"].get("agent", {}).get("id", "")) if hits else ""
    return out


def earliest_sample(os_client, pattern, agent_name):
    body = {"size": 1, "sort": [{"@timestamp": "asc"}], "_source": ["@timestamp"],
            "query": {"bool": {"filter": [{"exists": {"field": "data.mem_usage_pct"}},
                                          {"term": {"agent.name": agent_name}}]}}}
    hits = os_client.search(pattern, body).get("hits", {}).get("hits", [])
    return parse_ts(hits[0]["_source"]["@timestamp"]) if hits else None


def value(base, jitter, rng):
    if jitter <= 0:
        return base
    return min(100.0, max(0.0, rng.gauss(base, jitter)))


def generate_docs(agent_name, agent_id, start, end, step_s, cpu, mem, rng):
    docs = []
    t = start
    while t < end:
        c = value(cpu[0], cpu[1], rng)
        m = value(mem[0], mem[1], rng)
        ts = iso(t)
        docs.append({
            "@timestamp": ts, "timestamp": ts, "radar_seed": True, "location": "radar-ingest-seed",
            "agent": {"id": agent_id, "name": agent_name},
            "predecoder": {"program_name": PROGRAM},
            "data": {"cpu_usage_pct": f"{c:.2f}", "mem_usage_pct": f"{m:.2f}"},
        })
        t += timedelta(seconds=step_s)
    return docs


def ensure_index(os_client, index):
    r = os_client.request("HEAD", f"/{index}", ok=(200, 404))
    if r.status_code == 404:
        os_client.request("PUT", f"/{index}", SEED_MAPPING)
        print(f"Created seed index {index}")


def bulk(os_client, index, docs, chunk=5000):
    for i in range(0, len(docs), chunk):
        lines = []
        for d in docs[i:i + chunk]:
            lines.append(json.dumps({"index": {"_index": index}}))
            lines.append(json.dumps(d))
        r = os_client.request("POST", "/_bulk?refresh=wait_for", data=("\n".join(lines) + "\n").encode(),
                              headers={"Content-Type": "application/x-ndjson"})
        resp = r.json()
        if resp.get("errors"):
            bad = [it for it in resp.get("items", []) if list(it.values())[0].get("error")]
            raise RuntimeError(f"Bulk completed with {len(bad)} failed items, e.g. {json.dumps(bad[:2])[:800]}")


def stop_detector(os_client):
    body = {"query": {"match_phrase": {"name": DETECTOR_NAME}}, "size": 1}
    r = os_client.request("POST", "/_plugins/_anomaly_detection/detectors/_search", body, ok=(200, 404))
    hits = r.json().get("hits", {}).get("hits", []) if r.status_code == 200 else []
    if not hits:
        return None
    det_id = hits[0]["_id"]
    os_client.request("POST", f"/_plugins/_anomaly_detection/detectors/{det_id}/_stop", ok=(200, 400, 404))
    return det_id


def main():
    os_url = os.environ.get("OS_URL", "")
    os_user = os.environ.get("OS_USER", "")
    os_pass = os.environ.get("OS_PASS", "")
    if not os_url or not os_user or not os_pass:
        print("Missing OS_URL / OS_USER / OS_PASS in the environment.", file=sys.stderr)
        sys.exit(2)
    verify_on = os.environ.get("OS_VERIFY_SSL", "true").lower() in ("1", "true", "yes", "on")
    verify = CA_CERT if verify_on and Path(CA_CERT).is_file() else verify_on
    os_client = OS(os_url, os_user, os_pass, verify)

    cfg, index_prefix = load_ingest_cfg()
    pattern = f"{index_prefix}-*"
    seed_index = str(cfg["seed_index"])
    history = timedelta(minutes=int(cfg["history_minutes"]))
    step_s = int(cfg["step_seconds"])
    names = [str(n) for n in (cfg.get("agent_names") or [])]
    cpu = (float(cfg["baseline_cpu_pct"]), float(cfg["cpu_jitter"]))
    mem = (float(cfg["baseline_mem_pct"]), float(cfg["mem_jitter"]))

    ids = agent_ids(os_client, pattern, str(cfg["baseline_window"]), names)
    targets = names or sorted(ids)
    if not targets:
        print(f"ERROR: no {PROGRAM} samples in {pattern} within {cfg['baseline_window']} and no "
              f"agent_names configured. Check:\n"
              f"  1. The agent is enrolled in the {SCENARIO} group and its "
              f"radar-linux-resource-utilization.timer is running.\n"
              f"  2. /var/log/radar/resource_usage_metric.log on the endpoint is growing.\n"
              f"  3. ./radar.sh health --scenario {SCENARIO} reports no FAIL.", file=sys.stderr)
        sys.exit(1)

    now = datetime.now(timezone.utc)
    all_docs, summary = [], []
    for name in targets:
        if name not in ids:
            print(f"WARNING: no recent samples for '{name}'; seeding it with an empty agent.id.",
                  file=sys.stderr)
        first = earliest_sample(os_client, pattern, name)
        start = now - history
        end = min(first, now) if first else now
        if end - start < timedelta(seconds=step_s):
            summary.append(f"  {name}: already has {history} of history, skipped")
            continue
        docs = generate_docs(name, ids.get(name, ""), start, end, step_s, cpu, mem, random.Random(name))
        all_docs.extend(docs)
        summary.append(f"  {name}: {len(docs)} docs {iso(start)} -> {iso(end)} "
                       f"(cpu {cpu[0]:.2f}±{cpu[1]:.2f}, mem {mem[0]:.2f}±{mem[1]:.2f})")

    if all_docs:
        ensure_index(os_client, seed_index)
        bulk(os_client, seed_index, all_docs)
    print(f"Seed index: {seed_index}")
    print("\n".join(summary))
    print(f"Ingested {len(all_docs)} docs")

    det_id = stop_detector(os_client) if all_docs else None
    if det_id:
        print(f"Stopped detector {det_id} so it re-initialises on the seeded history at its next start.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, requests.RequestException) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)