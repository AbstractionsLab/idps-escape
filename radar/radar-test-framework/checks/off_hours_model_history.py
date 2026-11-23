#!/usr/bin/env python3
"""Model-mode check on the synthetic history (spec section 10.4), without waiting for real time.

Runs a historical analysis of the deployed model-mode detector
(SUSPICIOUS_LOGIN_OFF_HOURS_DETECTOR) over the last --days days, then reports:

  1. trent's burst (30 off-hours events at about 02:00 Luxembourg time): the
     detector must give an anomaly grade above 0 in an interval that overlaps it;
  2. trent's ordinary evenings (1-3 events between 21:00 and 24:00 local): the
     target is no anomaly; the number found and their grades are printed;
  3. alice, bob and oscar (rule-mode groups): no results at all, since the
     detector's filter keeps model-mode groups only.

Needs `run-radar.sh suspicious_login --ingest true` first (synthetic history,
backfill, detector). The analysis is a background task; this script waits for it.

Usage (from radar/):
    OS_URL=https://localhost:9200 OS_VERIFY_SSL=false \\
      poetry run python radar-test-framework/checks/off_hours_model_history.py --env .env
Exit status 0 when checks 1 and 3 pass (2 is reported, not enforced).
"""
import argparse
import sys
import time
import zoneinfo
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

RADAR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RADAR / "anomaly_detector"))
import off_hours as oh  # noqa: E402
from detector import load_env  # noqa: E402

ADMIN, ADMIN_TZ = "trent", "Europe/Luxembourg"
RULE_USERS = ("alice", "bob", "oscar")
DONE_STATES = ("FINISHED", "FAILED", "STOPPED", "FINISHED_WITH_ERRORS")


def ms(t: datetime) -> int:
    return int(t.timestamp() * 1000)


def utc(epoch_ms: int) -> datetime:
    return datetime.fromtimestamp(epoch_ms / 1000, timezone.utc)


def local(epoch_ms: int) -> str:
    return utc(epoch_ms).astimezone(zoneinfo.ZoneInfo(ADMIN_TZ)).strftime("%a %Y-%m-%d %H:%M")


def entity_of(src: dict) -> str:
    return next((e.get("value") for e in src.get("entity") or [] if e.get("name") == oh.FIELD_USER), "?")


def burst_windows(cluster: oh.Cluster, start: datetime, end: datetime) -> list[tuple[int, int, int]]:
    """30-minute buckets holding at least 10 of trent's off-hours events: (start ms, end ms, count)."""
    body = {
        "size": 0,
        "query": {"bool": {"filter": [{"term": {oh.FIELD_USER: ADMIN}}, {"term": {oh.FIELD_OFF_HOURS: 1}}, {"range": {"@timestamp": {"gte": ms(start), "lte": ms(end), "format": "epoch_millis"}}}]}},
        "aggs": {"b": {"date_histogram": {"field": "@timestamp", "fixed_interval": "30m", "min_doc_count": 10}}},
    }
    _, res = cluster.call("POST", f"{oh.ARCHIVES_PATTERN}/_search", body)
    return [(b["key"], b["key"] + 30 * 60 * 1000, b["doc_count"]) for b in res["aggregations"]["b"]["buckets"]]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--env", default=".env")
    ap.add_argument("--days", type=int, default=oh.DEFAULT_BACKFILL_DAYS)
    ap.add_argument("--timeout", type=int, default=3600, help="seconds to wait for the analysis")
    args = ap.parse_args()
    load_env(Path(args.env))
    cluster = oh.cluster_from_env()

    det_id = oh._find_detector(cluster, oh.MODEL_DETECTOR_NAME)
    if not det_id:
        print(f"[!] {oh.MODEL_DETECTOR_NAME} not found; run `off_hours.py monitors` (or run-radar.sh suspicious_login) first")
        return 2
    end = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    start = end - timedelta(days=args.days)
    det, running = oh._detector_state(cluster, det_id)
    print(f"[i] detector {det_id}: shingle {det.get('shingle_size')}, interval {det.get('detection_interval')}, real-time job running: {running}")

    try:
        _, started = cluster.call("POST", f"_plugins/_anomaly_detection/detectors/{det_id}/_start", {"start_time": ms(start), "end_time": ms(end)})
    except oh.OpenSearchError as exc:
        print(f"[!] historical analysis refused: {exc}")
        return 2
    task_id = started.get("_id")
    print(f"[i] historical analysis {task_id} over {start:%Y-%m-%d %H:%M} .. {end:%Y-%m-%d %H:%M} UTC")
    deadline = time.monotonic() + args.timeout
    while True:
        _, st = cluster.call("GET", f"_plugins/_anomaly_detection/detectors/{det_id}?task=true")
        task = st.get("historical_analysis_task") or {}
        state, progress = task.get("state"), task.get("task_progress")
        print(f"      state {state}, progress {progress}")
        if state in DONE_STATES:
            break
        if time.monotonic() > deadline:
            print("[!] timed out; the task keeps running, rerun later or raise --timeout")
            return 2
        time.sleep(15)
    if state != "FINISHED":
        print(f"[!] task ended {state}: {task.get('error')}")
    task_id = task.get("task_id") or task_id

    body = {
        "size": 10000,
        "sort": [{"data_start_time": "asc"}],
        "_source": ["entity", "anomaly_grade", "confidence", "data_start_time", "data_end_time", "feature_data"],
        "query": {"bool": {"filter": [{"term": {"detector_id": det_id}}, {"term": {"task_id": task_id}}]}},
    }
    _, res = cluster.call("POST", f"{oh.MODEL_RESULT_INDEX}*/_search", body)
    hits = [h["_source"] for h in res["hits"]["hits"]]
    if res["hits"]["total"]["value"] > len(hits):
        print(f"[!] only the first {len(hits)} of {res['hits']['total']['value']} results are analysed")
    per_user = defaultdict(list)
    for src in hits:
        per_user[entity_of(src)].append(src)
    print(f"[i] {len(hits)} results: " + ", ".join(f"{u} {len(r)} ({sum(1 for x in r if (x.get('anomaly_grade') or 0) > 0)} anomalous)" for u, r in sorted(per_user.items())))

    failures = 0
    print("\n[1] trent's burst")
    bursts = burst_windows(cluster, start, end)
    if not bursts:
        print("  FAIL  no burst of trent's off-hours events in the archives (was the ingest run with the shipped config?)")
        failures += 1
    anomalous = [x for x in per_user.get(ADMIN, []) if (x.get("anomaly_grade") or 0) > 0]
    burst_hits = []
    for b_start, b_end, count in bursts:
        hit = [x for x in anomalous if x["data_start_time"] < b_end and x["data_end_time"] > b_start]
        burst_hits += hit
        ok = bool(hit)
        failures += not ok
        grades = ", ".join(f"{x['anomaly_grade']:.3f} (conf {x.get('confidence', 0):.2f}, count {x['feature_data'][0]['data']:.0f})" for x in hit) or "none"
        print(f"  {'PASS' if ok else 'FAIL'}  burst of {count} events at {local(b_start)} local: grade {grades}")

    print("[2] trent's ordinary evenings (target: no anomaly)")
    evening = [x for x in anomalous if x not in burst_hits and utc(x["data_start_time"]).astimezone(zoneinfo.ZoneInfo(ADMIN_TZ)).hour >= 20]
    other = [x for x in anomalous if x not in burst_hits and x not in evening]
    print(f"  INFO  {len(evening)} anomalous evening interval(s)")
    for x in evening[:20]:
        print(f"        {local(x['data_start_time'])}  grade {x['anomaly_grade']:.3f}  conf {x.get('confidence', 0):.2f}  count {x['feature_data'][0]['data']:.0f}")
    if other:
        print(f"  INFO  {len(other)} other anomalous interval(s), first: " + ", ".join(f"{local(x['data_start_time'])} grade {x['anomaly_grade']:.3f}" for x in other[:5]))

    print("[3] rule-mode users are outside the detector")
    leaked = {u: len(per_user[u]) for u in RULE_USERS if per_user.get(u)}
    ok = not leaked
    failures += not ok
    print(f"  {'PASS' if ok else 'FAIL'}  no results for {', '.join(RULE_USERS)}" + ("" if ok else f": {leaked}"))

    print(f"\n[{'ok' if not failures else 'FAILED'}] {failures} failure(s)")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
