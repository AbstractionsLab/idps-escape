#!/usr/bin/env python3
"""Rule-mode checks on a live cluster (spec section 10.3), without waiting for real time.

The deployed config (config.yaml) plus the test groups and users of the case
table (test_always_off/test_off_user, test_always_on/test_on_user) is rendered
into a temporary pipeline `radar-off-hours-e2e`. Test events go through it into
a temporary index `wazuh-archives-4.x-radar-e2e`. The rule-mode query is then run
against that index with chosen values of {{period_end}}, which replays monitor runs
at those times:

  1. one test_off_user event in the current window -> reported once, count 1
  2. one test_on_user event in the same window -> not reported (flag 0)
  3. three more test_off_user events one interval later -> not reported again
     (the first event is in the quiet period); one event after the quiet period -> reported
  4. bob at 2026-09-18T02:05:00Z (the originally missed event) -> reported, count 1

Then the rule-mode monitor itself runs once inline (`_execute?dryrun=true`, not
saved, nothing sent) on the test index, to check the trigger and the rendered
webhook body. The pipeline and the index are deleted at the end. The deployed
monitor ignores the test groups, so it never reports the test users.

Usage (from radar/):
    OS_URL=https://localhost:9200 OS_VERIFY_SSL=false \\
      poetry run python radar-test-framework/checks/off_hours_rule_e2e.py --env .env
Exit status 0 when every check passes.
"""
import argparse
import copy
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

RADAR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RADAR / "anomaly_detector"))
import off_hours as oh  # noqa: E402
from detector import load_env  # noqa: E402

TABLE = RADAR / "tests/py/fixtures/off_hours_cases.yaml"
PIPELINE = "radar-off-hours-e2e"
INDEX = "wazuh-archives-4.x-radar-e2e"
TEST_GROUPS = ("test_always_off", "test_always_on")
TEST_USERS = ("test_off_user", "test_on_user")


def test_config(config_path: Path) -> oh.OffHoursConfig:
    """The deployed block plus the case table's test groups and users (and bob, for case 4)."""
    raw = copy.deepcopy(((yaml.safe_load(config_path.read_text()) or {}).get("scenarios") or {}).get("suspicious_login", {}).get("off_hours"))
    if not raw:
        sys.exit(f"[!] {config_path}: no {oh.CONFIG_PATH} block")
    table = yaml.safe_load(TABLE.read_text())["config"]
    raw.setdefault("groups", {}).update({g: table["groups"][g] for g in TEST_GROUPS})
    raw["groups"].setdefault("synthetic_day", table["groups"]["synthetic_day"])
    raw.setdefault("users", {}).update({u: table["users"][u] for u in TEST_USERS})
    raw["users"].setdefault("bob", "synthetic_day")
    raw["enabled"] = True
    return oh.parse_config(raw)


def epoch_ms(t: datetime) -> int:
    return int(t.timestamp() * 1000)


def iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def render_query(cfg: oh.OffHoursConfig, period_end: datetime) -> dict:
    """The monitor's query as Alerting runs it at `period_end` ({{period_end}} is epoch millis)."""
    text = json.dumps(oh.rule_monitor_query(cfg)).replace("{{period_end}}", str(epoch_ms(period_end)))
    assert "{{" not in text
    return json.loads(text)


def event(user: str, when: datetime, n: int) -> dict:
    ts = iso(when)
    return {"@timestamp": ts, "timestamp": ts.replace("Z", "+0000"), "agent": {"name": "radar-e2e"}, "decoder": {"name": "sshd"}, "data": {"dstuser": user}, "full_log": f"radar off-hours e2e {user} #{n}"}


class Check:
    def __init__(self) -> None:
        self.failures = 0

    def __call__(self, ok: bool, what: str, detail: str = "") -> None:
        self.failures += not ok
        print(f"  {'PASS' if ok else 'FAIL'}  {what}" + (f"\n        {detail}" if detail and not ok else ""))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--env", default=".env")
    ap.add_argument("--config", default=str(RADAR / "config.yaml"))
    ap.add_argument("--keep", action="store_true", help="keep the test index and pipeline for inspection")
    args = ap.parse_args()
    load_env(Path(args.env))
    cluster = oh.cluster_from_env()
    cfg = test_config(Path(args.config))
    rm = cfg.rule_mode
    check = Check()

    def write(docs: list[dict]) -> None:
        lines = []
        for d in docs:
            lines += [json.dumps({"index": {"_index": INDEX}}), json.dumps(d)]
        r = cluster.session.post(f"{cluster.base}/_bulk?refresh=true&pipeline={PIPELINE}", data="\n".join(lines) + "\n", headers={"Content-Type": "application/x-ndjson"}, verify=cluster.verify, timeout=cluster.timeout)
        r.raise_for_status()
        if r.json().get("errors"):
            raise oh.OpenSearchError(f"bulk errors: {json.dumps(r.json()['items'][:2])}")

    def run_at(period_end: datetime) -> dict:
        _, res = cluster.call("POST", f"{INDEX}/_search", render_query(cfg, period_end))
        return {b["key"]: b for b in res["aggregations"]["users"]["buckets"]}

    # Mid-window offset: events this far before a run are inside its current window.
    mid = timedelta(minutes=rm.delay_minutes + rm.interval_minutes / 2)
    p0 = datetime.now(timezone.utc).replace(microsecond=0)
    p1 = p0 + timedelta(minutes=rm.interval_minutes)
    p3 = p1 + timedelta(minutes=rm.quiet_minutes + rm.interval_minutes + rm.delay_minutes)
    bob_at = datetime(2026, 9, 18, 2, 5, tzinfo=timezone.utc)
    print(f"[i] rule mode: interval {rm.interval_minutes} min, delay {rm.delay_minutes} min, quiet {rm.quiet_minutes} min, min_events {rm.min_events}")
    print(f"[i] runs replayed at {iso(p0)} (now), {iso(p1)} (+1 interval), {iso(p3)} (after the quiet period)")

    try:
        cluster.call("DELETE", INDEX, allow=(404,))
        cluster.call("PUT", f"_ingest/pipeline/{PIPELINE}", oh.pipeline_body(cfg))
        write(
            [event("test_off_user", p0 - mid, 1), event("test_on_user", p0 - mid, 1)] + [event("test_off_user", p1 - mid + timedelta(seconds=10 * i), 2 + i) for i in range(3)] + [event("test_off_user", p3 - mid, 5), event("bob", bob_at, 1)]
        )
        _, flags = cluster.call("POST", f"{INDEX}/_search", {"size": 20, "_source": ["radar", "@timestamp"], "sort": [{"@timestamp": "asc"}]})
        print("[i] flags written by the pipeline:")
        for h in flags["hits"]["hits"]:
            print(f"      {h['_source']['@timestamp']}  {json.dumps(h['_source'].get('radar'))}")

        print("\n[1] one off-hours event now")
        now = run_at(p0)
        b = now.get("test_off_user")
        check(b is not None and b["now"]["doc_count"] == 1, "test_off_user is reported with count 1", json.dumps(now))
        check(b is not None and b["group"]["buckets"][0]["key"] == "test_always_off", "the report names the schedule group")

        print("[2] one on-hours event now")
        on_flag = [h["_source"]["radar"]["off_hours"] for h in flags["hits"]["hits"] if h["_source"]["radar"]["user"] == "test_on_user"]
        check(on_flag == [0], "test_on_user's event is flagged 0", str(on_flag))
        check("test_on_user" not in now, "test_on_user is not reported")

        print("[3] three more events one interval later, then one after the quiet period")
        later = run_at(p1)
        check("test_off_user" not in later, "no second notification while the burst goes on", json.dumps(later.get("test_off_user")))
        after = run_at(p3)
        b3 = after.get("test_off_user")
        check(b3 is not None and b3["now"]["doc_count"] == 1, "reported again after the quiet period", json.dumps(after))

        print("[4] bob at 2026-09-18T02:05:00Z (the originally missed event)")
        old = run_at(bob_at + mid)
        b4 = old.get("bob")
        check(b4 is not None and b4["now"]["doc_count"] == 1, "bob is reported with count 1", json.dumps(old))
        check(b4 is not None and b4["now"]["first"].get("value_as_string", "").startswith("2026-09-18T02:05"), "first event time is 02:05")

        print("[5] the monitor itself, run inline on the test index (dry run, nothing sent)")
        existing = oh.monitor_mod.find_monitor(cluster.session, cluster.base, oh.RULE_MONITOR_NAME, cluster.verify)
        if not existing:
            check(False, f"{oh.RULE_MONITOR_NAME} is deployed", "run `off_hours.py monitors` first; it supplies the webhook channel id")
        else:
            _, deployed = cluster.call("GET", f"_plugins/_alerting/monitors/{existing[0]}")
            trig = deployed["monitor"]["triggers"][0]
            dest = (trig.get("query_level_trigger") or trig)["actions"][0]["destination_id"]
            payload = oh.rule_monitor_payload(cfg, dest)
            payload["inputs"][0]["search"]["indices"] = [INDEX]
            _, res = cluster.call("POST", "_plugins/_alerting/monitors/_execute?dryrun=true", payload)
            triggered = [t.get("triggered") for t in (res.get("trigger_results") or {}).values()]
            messages = [json.loads(m) for m in oh._messages(res.get("trigger_results") or {})]
            check((res.get("input_results") or {}).get("error") is None, "the query runs", str((res.get("input_results") or {}).get("error")))
            check(triggered == [True], "the trigger fires", str(triggered))
            items = [a for m in messages for a in m.get("anomalies", []) if a]
            mine = [a for a in items if a.get("entity") == "test_off_user"]
            check(len(mine) == 1 and mine[0].get("off_hours_count") == "1" and mine[0].get("schedule_group") == "test_always_off", "the webhook body carries user, count and group", json.dumps(messages))
            if mine:
                print(f"        rendered item: {json.dumps(mine[0])}")
            check(all(re.fullmatch(r"\d{4}-\d\d-\d\dT[\d:.]+Z", str(a.get("dataStart", ""))) for a in mine), "dataStart is an ISO time")
    except oh.OpenSearchError as exc:
        print(f"[!] {exc}")
        return 2
    finally:
        if not args.keep:
            cluster.call("DELETE", INDEX, allow=(404,))
            cluster.call("DELETE", f"_ingest/pipeline/{PIPELINE}", allow=(404,))
            print(f"\n[i] removed {INDEX} and pipeline {PIPELINE}")
    print(f"\n[{'ok' if not check.failures else 'FAILED'}] {check.failures} failure(s)")
    return 0 if not check.failures else 1


if __name__ == "__main__":
    sys.exit(main())
