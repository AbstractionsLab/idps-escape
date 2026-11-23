#!/usr/bin/env python3
"""Phase 0 checks for the RADAR off-hours redesign.

Read-only against the cluster, except check 8, which creates and then deletes
throwaway objects named radar-p0-* (two pipelines, one legacy template, two
indices). Pass --no-write to skip check 8.

Usage (from the repo root):
    poetry run python radar/radar-test-framework/checks/off_hours_phase0.py --env radar/.env [--no-write]

OS_URL / OS_USER / OS_PASS / OS_VERIFY_SSL already set in the environment win
over the .env file. Credentials are never printed.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

import requests
import urllib3

ENV_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
USER_FIELDS = ["data.user", "data.dstuser", "data.srcuser", "data.win.eventdata.targetUserName", "data.office365.UserId", "data.username"]
P0 = "radar-p0"


def load_env(path: Path) -> None:
    if not path.exists():
        print(f"[i] {path} not found; using the process environment only")
        return
    for line in path.read_text().splitlines():
        m = ENV_RE.match(line.strip())
        if not m or line.strip().startswith("#"):
            continue
        val = m.group(2).strip()
        if val[:1] in ("'", '"'):
            val = val[1:].split(val[0], 1)[0]
        else:
            val = re.split(r"\s+#", val, maxsplit=1)[0].strip()
        os.environ.setdefault(m.group(1), val)


class OS:
    def __init__(self):
        self.base = os.environ.get("OS_URL", "").rstrip("/")
        if not self.base:
            sys.exit("[!] OS_URL is not set")
        self.s = requests.Session()
        self.s.auth = (os.environ.get("OS_USER", ""), os.environ.get("OS_PASS", ""))
        self.verify = os.environ.get("OS_VERIFY_SSL", "true").lower() in ("1", "true", "yes", "on")
        if not self.verify:
            urllib3.disable_warnings()

    def req(self, method, path, body=None, ok=(200, 201)):
        r = self.s.request(method, f"{self.base}/{path.lstrip('/')}", json=body, verify=self.verify, timeout=60)
        try:
            data = r.json()
        except ValueError:
            data = r.text
        return r.status_code, data


def section(title):
    print(f"\n=== {title} ===")


def show(obj, limit=4000):
    text = json.dumps(obj, indent=1, default=str) if not isinstance(obj, str) else obj
    print(text if len(text) <= limit else text[:limit] + f"\n... [truncated {len(text) - limit} chars]")


# Reference script from the spec, unchanged except that it reads params the same way.
SPEC_SCRIPT = """
def user = ctx.data?.user;
if (user == null) { return; }
String key = user.toString().toLowerCase();
String g = params.users.containsKey(key) ? params.users.get(key) : params.default_group;
def cfg = params.groups.get(g);
ZonedDateTime t = ZonedDateTime.parse(ctx['@timestamp'].toString()).withZoneSameInstant(ZoneId.of(cfg.tz));
int m = t.getHour() * 60 + t.getMinute();
int dow = t.getDayOfWeek().getValue();
int start = cfg.start; int end = cfg.end;
boolean inHours; int shiftDow = dow;
if (start < end) { inHours = m >= start && m < end; }
else { inHours = m >= start || m < end; if (m < end) { shiftDow = dow == 1 ? 7 : dow - 1; } }
boolean workday = cfg.workdays.contains(shiftDow);
ctx.off_hours = (inHours && workday) ? 0 : 1;
ctx.schedule_group = g;
"""

# Candidate replacement: user from a field list, +0000 offsets, epoch millis, no regex.
ROBUST_SCRIPT = """
def d = ctx.data;
if (d == null) { return; }
def user = null;
for (String f : params.user_fields) { def v = d.get(f); if (v != null && v.toString().length() > 0) { user = v; break; } }
if (user == null) { return; }
String key = user.toString().toLowerCase();
String g = params.users.containsKey(key) ? params.users.get(key) : params.default_group;
if (g == null) { return; }
def cfg = params.groups.get(g);
def ts = ctx['@timestamp'];
ZonedDateTime t;
if (ts instanceof Number) { t = Instant.ofEpochMilli(((Number) ts).longValue()).atZone(ZoneId.of('UTC')); }
else {
  String s = ts.toString(); int n = s.length();
  if (n > 5) { char c = s.charAt(n - 5); if ((c == (char) '+' || c == (char) '-') && s.indexOf(':', n - 5) < 0) { s = s.substring(0, n - 2) + ':' + s.substring(n - 2); } }
  t = ZonedDateTime.parse(s);
}
t = t.withZoneSameInstant(ZoneId.of(cfg.tz));
int m = t.getHour() * 60 + t.getMinute();
int dow = t.getDayOfWeek().getValue();
int start = cfg.start; int end = cfg.end;
boolean inHours; int shiftDow = dow;
if (start < end) { inHours = m >= start && m < end; }
else { inHours = m >= start || m < end; if (m < end) { shiftDow = dow == 1 ? 7 : dow - 1; } }
if (ctx.radar == null) { ctx.radar = new HashMap(); }
ctx.radar.user = key;
ctx.radar.off_hours = (inHours && cfg.workdays.contains(shiftDow)) ? 0 : 1;
ctx.radar.schedule_group = g;
"""

PARAMS = {
    "user_fields": ["user", "srcuser", "dstuser"],
    "default_group": "day",
    "users": {"bob": "day", "oscar": "late", "trent": "admin"},
    "groups": {
        "day": {"tz": "UTC", "start": 480, "end": 1140, "workdays": [1, 2, 3, 4, 5]},
        "late": {"tz": "UTC", "start": 960, "end": 180, "workdays": [1, 2, 3, 4, 5]},
        "admin": {"tz": "Europe/Luxembourg", "start": 480, "end": 1140, "workdays": [1, 2, 3, 4, 5]},
    },
}


def simulate(os_, script, docs, label):
    body = {
        "pipeline": {"processors": [{"script": {"lang": "painless", "source": script, "params": PARAMS, "on_failure": [{"set": {"field": "radar_p0_error", "value": "{{ _ingest.on_failure_message }}"}}]}}]},
        "docs": [{"_source": d} for d in docs],
    }
    code, data = os_.req("POST", "_ingest/pipeline/_simulate", body)
    print(f"[{label}] HTTP {code}")
    if code != 200:
        show(data)
        return
    for d, res in zip(docs, data.get("docs", [])):
        src = (res.get("doc") or {}).get("_source") or {}
        out = {k: src.get(k) for k in ("off_hours", "schedule_group", "radar", "radar_p0_error") if k in src}
        print(f"  in @timestamp={d.get('@timestamp')!r} user={(d.get('data') or {})} -> {out or res.get('error')}")


def check_reroute(os_: OS) -> None:
    """Mimic Filebeat: the request names a pipeline and targets one index; the
    pipeline moves the document to another index (as Wazuh's date_index_name
    does), whose template sets index.final_pipeline. Does the final pipeline run?"""
    section("8. Does index.final_pipeline run for a document rerouted by the request pipeline?")
    routes = {
        # Same processor and timestamp format as filebeat-7.10.2-wazuh-archives-pipeline.
        "date_index_name": {"date_index_name": {"field": "timestamp", "date_rounding": "d", "index_name_prefix": f"{P0}-tgt-dn-", "index_name_format": "yyyy.MM.dd", "ignore_failure": False}},
        "set _index": {"set": {"field": "_index", "value": f"{P0}-tgt-set"}},
    }
    try:
        code, r = os_.req("PUT", f"_ingest/pipeline/{P0}-final", {"processors": [{"set": {"field": "p0_final_ran", "value": True}}]})
        print(f"  final pipeline PUT: HTTP {code}")
        code, r = os_.req("PUT", f"_template/{P0}-tpl", {"index_patterns": [f"{P0}-tgt-*"], "order": 1, "settings": {"index.final_pipeline": f"{P0}-final", "number_of_replicas": 0}})
        print(f"  legacy template PUT: HTTP {code}")
        for i, (label, proc) in enumerate(routes.items()):
            code, r = os_.req("PUT", f"_ingest/pipeline/{P0}-route-{i}", {"processors": [proc]})
            print(f"  [{label}] route pipeline PUT: HTTP {code}")
            code, r = os_.req("POST", f"{P0}-src-{i}/_doc?pipeline={P0}-route-{i}&refresh=true", {"timestamp": "2026-11-20T10:00:00.123+0000", "v": label})
            print(f"  [{label}] write to {P0}-src-{i}: HTTP {code} -> {r.get('_index') if isinstance(r, dict) and '_index' in r else str(r)[:400]}")
        code, r = os_.req("POST", f"{P0}-*/_search", {"query": {"match_all": {}}})
        for h in (r.get("hits") or {}).get("hits", []) if code == 200 else []:
            print(f"  doc v={h['_source'].get('v')!r} landed in {h['_index']}: p0_final_ran={h['_source'].get('p0_final_ran', False)}")
        os_.req("POST", f"{P0}-tgt-direct/_doc?refresh=true", {"v": "direct"})
        code, r = os_.req("POST", f"{P0}-tgt-direct/_search", {"query": {"match_all": {}}})
        for h in (r.get("hits") or {}).get("hits", []) if code == 200 else []:
            print(f"  control: direct write to {h['_index']}: p0_final_ran={h['_source'].get('p0_final_ran', False)}")
    finally:
        cleanup = [("DELETE", f"{P0}-src-*"), ("DELETE", f"{P0}-tgt-*"), ("DELETE", f"_template/{P0}-tpl"), ("DELETE", f"_ingest/pipeline/{P0}-final")]
        cleanup += [("DELETE", f"_ingest/pipeline/{P0}-route-{i}") for i in range(len(routes))]
        for method, path in cleanup:
            code, _ = os_.req(method, path)
            print(f"  cleanup {method} {path}: HTTP {code}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--env", default=".env")
    ap.add_argument("--no-write", action="store_true", help="skip check 8 (throwaway final_pipeline test)")
    ap.add_argument("--only-reroute", action="store_true", help="run only check 8")
    args = ap.parse_args()
    load_env(Path(args.env))
    os_ = OS()
    print(f"[i] OS_URL={os_.base} verify_ssl={os_.verify}")
    if args.only_reroute:
        check_reroute(os_)
        print("\n[done] Paste everything above back into the conversation.")
        return

    section("1. Versions and plugins")
    code, root = os_.req("GET", "/")
    show({"http": code, "version": (root.get("version") if isinstance(root, dict) else root)})
    code, plugins = os_.req("GET", "_cat/plugins?format=json")
    if code == 200:
        show(sorted({(p.get("component"), p.get("version")) for p in plugins}))

    section("2. Templates matching wazuh-archives")
    code, legacy = os_.req("GET", "_template")
    if code == 200:
        for name, t in legacy.items():
            pats = t.get("index_patterns", [])
            if any("archives" in p or p in ("*", "wazuh-*") for p in pats):
                s = t.get("settings", {}).get("index", {})
                props = (t.get("mappings") or {}).get("properties", {})
                print(
                    f"  legacy {name}: order={t.get('order')} patterns={pats} "
                    f"default_pipeline={s.get('default_pipeline')} final_pipeline={s.get('final_pipeline')} "
                    f"dynamic_templates={[list(x)[0] for x in (t.get('mappings') or {}).get('dynamic_templates', [])]} "
                    f"data.user mapped={'user' in (props.get('data', {}).get('properties', {}))}"
                )
    code, comp = os_.req("GET", "_index_template")
    if code == 200:
        for it in comp.get("index_templates", []):
            pats = it["index_template"].get("index_patterns", [])
            print(f"  composable {it['name']}: patterns={pats} priority={it['index_template'].get('priority')}" + ("   <-- MATCHES ARCHIVES" if any("archives" in p or p in ("*", "wazuh-*") for p in pats) else ""))

    section("3. Archive indices")
    code, idx = os_.req("GET", "_cat/indices/wazuh-archives-*?format=json&h=index,docs.count,store.size&s=index")
    if code == 200:
        fams = {}
        for i in idx:
            fam = re.sub(r"\d{4}\.\d{2}\.\d{2}$", "YYYY.MM.DD", i["index"])
            f = fams.setdefault(fam, {"indices": 0, "docs": 0, "last": None})
            f["indices"] += 1
            f["docs"] += int(i.get("docs.count") or 0)
            f["last"] = i["index"]
        show(fams)
        code, sett = os_.req("GET", "wazuh-archives-*/_settings/index.default_pipeline,index.final_pipeline")
        if code == 200:
            pipes = {k: v.get("settings") for k, v in sett.items() if v.get("settings")}
            print(f"  indices with default/final pipeline set: {pipes or 'none'}")
    else:
        show(idx)

    section("4. Field mappings per archive family")
    fields = ",".join(USER_FIELDS + [f + ".keyword" for f in USER_FIELDS] + ["data.action", "data.action.keyword", "@timestamp", "timestamp", "rule.id", "radar.*", "off_hours", "schedule_group"])
    code, maps = os_.req("GET", f"wazuh-archives-*/_mapping/field/{fields}")
    if code == 200:
        summary = {}
        for index, m in maps.items():
            fam = re.sub(r"\d{4}\.\d{2}\.\d{2}$", "YYYY.MM.DD", index)
            for fname, fm in (m.get("mappings") or {}).items():
                leaf = list((fm.get("mapping") or {}).values())
                typ = leaf[0].get("type") if leaf else "?"
                summary.setdefault(fam, {}).setdefault(fname, set()).add(typ)
        show({fam: {k: sorted(v) for k, v in sorted(d.items())} for fam, d in summary.items()})
    else:
        show(maps)

    section("5. Which user fields real events carry (wazuh-archives-4.x-*, last 7 days)")
    rng = {"range": {"@timestamp": {"gte": "now-7d"}}}
    for f in USER_FIELDS + ["rule.id"]:
        code, c = os_.req("POST", "wazuh-archives-4.x-*/_count", {"query": {"bool": {"filter": [rng, {"exists": {"field": f}}]}}})
        print(f"  exists {f}: {c.get('count') if code == 200 else c}")
    for f in ("data.dstuser", "data.srcuser", "data.user"):
        code, r = os_.req("POST", "wazuh-archives-4.x-*/_search", {"size": 0, "query": {"bool": {"filter": [rng]}}, "aggs": {"u": {"terms": {"field": f, "size": 15}, "aggs": {"dec": {"terms": {"field": "decoder.name", "size": 3}}}}}})
        if code == 200:
            buckets = r.get("aggregations", {}).get("u", {}).get("buckets", [])
            print(f"  top {f}: " + ", ".join(f"{b['key']}={b['doc_count']} ({'/'.join(x['key'] for x in b['dec']['buckets'])})" for b in buckets))
        else:
            print(f"  top {f}: HTTP {code} {str(r)[:300]}")

    section("6. A real archived event with a user, and _simulate of both scripts")
    sample = None
    for f in ("data.dstuser", "data.srcuser", "data.user"):
        code, r = os_.req("POST", "wazuh-archives-4.x-*/_search", {"size": 1, "sort": [{"@timestamp": "desc"}], "query": {"exists": {"field": f}}})
        hits = (r.get("hits") or {}).get("hits", []) if code == 200 else []
        if hits:
            sample = hits[0]["_source"]
            print(
                f"  sample from {hits[0]['_index']} via {f}: @timestamp={sample.get('@timestamp')!r} timestamp={sample.get('timestamp')!r} "
                f"decoder={sample.get('decoder', {}).get('name')} data_keys={sorted((sample.get('data') or {}).keys())[:20]}"
            )
            break
    if sample is None:
        print("  no real archived event with a user field found")
    docs = []
    if sample:
        real = json.loads(json.dumps(sample))
        docs.append(real)
        as_bob = json.loads(json.dumps(sample))
        as_bob.setdefault("data", {})["user"] = "bob"
        docs.append(as_bob)
    for ts in ("2026-09-18T02:05:00Z", "2026-09-18T02:05:00+00:00", "2026-09-18T02:05:00.123+0000", "2026-03-30T06:30:00.000Z", "not-a-date"):
        user = "trent" if ts.startswith("2026-03") else "bob"
        docs.append({"@timestamp": ts, "data": {"user": user}})
    docs.append({"@timestamp": "2026-09-15T01:30:00Z", "data": {"dstuser": "oscar"}})
    docs.append({"@timestamp": "2026-09-16T12:00:00Z", "data": {"srcip": "1.2.3.4"}})
    simulate(os_, SPEC_SCRIPT, docs, "spec script")
    simulate(os_, ROBUST_SCRIPT, docs, "robust script")

    section("7. Ingest pipelines (Filebeat) and pipeline-processor options")
    code, pipes = os_.req("GET", "_ingest/pipeline")
    if code == 200:
        for name, p in pipes.items():
            procs = [list(x)[0] for x in p.get("processors", [])]
            print(f"  {name}: {len(procs)} processors; last={procs[-3:]}; has pipeline/script={[x for x in procs if x in ('pipeline', 'script')]}")
    code, r = os_.req("POST", "_ingest/pipeline/_simulate", {"pipeline": {"processors": [{"pipeline": {"name": f"{P0}-does-not-exist", "ignore_missing_pipeline": True}}]}, "docs": [{"_source": {"a": 1}}]})
    print(f"  pipeline processor with ignore_missing_pipeline: HTTP {code} {str(r)[:300]}")
    code, r = os_.req("POST", "_ingest/pipeline/_simulate", {"pipeline": {"processors": [{"pipeline": {"name": f"{P0}-does-not-exist", "ignore_failure": True}}]}, "docs": [{"_source": {"a": 1}}]})
    print(f"  pipeline processor to missing pipeline with ignore_failure: HTTP {code} {str(r)[:300]}")

    if args.no_write:
        section("8. Does index.final_pipeline run for a document rerouted by the request pipeline?")
        print("  skipped (--no-write)")
    else:
        check_reroute(os_)

    section("9. Existing detectors and monitors")
    code, r = os_.req("POST", "_plugins/_anomaly_detection/detectors/_search", {"size": 50, "query": {"match_all": {}}})
    for h in (r.get("hits") or {}).get("hits", []) if code == 200 else []:
        d = h["_source"]
        _, st = os_.req("GET", f"_plugins/_anomaly_detection/detectors/{h['_id']}/_profile/state")
        print(
            f"  {d.get('name')} ({h['_id']}): state={st.get('state') if isinstance(st, dict) else st} indices={d.get('indices')} "
            f"category={d.get('category_field')} interval={d.get('detection_interval')} shingle={d.get('shingle_size')} "
            f"features={[f.get('feature_name') for f in d.get('feature_attributes', [])]}"
        )
    if code != 200:
        print(f"  detector search: HTTP {code} {str(r)[:300]}")
    code, r = os_.req("POST", "_plugins/_alerting/monitors/_search", {"size": 50, "query": {"match_all": {}}})
    for h in (r.get("hits") or {}).get("hits", []) if code == 200 else []:
        m = h["_source"].get("monitor") or h["_source"]
        if m.get("name"):
            print(f"  monitor {m.get('name')}: type={m.get('monitor_type')} enabled={m.get('enabled')}")

    section("10. AD validation of a model-mode detector shape (read-only _validate)")
    for idx, cat in (("wazuh-archives-*", "data.user.keyword"), ("wazuh-archives-4.x-*", "data.dstuser")):
        spec = {
            "name": f"{P0}-validate",
            "time_field": "@timestamp",
            "indices": [idx],
            "shingle_size": 1,
            "category_field": [cat],
            "filter_query": {"match_all": {}},
            "detection_interval": {"period": {"interval": 30, "unit": "Minutes"}},
            "window_delay": {"period": {"interval": 10, "unit": "Minutes"}},
            "feature_attributes": [{"feature_name": "n", "feature_enabled": True, "aggregation_query": {"n": {"value_count": {"field": "@timestamp"}}}}],
        }
        code, r = os_.req("POST", "_plugins/_anomaly_detection/detectors/_validate/detector", spec)
        print(f"  {idx} category={cat} shingle=1: HTTP {code} {json.dumps(r)[:600]}")

    print("\n[done] Paste everything above back into the conversation.")


if __name__ == "__main__":
    main()
