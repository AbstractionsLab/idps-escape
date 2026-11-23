#!/usr/bin/env python3
"""Run the off-hours case table through the real ingest pipeline with _simulate.

Read-only: the pipeline is rendered from the table's config and sent inline to
_ingest/pipeline/_simulate, so nothing is stored on the cluster. Each case is
also checked against the Python twin (anomaly_detector/off_hours.py), so a
mismatch between the Painless script and the Python code shows up here.

Usage (from the repo root):
    OS_URL=https://localhost:9200 OS_VERIFY_SSL=false \\
      poetry run python radar/radar-test-framework/checks/off_hours_simulate.py --env radar/.env
Exit status 0 when every case passes.
"""
import argparse
import os
import re
import sys
from pathlib import Path

import requests
import urllib3
import yaml

RADAR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RADAR / "anomaly_detector"))
import off_hours as oh  # noqa: E402

TABLE = RADAR / "tests/py/fixtures/off_hours_cases.yaml"
ENV_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def load_env(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        m = ENV_RE.match(line.strip())
        if not m or line.strip().startswith("#"):
            continue
        val = m.group(2).strip()
        val = val[1:].split(val[0], 1)[0] if val[:1] in ("'", '"') else re.split(r"\s+#", val, maxsplit=1)[0].strip()
        os.environ.setdefault(m.group(1), val)


def expected(case: dict):
    exp = case["expect"]
    if exp in ("absent", "error"):
        return exp
    return {"off_hours": exp["off_hours"], "schedule_group": exp["group"], "user": exp["user"]}


def observed(result: dict):
    if "error" in result:
        return f"processor error: {result['error']}"
    radar = ((result.get("doc") or {}).get("_source") or {}).get("radar")
    if radar is None:
        return "absent"
    if "off_hours_error" in radar:
        return "error"
    return {k: radar.get(k) for k in ("off_hours", "schedule_group", "user")}


def twin(cfg: oh.OffHoursConfig, event: dict):
    try:
        res = cfg.classify(event)
    except oh.OffHoursEventError:
        return "error"
    return "absent" if res is None else res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--env", default=".env")
    args = ap.parse_args()
    load_env(Path(args.env))
    base = os.environ.get("OS_URL", "").rstrip("/")
    if not base:
        sys.exit("[!] OS_URL is not set")
    verify = os.environ.get("OS_VERIFY_SSL", "true").lower() in ("1", "true", "yes", "on")
    if not verify:
        urllib3.disable_warnings()

    table = yaml.safe_load(TABLE.read_text())
    cfg = oh.parse_config(table["config"])
    cases = table["cases"]
    body = {"pipeline": oh.pipeline_body(cfg), "docs": [{"_source": c["event"]} for c in cases]}
    r = requests.post(f"{base}/_ingest/pipeline/_simulate", json=body, auth=(os.environ.get("OS_USER", ""), os.environ.get("OS_PASS", "")), verify=verify, timeout=60)
    print(f"[i] _simulate HTTP {r.status_code}")
    if r.status_code != 200:
        print(r.text[:2000])
        return 2

    failures = 0
    for case, result in zip(cases, r.json().get("docs", [])):
        want, got, py = expected(case), observed(result), twin(cfg, case["event"])
        ok = got == want and py == want
        failures += not ok
        print(f"  {'PASS' if ok else 'FAIL'}  {case['note']}")
        if not ok:
            print(f"        expected={want}\n        painless={got}\n        python={py}")
            if got == "error" or (isinstance(got, str) and got.startswith("processor")):
                print(f"        detail={((result.get('doc') or {}).get('_source') or {}).get('radar', result.get('error'))}")
    print(f"\n[{'ok' if not failures else 'FAILED'}] {len(cases) - failures}/{len(cases)} cases pass")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
