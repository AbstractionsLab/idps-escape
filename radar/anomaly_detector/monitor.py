#!/usr/bin/env python3

import os, sys, json, yaml, requests
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from webhook import ensure_webhook

def die(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    sys.exit(code)

def load_env(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())

def load_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        die(f"config.yaml not found at {path}")
    with path.open() as f:
        return yaml.safe_load(f) or {}

def make_session(user: str, pwd: str) -> requests.Session:
    s = requests.Session()
    if user or pwd:
        s.auth = (user, pwd)
    s.headers.update({
        "Content-Type": "application/json",
    })
    return s

def pick_scenario(cfg: Dict[str, Any], arg_name: Optional[str]) -> Tuple[str, Dict[str, Any]]:
    scenarios = cfg.get("scenarios") or {}
    name = arg_name or cfg.get("default_scenario")
    if not name:
        die("Provide SCENARIO or set default_scenario in config.yaml")
    if name not in scenarios:
        die(f"Scenario '{name}' not found in config.yaml")
    return name, scenarios[name]

def _extract_detector_id(mon: Dict[str, Any]) -> Optional[str]:
    try:
        for inp in (mon.get("inputs") or []):
            search = inp.get("search") or inp
            bool_clause = (search.get("query") or {}).get("bool") or {}
            clauses = []
            for key in ("filter", "must", "should"):
                val = bool_clause.get(key)
                if isinstance(val, list):
                    clauses.extend(val)
                elif isinstance(val, dict):
                    clauses.append(val)
            for clause in clauses:
                term = clause.get("term") or {}
                if "detector_id" in term:
                    val = term["detector_id"]
                    return val["value"] if isinstance(val, dict) else val
    except (KeyError, IndexError, TypeError, AttributeError):
        pass
    return None

def find_monitor(session: requests.Session, opensearch_base: str, name: str, verify: bool) -> Optional[Tuple[str, Optional[str]]]:
    url = f"{opensearch_base.rstrip('/')}/_plugins/_alerting/monitors/_search"
    body = {"query": {"match": {"monitor.name": name}}}
    r = session.post(url, json=body, verify=verify)
    if r.status_code == 404:
        return None
    if r.status_code != 200:
        die(f"Monitor search failed: {r.status_code} {r.text}")
    for hit in (r.json().get("hits") or {}).get("hits", []):
        src = hit.get("_source") or {}
        mon = src.get("monitor") or src
        if mon.get("name") == name:
            return hit.get("_id"), _extract_detector_id(mon)
    return None

def monitor_payload(scenario_name: str, scn: Dict[str, Any], detector_id: str, destination_id: str) -> Dict[str, Any]:
    interval = int(scn.get("monitor_interval", scn.get("detector_interval", 5)))
    grade_th = float(scn.get("anomaly_grade_threshold", 0.2))
    conf_th  = float(scn.get("confidence_threshold", 0.2))

    result_index = scn.get("result_index")

    trigger_name = scn.get("trigger_name", f"{scenario_name}-trigger")
    monitor_name = scn.get("monitor_name", f"{scenario_name}-monitor")

    query = {
        "size": 1,
        "sort": [{"anomaly_grade": "desc"}, {"confidence": "desc"}],
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "execution_end_time": {
                                "from": f"{{{{period_end}}}}||-{interval}m",
                                "to": "{{period_end}}",
                                "include_lower": True,
                                "include_upper": True
                            }
                        }
                    },
                    {"term": {"detector_id": {"value": detector_id}}}
                ]
            }
        },
        "aggregations": {"max_anomaly_grade": {"max": {"field": "anomaly_grade"}}}
    }

    condition = (
        "return ctx.results != null && "
        "ctx.results.length > 0 && "
        "ctx.results[0].aggregations != null && "
        "ctx.results[0].aggregations.max_anomaly_grade != null && "
        "ctx.results[0].hits.total.value > 0 && "
        "ctx.results[0].hits.hits[0]._source != null && "
        "ctx.results[0].hits.hits[0]._source.confidence != null && "
        "ctx.results[0].aggregations.max_anomaly_grade.value != null && "
        f"ctx.results[0].aggregations.max_anomaly_grade.value > {grade_th} && "
        f"ctx.results[0].hits.hits[0]._source.confidence > {conf_th}"
    )

    return {
        "name": monitor_name,
        "type": "monitor",
        "monitor_type": "query_level_monitor",
        "enabled": True,
        "schedule": {"period": {"interval": interval, "unit": "MINUTES"}},
        "inputs": [{
            "search": {
                "indices": [result_index],
                "query": query
            }
        }],
        "triggers": [{
            "name": trigger_name,
            "severity": "1",
            "condition": {"script": {"lang": "painless", "source": condition}},
            "actions": [{
                "name": monitor_name,
                "destination_id": destination_id,
                "subject_template": {"lang": "mustache", "source": "Alerting Notification action"},
                "message_template": {"lang": "mustache", "source": json.dumps({
                    "monitor": {"name": "{{ctx.monitor.name}}"},
                    "trigger": {"name": "{{ctx.trigger.name}}"},
                    "entity": "{{ctx.results.0.hits.hits.0._source.entity.0.value}}",
                    "periodStart": "{{ctx.periodStart}}",
                    "periodEnd": "{{ctx.periodEnd}}",
                    "anomaly_grade": "{{ctx.results.0.hits.hits.0._source.anomaly_grade}}", 
                    "anomaly_confidence": "{{ctx.results.0.hits.hits.0._source.confidence}}"
                })},
                "throttle_enabled": False
            }]
        }],
        "ui_metadata": {
            "monitor_type": "query_level_monitor",
            "schedule": {
                "timezone": None,
                "frequency": "interval",
                "period": {"interval": interval, "unit": "MINUTES"},
                "daily": 0,
                "weekly": {"mon": False, "tue": False, "wed": False, "thur": False, "fri": False, "sat": False, "sun": False},
                "monthly": {"type": "day", "day": 1},
                "cronExpression": f"0 */{interval} * * *"
            },
            "search": {
                "searchType": "ad",
                "timeField": "",
                "aggregations": [],
                "groupBy": [],
                "bucketValue": 1,
                "bucketUnitOfTime": "h",
                "filters": []
            },
            "triggers": {
                trigger_name: {
                    "adTriggerMetadata": {
                        "triggerType": "anomaly_detector_trigger",
                        "anomalyGrade": {"value": grade_th, "enum": "ABOVE"},
                        "anomalyConfidence": {"value": conf_th, "enum": "ABOVE"}
                    }
                }
            }
        }
    }

def create_monitor(session: requests.Session, opensearch_base: str, payload: Dict[str, Any], verify: bool) -> str:
    r = session.post(f"{opensearch_base.rstrip('/')}/_plugins/_alerting/monitors", json=payload, verify=verify)
    if r.status_code not in (200, 201):
        die(f"Monitor create failed: {r.status_code} {r.text}")
    data = r.json() if r.text else {}
    mid = data.get("_id") or data.get("id")
    if not mid:
        die(f"Monitor create succeeded but no id returned: {r.text}")
    return mid

def update_monitor(session: requests.Session, opensearch_base: str, monitor_id: str, payload: Dict[str, Any], verify: bool) -> None:
    url = f"{opensearch_base.rstrip('/')}/_plugins/_alerting/monitors/{monitor_id}"
    r = session.put(url, json=payload, verify=verify)
    if r.status_code not in (200, 201):
        die(f"Monitor update failed: {r.status_code} {r.text}")

def main() -> None:
    if len(sys.argv) < 3:
        die("Usage: monitor.py <SCENARIO> <DETECTOR_ID>")
    scenario_arg = sys.argv[1]
    detector_id = sys.argv[2]

    load_env(Path(".env"))
    cfg = load_yaml(Path("config.yaml"))
    scenario_name, scn = pick_scenario(cfg, scenario_arg)

    opensearch_base = os.environ.get("OS_URL", "").rstrip("/")
    os_user = os.environ.get("OS_USER", "")
    os_pass = os.environ.get("OS_PASS", "")
    os_verify = os.environ.get("OS_VERIFY_SSL", os.environ.get("DASHBOARD_VERIFY_SSL", "true")).lower() in ("1","true","yes","on")
    if not opensearch_base: die("OS_URL is required in .env")

    wb_cfg = cfg.get("webhook") or {}
    webhook_name = wb_cfg.get("name") or os.environ.get("WEBHOOK_NAME", "RADAR Webhook")
    webhook_url  = wb_cfg.get("url")  or os.environ.get("WEBHOOK_URL", "")
    if not webhook_url:
        die("Set webhook.url in config.yaml or WEBHOOK_URL in .env")

    session = make_session(os_user, os_pass)

    destination_id = ensure_webhook(opensearch_base, os_user, os_pass, os_verify, webhook_name, webhook_url)

    mon_name = scn.get("monitor_name", f"{scenario_name}-monitor")
    existing = find_monitor(session, opensearch_base, mon_name, os_verify)
    if existing:
        monitor_id, linked_detector_id = existing
        if linked_detector_id != detector_id:
            payload = monitor_payload(scenario_name, scn, detector_id, destination_id)
            update_monitor(session, opensearch_base, monitor_id, payload, os_verify)
        print(monitor_id)
        return

    payload = monitor_payload(scenario_name, scn, detector_id, destination_id)
    monitor_id = create_monitor(session, opensearch_base, payload, os_verify)
    if not monitor_id:
        die("Monitor create succeeded but no id returned")
    print(monitor_id)

if __name__ == "__main__":
    try:
        main()
    except requests.HTTPError as e:
        die(f"HTTP error: {getattr(e.response,'status_code','?')} {getattr(e.response,'text','')}")
    except Exception as e:
        die(str(e))