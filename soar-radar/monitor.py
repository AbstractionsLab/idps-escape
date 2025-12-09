#!/usr/bin/env python3

import os, sys, json, yaml, requests
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from webhook import ensure_webhook

# ---------- utils ----------
def die(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    sys.exit(code)

def load_env(path: Path) -> None:
    if not path.exists(): return
    for line in path.read_text().splitlines():
        line=line.strip()
        if not line or line.startswith("#") or "=" not in line: continue
        k,v=line.split("=",1)
        os.environ.setdefault(k.strip(), v.strip())

def load_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists(): die(f"config.yaml not found at {path}")
    with path.open() as f: return yaml.safe_load(f) or {}

def make_session(user: str, pwd: str) -> requests.Session:
    s = requests.Session()
    if user or pwd:
        s.auth = (user, pwd)
    s.headers.update({
        "Content-Type": "application/json",
        "kbn-xsrf": "true",
        "osd-xsrf": "true",
    })
    return s


def pick_scenario(cfg: Dict[str, Any], arg_name: Optional[str]) -> Tuple[str, Dict[str, Any]]:
    scenarios = cfg.get("scenarios") or {}
    name = arg_name or cfg.get("default_scenario")
    if not name: die("Provide SCENARIO or set default_scenario in config.yaml")
    if name not in scenarios: die(f"Scenario '{name}' not found in config.yaml")
    return name, scenarios[name]

# ---------- monitor helpers ----------
def find_monitor_id(session: requests.Session, base: str, name: str, verify: bool) -> Optional[str]:
    r = session.post(f"{base.rstrip('/')}/api/alerting/monitors/_search",
                  json={"query":{"term":{"name.keyword": name}}}, verify=verify)
    if r.status_code == 404:
        return None
    if r.status_code != 200:
        die(f"Monitor search failed: {r.status_code} {r.text}")
    for hit in r.json().get("hits", {}).get("hits", []):
        if (hit.get("_source") or {}).get("name") == name:
            return hit.get("_id")
    return None

def monitor_payload(scenario_name: str, scn: Dict[str, Any], detector_id: str,
                    destination_id: str) -> Dict[str, Any]:
    return {
        "name": scn.get("monitor_name", f"{scenario_name}-monitor"),
        "type": "monitor",
        "monitor_type": "query_level_monitor",
        "enabled": True,
        "schedule": {"period":{"interval": int(scn.get("detector_interval",5)), "unit":"MINUTES"}},
        "inputs": [{
            "search": {
                "indices": [".opendistro-anomaly-results*"],
                "query": {
                    "size": 1,
                    "sort": [{"anomaly_grade":"desc"},{"confidence":"desc"}],
                    "query": {"bool":{"filter":[
                        {"range":{"execution_end_time":{"from":"{{period_end}}||-2m","to":"{{period_end}}","include_lower":True,"include_upper":True}}},
                        {"term":{"detector_id":{"value": detector_id}}}
                    ]}},
                    "aggregations":{"max_anomaly_grade":{"max":{"field":"anomaly_grade"}}}
                }
            }
        }],
        "triggers": [{
            "name": scn.get("trigger_name", f"{scenario_name}-trigger"),
            "severity": "1",
            "condition": {"script":{"lang":"painless","source":(
                "return ctx.results!=null && ctx.results.length>0 && "
                "ctx.results[0].aggregations!=null && "
                "ctx.results[0].aggregations.max_anomaly_grade!=null && "
                "ctx.results[0].hits.total.value>0 && "
                "ctx.results[0].hits.hits[0]._source!=null && "
                "ctx.results[0].hits.hits[0]._source.confidence!=null && "
                "ctx.results[0].aggregations.max_anomaly_grade.value!=null && "
                f"ctx.results[0].aggregations.max_anomaly_grade.value > {scn.get('anomaly_grade_threshold',0.5)} && "
                f"ctx.results[0].hits.hits[0]._source.confidence > {scn.get('confidence_threshold',0.5)}"
            )}},
            "actions": [{
                "name": scn.get("monitor_name", f"{scenario_name}-monitor"),
                "destination_id": destination_id,
                "subject_template":{"lang":"mustache","source":"Alerting Notification action"},
                "message_template":{"lang":"mustache","source": json.dumps({
                    "monitor":{"name":"{{ctx.monitor.name}}"},
                    "trigger":{"name":"{{ctx.trigger.name}}"},
                    "entity":"{{ctx.results.0.hits.hits.0._source.entity.0.value}}",
                    "periodStart":"{{ctx.periodStart}}",
                    "periodEnd":"{{ctx.periodEnd}}"
                })},
                "throttle_enabled": False
            }]
        }]
    }

def create_monitor(session: requests.Session, base: str, payload: Dict[str, Any], verify: bool) -> str:
    r = session.post(f"{base.rstrip('/')}/api/alerting/monitors", json=payload, verify=verify)
    if r.status_code != 200: die(f"Monitor create failed: {r.status_code} {r.text}")
    return r.json().get("_id")

# ---------- main ----------
def main() -> None:
    if len(sys.argv) < 3:
        die("Usage: monitor.py <SCENARIO> <DETECTOR_ID>")
    scenario_arg = sys.argv[1]
    detector_id = sys.argv[2]

    load_env(Path(".env"))
    cfg = load_yaml(Path("config.yaml"))
    scenario_name, scn = pick_scenario(cfg, scenario_arg)

    base = os.environ.get("DASHBOARD_URL","").rstrip("/")
    user = os.environ.get("DASHBOARD_USER",""); pwd = os.environ.get("DASHBOARD_PASS","")
    verify = os.environ.get("DASHBOARD_VERIFY_SSL","true").lower() in ("1","true","yes","on")
    if not base: die("DASHBOARD_URL is required in .env")

    # webhook settings: config.yaml preferred, then env
    wb_cfg = cfg.get("webhook") or {}
    webhook_name = wb_cfg.get("name") or os.environ.get("WEBHOOK_NAME","RADAR Webhook")
    webhook_url  = wb_cfg.get("url")  or os.environ.get("WEBHOOK_URL","")
    if not webhook_url: die("Set webhook.url in config.yaml or WEBHOOK_URL in .env")

    session = make_session(user, pwd)

    # 1) ensure webhook destination
    destination_id = ensure_webhook(base, user, pwd, verify, webhook_name, webhook_url)

    # 2) ensure monitor
    mon_name = scn.get("monitor_name", f"{scenario_name}-monitor")
    existing = find_monitor_id(session, base, mon_name, verify)
    if existing:
        print(existing); return

    payload = monitor_payload(scenario_name, scn, detector_id, destination_id)
    monitor_id = create_monitor(session, base, payload, verify)
    print(monitor_id)

if __name__ == "__main__":
    try:
        main()
    except requests.HTTPError as e:
        die(f"HTTP error: {getattr(e.response,'status_code','?')} {getattr(e.response,'text','')}")
    except Exception as e:
        die(str(e))
