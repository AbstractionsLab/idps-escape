#!/usr/bin/env python3
import os, sys, json, yaml, requests
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# utilities
def die(msg: str, code: int = 1) -> None:
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(code)

def load_env(env_path: Path) -> None:
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
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
    s.headers.update({"Content-Type": "application/json"})
    return s

# config helpers
def find_config_file() -> Path:
    return Path("config.yaml")

def pick_scenario(cfg: Dict[str, Any], arg_name: Optional[str]) -> Tuple[str, Dict[str, Any]]:
    scenarios = cfg.get("scenarios") or {}
    name = arg_name or cfg.get("default_scenario")
    if not name:
        die("Provide SCENARIO or set default_scenario in config.yaml")
    if name not in scenarios:
        die(f"Scenario '{name}' not found in config.yaml")
    return name, scenarios[name]

def index_pattern(scn: Dict[str, Any]) -> str:
    if "log_index_pattern" in scn:
        return scn["log_index_pattern"]
    prefix = scn["index_prefix"]
    return f"{prefix}-*"

def build_features(scn: Dict[str, Any]) -> List[Dict[str, Any]]:
    feats = scn.get("features")
    if not feats:
        die("Scenario features are required in config.yaml (scenarios.<name>.features)")
    return feats

# detector API
def find_detector_id(sess, base, name, verify, timeout):
    url = f"{base}/_plugins/_anomaly_detection/detectors/_search"
    body = {"query": {"term": {"name.keyword": name}}}
    r = sess.post(url, json=body, verify=verify, timeout=timeout)
    if r.status_code == 404:
        # System index not created yet -> treat as "no detectors exist"
        return None
    r.raise_for_status()
    hits = r.json().get("hits", {}).get("hits", [])
    return hits[0]["_id"] if hits else None

def detector_spec(scn_name: str, scn: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": f"{scn_name.upper()}_DETECTOR",
        "description": f"{scn_name} detector",
        "time_field": scn["time_field"],
        "indices": [index_pattern(scn)],
        "filter_query": {"match_all": {}},
        "feature_attributes": build_features(scn),
        "detection_interval": {"period": {"interval": int(scn.get("detector_interval", 5)), "unit": "Minutes"}},
        "window_delay": {"period": {"interval": int(scn.get("delay_minutes", 1)), "unit": "Minutes"}},
        "category_field": [scn["categorical_field"]],
        "result_index": scn["result_index"],
        "rules": [],
    }

def create_detector(sess: requests.Session, base: str, spec: Dict[str, Any], verify: bool, timeout: float) -> str:
    r = sess.post(f"{base}/_plugins/_anomaly_detection/detectors", json=spec, verify=verify, timeout=timeout)
    if r.status_code != 201:
        die(f"Create failed: {r.status_code} {r.text}")
    det_id = r.json()["_id"]
    print(f"[+] Created detector '{spec['name']}' (ID: {det_id})", file=sys.stderr)
    return det_id

def start_detector(sess: requests.Session, base: str, det_id: str, verify: bool, timeout: float) -> None:
    r = sess.post(f"{base}/_plugins/_anomaly_detection/detectors/{det_id}/_start", verify=verify, timeout=timeout)
    if r.status_code != 200:
        die(f"Start failed: {r.status_code} {r.text}")
    print(f"[✓] Started detector (ID: {det_id})", file=sys.stderr)

# main
def main() -> None:
    # 1) env + config
    load_env(Path(".env"))
    cfg = load_yaml(find_config_file())
    
    scenario_arg = sys.argv[1] if len(sys.argv) > 1 else None
    scn_name, scn = pick_scenario(cfg, scenario_arg)

    os_url = os.environ.get("OS_URL", "").rstrip("/")
    os_user = os.environ.get("OS_USER", "")
    os_pass = os.environ.get("OS_PASS", "")
    os_verify = os.environ.get("OS_VERIFY_SSL", "true").lower() in ("1","true","yes","on")
    os_timeout = float(os.environ.get("OS_TIMEOUT", "30"))
    if not os_url:
        die("OS_URL is required in .env")
    session = make_session(os_user, os_pass)
    # 2) find or create detector
    name = f"{scn_name.upper()}_DETECTOR"
    det_id = find_detector_id(session, os_url, name, os_verify, os_timeout)
    if det_id:
        print(f"[✓] Detector exists: {name} (ID: {det_id})", file=sys.stderr)
    else:
        spec = detector_spec(scn_name, scn)
        det_id = create_detector(session, os_url, spec, os_verify, os_timeout)

    # 3) start
    start_detector(session, os_url, det_id, os_verify, os_timeout)
    sys.stdout.write(det_id)
    sys.stdout.flush()

if __name__ == "__main__":
    try:
        main()
    except requests.HTTPError as e:
        die(f"HTTP error: {getattr(e.response,'status_code','?')} {getattr(e.response,'text','')}")
    except Exception as e:
        die(str(e))
