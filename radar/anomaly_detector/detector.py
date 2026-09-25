#!/usr/bin/env python3
import re
import os, sys, json, time, yaml, requests
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# utilities
def die(msg: str, code: int = 1) -> None:
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(code)

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

def build_rules(scn: Dict[str, Any]) -> List[Dict[str, Any]]:
    rules = scn.get("rules", [])
    return rules

def build_filter_query(scn: Dict[str, Any]) -> Dict[str, Any]:
    fq = scn.get("filter_query")
    if fq is None:
        return {"match_all": {}}
    if not isinstance(fq, dict):
        die("filter_query must be a valid YAML object in config.yaml")
    return fq

def build_category_field(scn: Dict[str, Any]) -> List[str]:
    field = scn.get("categorical_field")
    return [field] if field else []

def detector_spec(scn_name: str, scn: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": f"{scn_name.upper()}_DETECTOR",
        "description": f"{scn_name} detector",
        "time_field": scn["time_field"],
        "shingle_size": scn.get("shingle_size",8),
        "indices": [index_pattern(scn)],
        "filter_query": build_filter_query(scn),
        "feature_attributes": build_features(scn),
        "detection_interval": {"period": {"interval": int(scn.get("detector_interval", 5)), "unit": "Minutes"}},
        "window_delay": {"period": {"interval": int(scn.get("delay_minutes", 1)), "unit": "Minutes"}},
        "category_field": build_category_field(scn),
        "result_index": scn["result_index"],
        "result_index_min_age": scn.get("result_index_min_age", 10),
        "result_index_min_size":  scn.get("result_index_min_size", 51200),
        "result_index_ttl":  scn.get("result_index_ttl", 60),
        "flatten_custom_result_index": scn.get("flatten_custom_result_index", False),
        "rules": build_rules(scn),
    }

def count_documents(sess: requests.Session, base: str, index_pattern: str, verify: bool, timeout: float) -> int:
    r = sess.post(f"{base}/{index_pattern}/_count", json={"query": {"match_all": {}}}, verify=verify, timeout=timeout)
    if r.status_code == 404:
        return 0
    r.raise_for_status()
    return int(r.json().get("count", 0))

def wait_for_documents(sess: requests.Session, base: str, index_pattern: str, verify: bool, timeout: float,
                        attempts: int = 10, delay_seconds: float = 1.0) -> None:
    for attempt in range(1, attempts + 1):
        try:
            if count_documents(sess, base, index_pattern, verify, timeout) > 0:
                return
        except requests.RequestException:
            pass
        if attempt < attempts:
            time.sleep(delay_seconds)

def create_detector(sess: requests.Session, base: str, spec: Dict[str, Any], verify: bool, timeout: float) -> str:
    wait_for_documents(sess, base, spec["indices"][0], verify, timeout)
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
