#!/usr/bin/env python3

import os, sys, json, requests
from typing import Dict, List, Optional, Tuple

# ---------- utils ----------
def die(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    sys.exit(code)

def make_session(user: str, pwd: str, extra_headers: Optional[Dict[str,str]] = None) -> requests.Session:
    s = requests.Session()
    if user or pwd: s.auth = (user, pwd)
    headers = {"Content-Type":"application/json","kbn-xsrf":"true","osd-xsrf":"true"}
    if extra_headers: headers.update(extra_headers)
    s.headers.update(headers)
    return s

# ---------- feature detection ----------
def has_destinations(session: requests.Session, base: str, verify: bool) -> bool:
    req = session.post(f"{base}/api/alerting/destinations", verify=verify)
    if req.status_code == 200: return True
    if req.status_code in (401,403): return True  # endpoint exists but unauthorized
    return False

# ---------- destinations API ----------
def dest_list(session: requests.Session, base: str, verify: bool) -> List[Dict]:
    r = session.get(f"{base}/api/alerting/destinations", verify=verify)
    if r.status_code != 200: die(f"List destinations failed: {r.status_code} {r.text}")
    return (r.json() or {}).get("destinations") or []

def dest_find_id(session: requests.Session, base: str, name: str, verify: bool) -> Optional[str]:
    for d in dest_list(session, base, verify):
        if d.get("name") == name:
            return d.get("id") or d.get("config_id")
    return None

def dest_create(session: requests.Session, base: str, name: str, url: str, description: str, verify: bool) -> str:
    payload = {
        "name": name,
        "type": "custom_webhook",
        "custom_webhook": {"url": url, "header_params": {"Content-Type":"application/json"}, "method":"POST"},
        "description": description,
    }
    r = session.post(f"{base}/api/alerting/destinations", data=json.dumps(payload), verify=verify)
    if r.status_code not in (200,201): die(f"Create destination failed: {r.status_code} {r.text}")
    res = r.json() or {}
    print(res)
    return res.get("id") or res.get("destination", {}).get("id") or res.get("config_id","")

# ---------- notifications API (fallback) ----------
def notif_list(session: requests.Session, base: str, verify: bool) -> List[Dict]:
    params = {
        "config_type": "webhook",
        "from_index": 0,
        "max_items": 200,
        "sort_field": "name",
        "sort_order": "asc",
    }
    r = session.get(f"{base}/api/notifications/get_configs", params=params, verify=verify)
    if r.status_code != 200: die(f"List notifications failed: {r.status_code} {r.text}")
    return (r.json().get("data") or {}).get("items", []) or []

def notif_find_id(session: requests.Session, base: str, name: str, verify: bool) -> Optional[str]:
    for item in notif_list(session, base, verify):
        if item.get("name") == name:
            return item.get("id") or item.get("config_id")
    return None

def notif_create(session: requests.Session, base: str, name: str, url: str, description: str, verify: bool) -> str:
    payload = {
        "config": {
            "name": name, "description": description, "config_type":"webhook", "is_enabled": True,
            "webhook": {"url": url, "header_params":{"Content-Type":"application/json"}, "method":"POST"}
        }
    }
    r = session.post(f"{base}/api/notifications/create_config", data=json.dumps(payload), verify=verify)
    if r.status_code != 200: die(f"Create notification failed: {r.status_code} {r.text}")
    return r.json().get("config_id","")

# ---------- public helpers ----------
def ensure_webhook(base: str, user: str, pwd: str, verify: bool, name: str, url: str, description: str = "") -> str:
    session = make_session(user, pwd)
    base = base.rstrip("/")
    existing = notif_find_id(session, base, name, verify)
    if existing: return existing
    return notif_create(session, base, name, url, description, verify)

def main() -> None:
    base = os.environ.get("DASHBOARD_URL","").rstrip("/")
    user = os.environ.get("DASHBOARD_USER",""); pwd = os.environ.get("DASHBOARD_PASS","")
    verify = os.environ.get("DASHBOARD_VERIFY_SSL","true").lower() in ("1","true","yes","on")
    name = os.environ.get("WEBHOOK_NAME","RADAR Webhook")
    url  = os.environ.get("WEBHOOK_URL","")
    if not base or not url: die("Set DASHBOARD_URL and WEBHOOK_URL in env")
    dest_id = ensure_webhook(base, user, pwd, verify, name, url)
    print(dest_id)

if __name__ == "__main__":
    try:
        main()
    except requests.HTTPError as e:
        die(f"HTTP error: {getattr(e.response,'status_code','?')} {getattr(e.response,'text','')}")
    except Exception as e:
        die(str(e))
