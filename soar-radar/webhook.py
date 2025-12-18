#!/usr/bin/env python3

import os, sys, json, requests
from pathlib import Path
from typing import Dict, List, Optional

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

def make_session(user: str, pwd: str) -> requests.Session:
    s = requests.Session()
    if user or pwd:
        s.auth = (user, pwd)
    s.headers.update({"Content-Type": "application/json"})
    return s

def notif_list(session: requests.Session, os_base: str, verify: bool) -> List[Dict]:
    r = session.get(f"{os_base.rstrip('/')}/_plugins/_notifications/configs", verify=verify)
    if r.status_code != 200:
        die(f"List notifications failed: {r.status_code} {r.text}")
    data = r.json() if r.text else {}
    return data.get("config_list") or []

def notif_find_id(session: requests.Session, os_base: str, name: str, verify: bool, url: Optional[str] = None) -> Optional[str]:
    for item in notif_list(session, os_base, verify):
        cfg = item.get("config") or {}
        if (cfg.get("name") or "").strip() != name:
            continue
        if (cfg.get("config_type") or "").strip() != "webhook":
            continue
        if url:
            wh = cfg.get("webhook") or {}
            if (wh.get("url") or "").strip() != url:
                continue
        return item.get("config_id") or item.get("id")
    return None

def notif_create(session: requests.Session, os_base: str, name: str, url: str, description: str, verify: bool) -> str:
    payload = {
        "name": name,
        "config": {
            "name": name,
            "description": description,
            "config_type": "webhook",
            "is_enabled": True,
            "webhook": {
                "url": url
            }
        }
    }
    r = session.post(f"{os_base.rstrip('/')}/_plugins/_notifications/configs", json=payload, verify=verify)
    if r.status_code not in (200, 201):
        die(f"Create notification failed: {r.status_code} {r.text}")
    data = r.json() if r.text else {}
    cid = data.get("config_id") or data.get("id")
    if not cid:
        cid = notif_find_id(session, os_base, name, verify, url=url)
    if not cid:
        die(f"Create notification succeeded but no id returned: {r.text}")
    return cid

def ensure_webhook(os_base: str, user: str, pwd: str, verify: bool, name: str, url: str, description: str = "") -> str:
    session = make_session(user, pwd)
    os_base = os_base.rstrip("/")

    existing = notif_find_id(session, os_base, name, verify, url=url)
    if existing:
        return existing

    return notif_create(session, os_base, name, url, description, verify)


def main() -> None:
    load_env(Path(".env"))
    base = os.environ.get("OS_URL", "").rstrip("/")
    user = os.environ.get("OS_USER", "")
    pwd  = os.environ.get("OS_PASS", "")
    verify = os.environ.get("OS_VERIFY_SSL", "true").lower() in ("1","true","yes","on")
    name = os.environ.get("WEBHOOK_NAME", "RADAR Webhook")
    url  = os.environ.get("WEBHOOK_URL", "")
    if not base or not url:
        die("Set OS_URL and WEBHOOK_URL in env")
    cid = ensure_webhook(base, user, pwd, verify, name, url)
    print(cid)

if __name__ == "__main__":
    try:
        main()
    except requests.HTTPError as e:
        die(f"HTTP error: {getattr(e.response,'status_code','?')} {getattr(e.response,'text','')}")
    except Exception as e:
        die(str(e))