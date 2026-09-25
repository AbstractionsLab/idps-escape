#!/usr/bin/env python3

import re
import os, sys, json, requests
from pathlib import Path
from typing import Dict, List, Optional

def die(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
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


def load_env(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _ENV_LINE_RE.match(line)
        if not m:
            continue
        value = _parse_env_value(m.group(2))
        if value is not None:
            os.environ.setdefault(m.group(1), value)

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

TOKEN_HEADER = "X-RADAR-Webhook-Token"


def notif_find(session: requests.Session, os_base: str, name: str, verify: bool, url: Optional[str] = None) -> Optional[Dict]:
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
        return item
    return None


def notif_find_id(session: requests.Session, os_base: str, name: str, verify: bool, url: Optional[str] = None) -> Optional[str]:
    item = notif_find(session, os_base, name, verify, url=url)
    return (item.get("config_id") or item.get("id")) if item else None


def _channel_config(name: str, url: str, description: str, headers: Optional[Dict[str, str]]) -> Dict:
    webhook = {"url": url}
    if headers:
        webhook["header_params"] = dict(headers)
    return {
        "name": name,
        "description": description,
        "config_type": "webhook",
        "is_enabled": True,
        "webhook": webhook,
    }


def notif_create(session: requests.Session, os_base: str, name: str, url: str, description: str, verify: bool,
                 headers: Optional[Dict[str, str]] = None) -> str:
    payload = {"name": name, "config": _channel_config(name, url, description, headers)}
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


def notif_update(session: requests.Session, os_base: str, config_id: str, name: str, url: str, description: str,
                 verify: bool, headers: Optional[Dict[str, str]]) -> None:
    payload = {"config": _channel_config(name, url, description, headers)}
    r = session.put(f"{os_base.rstrip('/')}/_plugins/_notifications/configs/{config_id}", json=payload, verify=verify)
    if r.status_code not in (200, 201):
        die(f"Update notification failed: {r.status_code} {r.text}")


def webhook_headers() -> Optional[Dict[str, str]]:
    secret = os.environ.get("WEBHOOK_SHARED_SECRET", "").strip()
    return {TOKEN_HEADER: secret} if secret else None


def ensure_webhook(os_base: str, user: str, pwd: str, verify: bool, name: str, url: str, description: str = "",
                   headers: Optional[Dict[str, str]] = None) -> str:
    session = make_session(user, pwd)
    os_base = os_base.rstrip("/")

    existing = notif_find(session, os_base, name, verify, url=url)
    if existing:
        cid = existing.get("config_id") or existing.get("id")
        current = ((existing.get("config") or {}).get("webhook") or {}).get("header_params") or {}
        if headers and any(current.get(k) != v for k, v in headers.items()):
            notif_update(session, os_base, cid, name, url, description, verify, headers)
        return cid

    return notif_create(session, os_base, name, url, description, verify, headers=headers)


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
    cid = ensure_webhook(base, user, pwd, verify, name, url, headers=webhook_headers())
    print(cid)

if __name__ == "__main__":
    try:
        main()
    except requests.HTTPError as e:
        die(f"HTTP error: {getattr(e.response,'status_code','?')} {getattr(e.response,'text','')}")
    except Exception as e:
        die(str(e))