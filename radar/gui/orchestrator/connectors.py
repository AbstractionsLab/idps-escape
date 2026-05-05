from __future__ import annotations

import os
import smtplib
import threading
from pathlib import Path

_lock = threading.Lock()

FIELD_MAP = {
    "os-url": "OS_URL",
    "os-user": "OS_USER",
    "os-pass": "OS_PASS",
    "os-ssl-enabled": "_OS_SSL_ENABLED",
    "os-cert-content": "_OS_CERT_CONTENT",
    "wazuh-url": "WAZUH_API_URL",
    "wazuh-user": "WAZUH_AUTH_USER",
    "wazuh-pass": "WAZUH_AUTH_PASS",
    "wazuh-manager": "WAZUH_MANAGER_ADDRESS",
    "dashboard-url": "DASHBOARD_URL",
    "dashboard-user": "DASHBOARD_USER",
    "dashboard-pass": "DASHBOARD_PASS",
    "dashboard-ssl-enabled": "_DASHBOARD_SSL_ENABLED",
    "dashboard-cert-content": "_DASHBOARD_CERT_CONTENT",
    "smtp-host": "SMTP_HOST",
    "smtp-port": "SMTP_PORT",
    "smtp-user": "SMTP_USER",
    "smtp-pass": "SMTP_PASS",
    "smtp-to": "EMAIL_TO",
    "smtp-starttls": "SMTP_STARTTLS",
    "decipher-url": "DECIPHER_BASE_URL",
    "decipher-ssl-enabled": "DECIPHER_VERIFY_SSL",
    "decipher-timeout": "DECIPHER_TIMEOUT_SEC",
    "webhook-name": "WEBHOOK_NAME",
    "webhook-url": "WEBHOOK_URL",
}

PASSWORD_KEYS = {
    "os-pass": "OS_PASS",
    "wazuh-pass": "WAZUH_AUTH_PASS",
    "dashboard-pass": "DASHBOARD_PASS",
    "smtp-pass": "SMTP_PASS"
}


def _env_path(radar_root: str) -> Path:
    return Path(radar_root) / ".env"


def _certs_dir(radar_root: str) -> Path:
    return Path(radar_root) / ".certs"


def load_env(radar_root: str) -> dict:
    p = _env_path(radar_root)
    result = {}
    if not p.exists():
        return result
    with p.open() as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, _, v = line.partition("=")
                result[k.strip()] = v.strip().strip('"')
    return result


def has_passwords(env: dict) -> dict:
    return {field_id: bool(env.get(env_key, "").strip())
            for field_id, env_key in PASSWORD_KEYS.items()}


def reveal_password(radar_root: str, env_key: str) -> str | None:
    return load_env(radar_root).get(env_key)


def save_connector(radar_root: str, connector: str, fields: dict) -> None:
    with _lock:
        env = load_env(radar_root)

        ssl_prefix_map = {
            "os-ssl-enabled": ("OS_VERIFY_SSL", "opensearch"),
            "dashboard-ssl-enabled": ("DASHBOARD_VERIFY_SSL", "dashboard"),
            "decipher-ssl-enabled": ("DECIPHER_VERIFY_SSL", "decipher"),
        }

        for field_id, value in fields.items():
            if field_id in ssl_prefix_map:
                env_key, cert_name = ssl_prefix_map[field_id]
                if value == "false":
                    env[env_key] = "false"
                else:
                    cert_content = fields.get(field_id.replace("-ssl-enabled", "-cert-content"))
                    if cert_content:
                        cert_path = _save_cert(radar_root, cert_name, cert_content)
                        env[env_key] = str(cert_path)
                    else:
                        env[env_key] = "true"
                continue

            if field_id.endswith("-cert-content"):
                continue

            env_key = FIELD_MAP.get(field_id)
            if env_key and value:
                env[env_key] = value

        _write_env(radar_root, env)


def _save_cert(radar_root: str, name: str, content: str) -> Path:
    d = _certs_dir(radar_root)
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{name}-ca.pem"
    p.write_text(content)
    p.chmod(0o600)
    return p


def _write_env(radar_root: str, env: dict) -> None:
    p = _env_path(radar_root)
    lines = []
    written_keys: set = set()

    if p.exists():
        with p.open() as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    lines.append(line.rstrip())
                    continue
                if "=" in stripped:
                    k = stripped.split("=", 1)[0].strip()
                    if k in env:
                        lines.append(f"{k}={env[k]}")
                        written_keys.add(k)
                    else:
                        lines.append(line.rstrip())

    for k, v in env.items():
        if k not in written_keys:
            lines.append(f"{k}={v}")

    tmp = p.with_suffix(".env.tmp")
    with tmp.open("w") as f:
        f.write("\n".join(lines) + "\n")
    tmp.replace(p)


def test_connector(radar_root: str, connector: str) -> dict:
    env = load_env(radar_root)
    if connector == "opensearch":
        return _test_opensearch(env)
    if connector == "wazuh-api":
        return _test_wazuh_api(env)
    if connector == "dashboard":
        return _test_dashboard(env)
    if connector == "smtp":
        return _test_smtp(env)
    if connector == "decipher":
        return _test_decipher(env)
    if connector == "webhook":
        return _test_webhook(env)
    return {"ok": False, "error": f"Unknown connector: {connector}"}


def _ssl_ctx(verify_val: str):
    import ssl
    ctx = ssl.create_default_context()
    if not verify_val or verify_val.lower() in ("false", "0"):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif verify_val.lower() not in ("true", "1"):
        p = Path(verify_val)
        if p.exists():
            ctx.load_verify_locations(str(p))
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _test_opensearch(env: dict) -> dict:
    try:
        import urllib.request
        import base64
        url = env.get("OS_URL", "").rstrip("/") + "/_cluster/health"
        creds = base64.b64encode(f"{env.get('OS_USER','')}:{env.get('OS_PASS','')}".encode()).decode()
        ctx = _ssl_ctx(env.get("OS_VERIFY_SSL", "false"))
        req = urllib.request.Request(url, headers={"Authorization": f"Basic {creds}"})
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            body = resp.read().decode()
            return {"ok": True, "detail": f"Cluster status: {body[:80]}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _test_wazuh_api(env: dict) -> dict:
    try:
        import urllib.request
        import ssl
        import base64
        url = env.get("WAZUH_API_URL", "").rstrip("/") + "/security/user/authenticate"
        creds = base64.b64encode(f"{env.get('WAZUH_AUTH_USER','')}:{env.get('WAZUH_AUTH_PASS','')}".encode()).decode()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, method="GET", headers={"Authorization": f"Basic {creds}"})
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            return {"ok": True, "detail": f"Wazuh API responded {resp.status}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _test_dashboard(env: dict) -> dict:
    try:
        import urllib.request
        url = env.get("DASHBOARD_URL", "").rstrip("/") + "/api/status"
        ctx = _ssl_ctx(env.get("DASHBOARD_VERIFY_SSL", "false"))
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            return {"ok": True, "detail": f"Dashboard responded {resp.status}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _test_smtp(env: dict) -> dict:
    try:
        host = env.get("SMTP_HOST", "")
        port = int(env.get("SMTP_PORT", 587))
        user = env.get("SMTP_USER", "")
        pw = env.get("SMTP_PASS", "")
        starttls = env.get("SMTP_STARTTLS", "yes").lower() == "yes"
        if not host:
            return {"ok": False, "error": "SMTP_HOST not configured"}
        with smtplib.SMTP(host, port, timeout=10) as s:
            if starttls:
                s.starttls()
            if user and pw:
                s.login(user, pw)
        return {"ok": True, "detail": f"SMTP login to {host}:{port} successful"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _test_decipher(env: dict) -> dict:
    try:
        import urllib.request
        url = env.get("DECIPHER_BASE_URL", "").rstrip("/") + "/api/case/list"
        timeout = int(env.get("DECIPHER_TIMEOUT_SEC", 30))
        ctx = _ssl_ctx(env.get("DECIPHER_VERIFY_SSL", "false"))
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            return {"ok": True, "detail": f"DECIPHER responded {resp.status}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _test_webhook(env: dict) -> dict:
    try:
        import urllib.request
        import json as _json
        url = env.get("WEBHOOK_URL", "")
        if not url:
            return {"ok": False, "error": "WEBHOOK_URL not configured"}
        payload = _json.dumps({"ping": True}).encode()
        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return {"ok": True, "detail": f"Webhook responded {resp.status}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}