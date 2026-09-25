from __future__ import annotations

import re
import smtplib
import subprocess
import threading
from pathlib import Path

from wazuh_api import envfile
from wazuh_api import infra as infra_module

_lock = threading.Lock()

_DEFAULT_MANAGER_CONTAINER = "wazuh.manager"
_DEFAULT_AR_RISK_CONFIG = "/var/ossec/active-response/bin/ar.yaml"

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
    "maxmind-key": "MAXMIND_LICENSE_KEY",
}

PASSWORD_KEYS = {
    "os-pass": "OS_PASS",
    "wazuh-pass": "WAZUH_AUTH_PASS",
    "dashboard-pass": "DASHBOARD_PASS",
    "smtp-pass": "SMTP_PASS",
    "maxmind-key": "MAXMIND_LICENSE_KEY",
}

PUBLIC_KEYS = frozenset(
    {v for k, v in FIELD_MAP.items() if k not in PASSWORD_KEYS and not v.startswith("_")}
    | {"OS_VERIFY_SSL", "DASHBOARD_VERIFY_SSL"}
)

# Endpoint settings that receive a stored secret, and the secrets they receive.
# Changing one needs the unlocked vault, unless the same save also sets new secrets.
SECRET_ENDPOINTS = {
    "OS_URL": ("OS_PASS",),
    "WAZUH_API_URL": ("WAZUH_AUTH_PASS",),
    "SMTP_HOST": ("SMTP_PASS",),
    "SMTP_PORT": ("SMTP_PASS",),
    "SMTP_STARTTLS": ("SMTP_PASS",),
    "WEBHOOK_URL": ("WEBHOOK_SHARED_SECRET",),
}
_ENDPOINT_DEFAULTS = {"SMTP_PORT": "587", "SMTP_STARTTLS": "yes"}


class VaultRequired(Exception):
    pass


def _env_path(radar_root: str) -> Path:
    return Path(radar_root) / ".env"


def _certs_dir(radar_root: str) -> Path:
    return Path(radar_root) / ".certs"


def load_env(radar_root: str) -> dict:
    return envfile.load(_env_path(radar_root))


def public_env(env: dict) -> dict:
    return {k: v for k, v in env.items() if k in PUBLIC_KEYS}


def has_passwords(env: dict) -> dict:
    return {field_id: bool(env.get(env_key, "").strip())
            for field_id, env_key in PASSWORD_KEYS.items()}


def reveal_password(radar_root: str, env_key: str) -> str | None:
    return load_env(radar_root).get(env_key)


def _endpoint_changes_needing_vault(current: dict, updates: dict) -> list[str]:
    return [key for key, secrets in SECRET_ENDPOINTS.items()
            if key in updates
            and updates[key] != current.get(key, _ENDPOINT_DEFAULTS.get(key, ""))
            and not all(updates.get(s) for s in secrets)]


def save_connector(radar_root: str, connector: str, fields: dict, vault_unlocked: bool = False) -> dict:
    with _lock:
        updates: dict = {}

        ssl_prefix_map = {
            "os-ssl-enabled": ("OS_VERIFY_SSL", "opensearch"),
            "dashboard-ssl-enabled": ("DASHBOARD_VERIFY_SSL", "dashboard"),
            "decipher-ssl-enabled": ("DECIPHER_VERIFY_SSL", "decipher"),
        }

        for field_id, value in fields.items():
            if field_id in ssl_prefix_map:
                env_key, cert_name = ssl_prefix_map[field_id]
                if value == "false":
                    updates[env_key] = "false"
                else:
                    cert_content = fields.get(field_id.replace("-ssl-enabled", "-cert-content"))
                    if cert_content:
                        cert_path = _save_cert(radar_root, cert_name, cert_content)
                        updates[env_key] = str(cert_path)
                    else:
                        updates[env_key] = "true"
                continue

            if field_id.endswith("-cert-content"):
                continue

            env_key = FIELD_MAP.get(field_id)
            if env_key and value:
                if not isinstance(value, (str, int, float)):
                    raise ValueError(f"{field_id}: expected a string")
                updates[env_key] = envfile.validate(env_key, str(value))

        if not vault_unlocked:
            blocked = _endpoint_changes_needing_vault(load_env(radar_root), updates)
            if blocked:
                raise VaultRequired(", ".join(blocked))

        _write_env(radar_root, updates)

    try:
        _sync_active_responses_env(radar_root)
        return {"synced": True, "sync_error": None}
    except Exception as e:
        return {"synced": False, "sync_error": str(e)}


def _sync_active_responses_env(radar_root: str) -> None:
    from wazuh_api import ar_env

    env = load_env(radar_root)
    container = infra_module.container_for(radar_root, "manager", _DEFAULT_MANAGER_CONTAINER)
    ar_risk_config = env.get("AR_RISK_CONFIG", "").strip() or _DEFAULT_AR_RISK_CONFIG
    ar_env_path = str(Path(ar_risk_config).parent / "active_responses.env")

    overrides = {"RADAR_MANAGER_ADDRESS": env.get("WAZUH_MANAGER_ADDRESS", "") or infra_module.detect_local_ip() or ""}
    try:
        overrides["OS_URL"] = infra_module.resolve_url(radar_root, "manager", "indexer")
    except infra_module.NotConfigured:
        pass

    tmp_path = Path(radar_root) / ".active_responses.env.tmp"
    ar_env.write(tmp_path, env, overrides)
    try:
        subprocess.run(
            ["docker", "cp", str(tmp_path), f"{container}:{ar_env_path}"],
            capture_output=True, text=True, timeout=15, check=True,
        )
    except subprocess.CalledProcessError as e:
        detail = (e.stderr or e.stdout or str(e)).strip()
        raise RuntimeError(f"could not copy active_responses.env into {container}: {detail}")
    except FileNotFoundError:
        raise RuntimeError(f"docker CLI not found on GUI host -- could not sync into {container}")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"timed out copying active_responses.env into {container}")
    finally:
        tmp_path.unlink(missing_ok=True)
    for cmd in (["chown", ar_env.FINAL_OWNER, ar_env_path], ["chmod", oct(ar_env.FINAL_MODE)[2:], ar_env_path]):
        proc = subprocess.run(["docker", "exec", "-u", "root", container, *cmd],
                              capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            raise RuntimeError(f"could not {' '.join(cmd[:2])} active_responses.env in {container}: "
                               f"{(proc.stderr or proc.stdout).strip()}")


def _save_cert(radar_root: str, name: str, content: str) -> Path:
    d = _certs_dir(radar_root)
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{name}-ca.pem"
    p.write_text(content)
    p.chmod(0o600)
    return p


def _write_env(radar_root: str, updates: dict) -> None:
    """Apply `updates` to .env in place (comments and order kept).

    Audit #2/#16: values are validated and quoted by wazuh_api.envfile, and
    the file is rewritten atomically with mode 0600."""
    envfile.update(_env_path(radar_root), updates)


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
        return _test_decipher(radar_root, env)
    if connector == "webhook":
        return _test_webhook(env)
    if connector == "maxmind":
        return _test_maxmind(env)
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


def _test_via_container(label: str, container: str, url: str, verify_val: str, timeout_val: str,
                         method: str = "GET", data: bytes = None, auth: tuple = None) -> dict:
    try:
        timeout_f = float(timeout_val)
    except (TypeError, ValueError):
        timeout_f = 10.0

    insecure = not verify_val or verify_val.lower() in ("false", "0")
    cmd = [
        "docker", "exec", container,
        "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
        "--max-time", str(timeout_f),
    ]
    if insecure:
        cmd.append("-k")
    if method != "GET":
        cmd += ["-X", method]
    if data is not None:
        cmd += ["-H", "Content-Type: application/json", "-d", data.decode() if isinstance(data, bytes) else data]
    if auth:
        cmd += ["-u", f"{auth[0]}:{auth[1]}"]
    cmd.append(url)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_f + 15)
        status = (proc.stdout or "").strip()
        if proc.returncode == 0 and status[:1] in ("2", "3"):
            return {"ok": True, "detail": f"{label} responded HTTP {status} -- checked from inside {container}"}
        err = (proc.stderr or "").strip()
        detail = err or f"curl exited {proc.returncode} (status={status or 'n/a'})"
        return {"ok": False, "error": f"{detail} (checked from inside {container})"}
    except FileNotFoundError:
        return {"ok": False, "error": f"docker CLI not found on GUI host -- cannot exec into {container}"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timed out waiting for docker exec into {container}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _test_decipher(radar_root: str, env: dict) -> dict:
    base = env.get("DECIPHER_BASE_URL", "")
    if not base:
        return {"ok": False, "error": "DECIPHER_BASE_URL not configured"}
    url = base.rstrip("/") + "/health"
    timeout = env.get("DECIPHER_TIMEOUT_SEC", "30")
    verify = env.get("DECIPHER_VERIFY_SSL", "false")
    container = infra_module.container_for(radar_root, "manager", _DEFAULT_MANAGER_CONTAINER)
    return _test_via_container("DECIPHER", container, url, verify, timeout)


def _test_maxmind(env: dict) -> dict:
    try:
        import urllib.request
        import urllib.error
        key = env.get("MAXMIND_LICENSE_KEY", "").strip()
        if not key:
            return {"ok": False, "error": "MAXMIND_LICENSE_KEY not configured"}
        url = (
            "https://download.maxmind.com/app/geoip_download"
            f"?edition_id=GeoLite2-City&license_key={key}&suffix=tar.gz"
        )
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=10):
            return {"ok": True, "detail": "MaxMind license key accepted"}
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return {"ok": False, "error": "MaxMind rejected this license key (401/403)"}
        return {"ok": False, "error": f"MaxMind returned HTTP {e.code}"}
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
        headers = {"Content-Type": "application/json"}
        secret = env.get("WEBHOOK_SHARED_SECRET", "")
        if secret:
            headers["X-RADAR-Webhook-Token"] = secret
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return {"ok": True, "detail": f"Webhook responded {resp.status}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}