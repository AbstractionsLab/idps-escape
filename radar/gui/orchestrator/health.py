from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

from . import vault as vault_module


def _parse_lines(lines: list[str]) -> list[dict]:
    out = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("OK"):
            out.append({"status": "ok", "detail": line})
        elif line.startswith("WARN"):
            out.append({"status": "warn", "detail": line})
        elif line.startswith("FAIL"):
            out.append({"status": "fail", "detail": line})
        else:
            out.append({"status": "ok", "detail": line})
    return out


def _tally(checks: list[dict]) -> dict:
    ok = sum(1 for c in checks if c["status"] == "ok")
    warn = sum(1 for c in checks if c["status"] == "warn")
    fail = sum(1 for c in checks if c["status"] == "fail")
    return {
        "ok": ok, "warn": warn, "fail": fail,
        "overall": "fail" if fail > 0 else ("warn" if warn > 0 else "ok"),
    }


def _load_env(radar_root: str) -> dict:
    env_file = Path(radar_root) / ".env"
    env = {}
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            v = v.split("#")[0].strip().strip('"').strip("'")
            env[k.strip()] = v
    return env


def _any_vault_encrypted(radar_root: str) -> bool:
    hv = Path(radar_root) / "host_vars"
    if not hv.exists():
        return False
    for p in hv.glob("*.yml"):
        try:
            if p.read_text(errors="ignore")[:32].startswith("$ANSIBLE_VAULT"):
                return True
        except OSError:
            continue
    return False


def _run_ansible(
    radar_root: str,
    limit_groups: str,
    extra_vars: dict,
    ssh_key_path: str | None,
    vault_session_id: str | None,
    ssh_session_id: str | None = None,
) -> tuple[bool, str]:
    playbook = str(Path(radar_root) / "roles" / "health_check" / "health-check.yml")
    inventory = str(Path(radar_root) / "inventory.yaml")

    cmd = [
        "ansible-playbook",
        playbook,
        "-i", inventory,
        "--limit", limit_groups,
    ]

    for k, v in extra_vars.items():
        cmd += ["-e", f"{k}={v}"]

    env = os.environ.copy()
    env.update(_load_env(radar_root))

    if ssh_key_path and Path(ssh_key_path).exists():
        env["ANSIBLE_PRIVATE_KEY_FILE"] = ssh_key_path

    env["ANSIBLE_STDOUT_CALLBACK"] = "minimal"
    env["ANSIBLE_DISPLAY_SKIPPED_HOSTS"] = "false"
    env["ANSIBLE_DISPLAY_OK_HOSTS"] = "false"
    env.setdefault("ANSIBLE_HOST_KEY_CHECKING", "False")

    use_vault = _any_vault_encrypted(radar_root)
    if use_vault and (not vault_session_id or not vault_module.has_password(vault_session_id)):
        return False, "vault password required: encrypted host_vars/ files present. Unlock vault in the UI."

    run_ctx = vault_module.password_file(vault_session_id) if use_vault else None
    try:
        if run_ctx is not None:
            pf = run_ctx.__enter__()
            cmd += ["--vault-password-file", pf]
        with vault_module.ssh_askpass_env(ssh_session_id, env) as final_env:
            try:
                result = subprocess.run(
                    cmd, cwd=radar_root, env=final_env,
                    capture_output=True, text=True, timeout=180,
                )
                return result.returncode == 0, result.stderr or result.stdout
            except FileNotFoundError:
                return False, "ansible-playbook not found. Install Ansible: pip install ansible"
            except subprocess.TimeoutExpired:
                return False, "ansible-playbook timed out after 180 seconds"
            except Exception as e:
                return False, str(e)
    finally:
        if run_ctx is not None:
            try:
                run_ctx.__exit__(None, None, None)
            except Exception:
                pass


def _read_json(path: str) -> dict | None:
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def _checks_from_raw(raw_checks) -> list[dict]:
    if isinstance(raw_checks, list):
        result = []
        for item in raw_checks:
            if isinstance(item, str):
                result.extend(_parse_lines([item]))
            elif isinstance(item, dict):
                result.append(item)
        return result
    return []


def check_manager(
    radar_root: str,
    manager: dict,
    bound_scenarios: list,
    ssh_key_path: str | None = None,
    vault_session_id: str | None = None,
    ssh_session_id: str | None = None,
) -> dict:
    name = manager["name"]
    mode = manager["manager_mode"]
    scenario_filter = ",".join(bound_scenarios) if bound_scenarios else "all"
    limit = name

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, prefix="radar_hc_mgr_") as tf:
        json_file = tf.name

    try:
        env_vars = _load_env(radar_root)
        extra_vars = {
            "manager_mode": mode,
            "scenario_filter": scenario_filter if len(bound_scenarios) == 1 else "all",
            "gui_json_output": "true",
            "gui_json_file": json_file,
            "os_url": env_vars.get("OS_URL", ""),
            "os_user": env_vars.get("OS_USER", ""),
            "os_pass": env_vars.get("OS_PASS", ""),
            "wazuh_api_url": env_vars.get("WAZUH_API_URL", ""),
            "wazuh_auth_user": env_vars.get("WAZUH_AUTH_USER", ""),
            "wazuh_auth_pass": env_vars.get("WAZUH_AUTH_PASS", ""),
            "webhook_url": env_vars.get("WEBHOOK_URL", ""),
            "summary_file": json_file.replace(".json", ".txt"),
            "scenarios_root": str(Path(radar_root) / "scenarios"),
            "ar_yaml_path": str(Path(radar_root) / "scenarios" / "active_responses" / "ar.yaml"),
        }

        ok, err = _run_ansible(radar_root, limit, extra_vars, ssh_key_path, vault_session_id, ssh_session_id)

        data = _read_json(json_file)
        if data:
            checks = _checks_from_raw(data.get("checks", []))
            tally = _tally(checks)
            return {"name": name, "type": "manager", "checks": checks, **tally}

        if not ok:
            error_checks = [{"status": "fail", "detail": f"FAIL - ansible-playbook error: {err.strip()[:400]}"}]
            return {"name": name, "type": "manager", "checks": error_checks,
                    "ok": 0, "warn": 0, "fail": 1, "overall": "fail"}

        return {"name": name, "type": "manager", "checks": [],
                "ok": 0, "warn": 1, "fail": 0, "overall": "warn",
                "_note": "Playbook ran but produced no JSON output"}

    finally:
        for f in [json_file, json_file.replace(".json", ".txt")]:
            try:
                Path(f).unlink(missing_ok=True)
            except Exception:
                pass


def check_agent(
    radar_root: str,
    agent: dict,
    ssh_key_path: str | None = None,
    vault_session_id: str | None = None,
    ssh_session_id: str | None = None,
) -> dict:
    name = agent["name"]
    agent_mode = agent["agent_mode"]
    limit = name

    json_dir = tempfile.mkdtemp(prefix="radar_hc_agent_")
    json_file = str(Path(json_dir) / f"radar_health_agent_{name}.json")

    try:
        extra_vars = {
            "gui_json_output": "true",
            "gui_json_dir": json_dir,
            "summary_file": str(Path(json_dir) / "summary.txt"),
        }

        ok, err = _run_ansible(radar_root, limit, extra_vars, ssh_key_path, vault_session_id, ssh_session_id)

        data = _read_json(json_file)
        if data:
            checks = _checks_from_raw(data.get("checks", []))
            tally = _tally(checks)
            return {"name": name, "type": "agent", "checks": checks, **tally}

        if not ok:
            error_checks = [{"status": "fail", "detail": f"FAIL - ansible-playbook error: {err.strip()[:400]}"}]
            return {"name": name, "type": "agent", "checks": error_checks,
                    "ok": 0, "warn": 0, "fail": 1, "overall": "fail"}

        return {"name": name, "type": "agent", "checks": [],
                "ok": 0, "warn": 1, "fail": 0, "overall": "warn"}

    finally:
        import shutil
        try:
            shutil.rmtree(json_dir, ignore_errors=True)
        except Exception:
            pass