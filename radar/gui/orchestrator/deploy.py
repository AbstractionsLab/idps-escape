from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path
from typing import Iterator

from . import vault as vault_module


VALID_SCENARIOS = {
    "suspicious_login", "insider_threat", "ddos_detection",
    "malware_communication", "geoip_detection", "log_volume",
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


def _prep_env(radar_root: str, ssh_key: str | None, vault_pw_file: str | None,
              vault_session_id: str | None = None) -> dict:
    env = os.environ.copy()
    env.update(_load_env(radar_root))
    if ssh_key and Path(ssh_key).exists():
        env["ANSIBLE_PRIVATE_KEY_FILE"] = ssh_key
    env.setdefault("ANSIBLE_HOST_KEY_CHECKING", "False")
    env.setdefault("PYTHONUNBUFFERED", "1")
    env["RADAR_NONINTERACTIVE"] = "1"
    if vault_pw_file:
        env["ANSIBLE_VAULT_PASSWORD_FILE"] = vault_pw_file
    return env


def _validate_scenario(scenario: str) -> None:
    if scenario not in VALID_SCENARIOS:
        raise ValueError(f"Invalid scenario '{scenario}'. Must be one of: {sorted(VALID_SCENARIOS)}")


def _validate_mode(value: str, field: str) -> None:
    if value not in ("local", "remote"):
        raise ValueError(f"Invalid {field} '{value}'. Must be 'local' or 'remote'.")


def _build_cmd(radar_root: str, spec: dict) -> list[str]:
    scenario = spec.get("scenario", "")
    agent_mode = spec.get("agent_mode", "local")
    manager_mode = spec.get("manager_mode", "local")
    manager_exists = str(spec.get("manager_exists", True)).lower()
    ssh_key = spec.get("ssh_key") or ""

    _validate_scenario(scenario)
    _validate_mode(agent_mode, "agent_mode")
    _validate_mode(manager_mode, "manager_mode")
    if manager_exists not in ("true", "false"):
        raise ValueError("manager_exists must be true or false")

    script = str(Path(radar_root) / "build-radar.sh")
    cmd = [
        "bash", script, scenario,
        "--agent", agent_mode,
        "--manager", manager_mode,
        "--manager_exists", manager_exists,
    ]
    if ssh_key:
        cmd += ["--ssh-key", ssh_key]
    return cmd


def _run_cmd(radar_root: str, spec: dict) -> list[str]:
    scenario = spec.get("scenario", "")
    ingest = str(spec.get("ingest", False)).lower()

    _validate_scenario(scenario)
    if ingest not in ("true", "false"):
        raise ValueError("ingest must be true or false")

    script = str(Path(radar_root) / "run-radar.sh")
    return ["bash", script, scenario, "--ingest", ingest]


def _health_cmd(radar_root: str, spec: dict) -> list[str]:
    agent_mode = spec.get("agent_mode", "local")
    manager_mode = spec.get("manager_mode", "local")
    scenario = spec.get("scenario", "all")
    ssh_key = spec.get("ssh_key") or ""

    _validate_mode(agent_mode, "agent_mode")
    _validate_mode(manager_mode, "manager_mode")
    if scenario != "all":
        _validate_scenario(scenario)

    script = str(Path(radar_root) / "health-radar.sh")
    cmd = [
        "bash", script,
        "--manager", manager_mode,
        "--agent", agent_mode,
        "--scenario", scenario,
    ]
    if ssh_key:
        cmd += ["--ssh-key", ssh_key]
    return cmd


def preview(radar_root: str, spec: dict) -> dict:
    action = spec.get("action", "build")
    try:
        if action == "build":
            cmd = _build_cmd(radar_root, spec)
        elif action == "run":
            cmd = _run_cmd(radar_root, spec)
        elif action == "health":
            cmd = _health_cmd(radar_root, spec)
        else:
            raise ValueError(f"Unknown action '{action}'")
        return {"ok": True, "cmd": " ".join(shlex.quote(x) for x in cmd)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _needs_vault(radar_root: str, spec: dict) -> bool:
    if spec.get("action") == "run":
        return False
    if spec.get("manager_mode") != "remote" and spec.get("agent_mode") != "remote":
        return False
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


def _stream_process(cmd: list[str], cwd: str, env: dict) -> Iterator[str]:
    yield f"$ {' '.join(shlex.quote(x) for x in cmd)}\n\n"
    try:
        proc = subprocess.Popen(
            cmd, cwd=cwd, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            bufsize=1, text=True,
        )
    except FileNotFoundError as e:
        yield f"[ERROR] executable not found: {e}\n"
        return

    assert proc.stdout is not None
    try:
        for line in iter(proc.stdout.readline, ""):
            yield line
        proc.stdout.close()
        rc = proc.wait()
        yield f"\n[exit code: {rc}]\n"
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def _stream_with_vault(radar_root: str, spec: dict, cmd_builder, vault_session_id: str | None) -> Iterator[str]:
    try:
        cmd = cmd_builder(radar_root, spec)
    except Exception as e:
        yield f"[ERROR] {e}\n"
        return

    use_vault = _needs_vault(radar_root, {**spec, "action": spec.get("action")})
    if use_vault and (not vault_session_id or not vault_module.has_password(vault_session_id)):
        yield "[ERROR] vault password required: encrypted host_vars/ files present. Unlock vault in the UI first.\n"
        return

    if use_vault:
        with vault_module.password_file(vault_session_id) as pf:
            base_env = _prep_env(radar_root, spec.get("ssh_key"), pf, vault_session_id)
            with vault_module.ssh_askpass_env(vault_session_id, base_env) as env:
                yield from _stream_process(cmd, radar_root, env)
    else:
        base_env = _prep_env(radar_root, spec.get("ssh_key"), None, vault_session_id)
        with vault_module.ssh_askpass_env(vault_session_id, base_env) as env:
            yield from _stream_process(cmd, radar_root, env)


def stream_build(radar_root: str, spec: dict, vault_session_id: str | None = None) -> Iterator[str]:
    yield from _stream_with_vault(radar_root, {**spec, "action": "build"}, _build_cmd, vault_session_id)


def stream_run(radar_root: str, spec: dict) -> Iterator[str]:
    try:
        cmd = _run_cmd(radar_root, spec)
    except Exception as e:
        yield f"[ERROR] {e}\n"
        return
    env = _prep_env(radar_root, None, None)
    yield from _stream_process(cmd, radar_root, env)


def stream_health(radar_root: str, spec: dict, vault_session_id: str | None = None) -> Iterator[str]:
    yield from _stream_with_vault(radar_root, {**spec, "action": "health"}, _health_cmd, vault_session_id)