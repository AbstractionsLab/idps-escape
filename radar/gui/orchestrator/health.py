from __future__ import annotations

import os
import subprocess
from pathlib import Path

from . import connectors as conn_module


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


def _run(cmd: list[str], radar_root: str, timeout: int = 90) -> list[str]:
    env = os.environ.copy()
    env.update(conn_module.load_env(radar_root))
    env.setdefault("PYTHONPATH", radar_root)
    env.setdefault("PYTHONUNBUFFERED", "1")
    try:
        result = subprocess.run(cmd, cwd=radar_root, env=env, capture_output=True, text=True, timeout=timeout)
        lines = (result.stdout or "").splitlines()
        if result.returncode != 0 and not lines:
            lines = [f"FAIL - {' '.join(cmd)} exited {result.returncode}: {(result.stderr or '').strip()[:300]}"]
        return lines
    except FileNotFoundError as e:
        return [f"FAIL - command not found: {e}"]
    except subprocess.TimeoutExpired:
        return [f"FAIL - {' '.join(cmd)} timed out after {timeout}s"]


def check_manager(radar_root: str, manager: dict, bound_scenarios: list, **_ignored) -> dict:
    name = manager.get("name", "wazuh.manager")
    scenario_filter = bound_scenarios[0] if len(bound_scenarios) == 1 else "all"

    lines = _run(["bash", str(Path(radar_root, "radar_deploy", "manager-health.sh")), scenario_filter], radar_root)
    lines += _run(["python3", "-m", "wazuh_api.cli", "manager-health-api", "--scenario", scenario_filter], radar_root)

    checks = _parse_lines(lines)
    return {"name": name, "type": "manager", "checks": checks, **_tally(checks)}


def check_agent(radar_root: str, agent: dict, **_ignored) -> dict:
    name = agent["name"]
    lines = _run(["python3", "-m", "wazuh_api.cli", "agent-health", "--agent-name", name, "--scenario", "all"],
                 radar_root)
    checks = _parse_lines(lines)
    return {"name": name, "type": "agent", "checks": checks, **_tally(checks)}