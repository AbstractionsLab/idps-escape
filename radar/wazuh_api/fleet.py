"""
Tracks enrolled agents in fleet.yaml
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Dict, Optional

import yaml


def fleet_path(radar_root: str = ".") -> Path:
    return Path(radar_root) / "fleet.yaml"


def load_fleet(radar_root: str = ".") -> Dict:
    path = fleet_path(radar_root)
    if not path.exists():
        return {"agents": {}}
    data = yaml.safe_load(path.read_text()) or {}
    data.setdefault("agents", {})
    return data


def _write_fleet(radar_root: str, data: Dict) -> None:
    path = fleet_path(radar_root)
    path.write_text(yaml.safe_dump(data, sort_keys=False))


def update_fleet_from_assignment_results(radar_root: str, results: Dict, scenario_name: str,
                                          agent_status: Optional[str] = None) -> None:
    fleet = load_fleet(radar_root)
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

    for key, outcome in results.items():
        entry = fleet["agents"].setdefault(key, {})
        entry["last_updated"] = now
        entry["last_scenario"] = scenario_name

        if not outcome.get("resolved", False):
            entry["last_action"] = "group_assignment_failed"
            entry["last_warning"] = outcome.get("warning", "")
            continue

        entry["agent_id"] = outcome.get("agent_id", entry.get("agent_id"))
        entry["resolved_via"] = outcome.get("resolved_via", entry.get("resolved_via"))
        entry["last_action"] = "group_assignment"
        entry.pop("last_warning", None)
        if agent_status:
            entry["status"] = agent_status

        existing_groups = set(entry.get("groups", []))
        new_groups = set(outcome.get("groups", []))
        entry["groups"] = sorted(existing_groups | new_groups)

    _write_fleet(radar_root, fleet)