from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml


@lru_cache(maxsize=None)
def load(radar_root: str = ".") -> dict:
    path = Path(radar_root) / "config.yaml"
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text()) or {}


def valid_scenarios(radar_root: str = ".") -> set[str]:
    scenarios = load(radar_root).get("scenarios", {})
    return {name for name in scenarios if name != "default"}


def agent_service_by_scenario(radar_root: str = ".") -> dict[str, str]:
    scenarios = load(radar_root).get("scenarios", {})
    return {name: cfg["container_name"] for name, cfg in scenarios.items()
            if name != "default" and isinstance(cfg, dict) and "container_name" in cfg}


def shared_scenarios(radar_root: str = ".") -> set[str]:
    return set(load(radar_root).get("shared_scenarios", []))


def whitelist_scenarios(radar_root: str = ".") -> set[str]:
    return set(load(radar_root).get("whitelist_scenarios", []))


def gui_visible_scenarios(radar_root: str = ".") -> list[str]:
    scenarios = load(radar_root).get("scenarios", {})
    return sorted(name for name, cfg in scenarios.items()
                  if name != "default" and isinstance(cfg, dict) and cfg.get("gui_visible"))


def scenario_display_info(radar_root: str, scenario_name: str) -> dict:
    cfg = load(radar_root).get("scenarios", {}).get(scenario_name, {}) or {}
    return {
        "display_name": cfg.get("display_name", scenario_name),
        "description": cfg.get("description", ""),
        "status": cfg.get("status", "active"),
    }


def manager_volume_host_paths(radar_root: str = ".", service: str = "wazuh.manager") -> list[str]:
    path = Path(radar_root) / "volumes.yml"
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text()) or {}
    service_cfg = (data.get("services") or {}).get(service) or {}
    host_paths: list[str] = []
    for entry in service_cfg.get("volumes") or []:
        if not isinstance(entry, str) or ":" not in entry:
            continue
        host_side = entry.split(":", 1)[0]
        if host_side.startswith(("/", "./", "../", "~")):
            host_paths.append(host_side)
    return host_paths


def manager_volume_host_path_for(radar_root: str, container_path: str,
                                  service: str = "wazuh.manager") -> str | None:
    path = Path(radar_root) / "volumes.yml"
    if not path.exists():
        return None
    data = yaml.safe_load(path.read_text()) or {}
    service_cfg = (data.get("services") or {}).get(service) or {}
    for entry in service_cfg.get("volumes") or []:
        if not isinstance(entry, str) or ":" not in entry:
            continue
        host_side, _, container_side = entry.partition(":")
        # Strip an optional trailing mode flag, e.g. "...:/path:ro"
        container_side = container_side.split(":", 1)[0]
        if container_side == container_path and host_side.startswith(("/", "./", "../", "~")):
            return host_side
    return None