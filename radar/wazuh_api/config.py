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


def _manager_service_name(radar_root: str) -> str:
    try:
        from . import infra as infra_module
        name = infra_module.container_for(radar_root, "manager")
        if name:
            return name
    except Exception:
        pass
    return "wazuh.manager"


def _load_service_cfg(radar_root: str, service: str) -> dict:
    path = Path(radar_root) / "volumes.yml"
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text()) or {}
    return (data.get("services") or {}).get(service) or {}


def manager_volume_host_paths(radar_root: str = ".", service: str | None = None) -> list[str]:
    service = service or _manager_service_name(radar_root)
    service_cfg = _load_service_cfg(radar_root, service)
    host_paths: list[str] = []
    for entry in service_cfg.get("volumes") or []:
        if not isinstance(entry, str) or ":" not in entry:
            continue
        host_side = entry.split(":", 1)[0]
        if host_side.startswith(("/", "./", "../", "~")):
            host_paths.append(host_side)
    return host_paths


def manager_volume_host_path_for(radar_root: str, container_path: str,
                                  service: str | None = None) -> str | None:
    service = service or _manager_service_name(radar_root)
    service_cfg = _load_service_cfg(radar_root, service)
    for entry in service_cfg.get("volumes") or []:
        if not isinstance(entry, str) or ":" not in entry:
            continue
        host_side, _, container_side = entry.partition(":")
        # Strip an optional trailing mode flag, e.g. "...:/path:ro"
        container_side = container_side.split(":", 1)[0]
        if container_side == container_path and host_side.startswith(("/", "./", "../", "~")):
            return host_side
    return None


def _core_compose_services(radar_root: str) -> set:
    path = Path(radar_root) / "docker-compose.core.yml"
    if not path.exists():
        return set()
    data = yaml.safe_load(path.read_text()) or {}
    return set((data.get("services") or {}).keys())


def core_volumes_overlay_yaml(radar_root: str) -> str:
    core_services = _core_compose_services(radar_root)
    path = Path(radar_root) / "volumes.yml"
    data = yaml.safe_load(path.read_text()) if path.exists() else {}
    all_services = (data or {}).get("services") or {}
    filtered = {k: v for k, v in all_services.items() if k in core_services}
    return yaml.safe_dump({"services": filtered}, sort_keys=False)