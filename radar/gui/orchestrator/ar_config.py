from __future__ import annotations

import copy
import threading
from pathlib import Path
from typing import Any

import yaml

_lock = threading.Lock()


def _ar_path(radar_root: str | Path) -> Path:
    return Path(radar_root) / "scenarios" / "active_responses" / "ar.yaml"


def load(radar_root: str | Path) -> dict:
    p = _ar_path(radar_root)
    with _lock:
        with p.open() as f:
            return yaml.safe_load(f) or {}


def get_scenario(radar_root: str | Path, scenario_id: str) -> dict:
    data = load(radar_root)
    scenarios = data.get("scenarios", {})
    default = scenarios.get("default", {})
    specific = scenarios.get(scenario_id, {})
    merged = copy.deepcopy(default)
    _deep_merge(merged, specific)
    return merged


def list_bound_scenarios(radar_root: str | Path) -> list[str]:
    data = load(radar_root)
    scenarios = data.get("scenarios", {})
    return [k for k in scenarios if k != "default"]


def list_known_mitigations(radar_root: str | Path) -> list[str]:
    return ["firewall-drop", "lock_user_linux", "terminate_service"]


def bind_scenario(radar_root: str | Path, scenario_id: str,
                  mitigations: list[str] | None = None) -> None:
    p = _ar_path(radar_root)
    with _lock:
        with p.open() as f:
            data = yaml.safe_load(f) or {}
        scenarios = data.setdefault("scenarios", {})
        if scenario_id in scenarios:
            if mitigations is not None:
                scenarios[scenario_id]["mitigations_tier2"] = mitigations
                scenarios[scenario_id]["mitigations_tier3"] = mitigations
                _write(p, data)
            return
        default = scenarios.get("default", {})
        mit = mitigations or []
        skeleton: dict[str, Any] = {
            "ad": {"rule_ids": []},
            "signature": {"rule_ids": []},
            "w_ad": default.get("w_ad", 0.0),
            "w_sig": default.get("w_sig", 0.7),
            "w_cti": default.get("w_cti", 0.3),
            "delta_ad_minutes": 10,
            "delta_signature_minutes": 1,
            "signature_impact": default.get("signature_impact", 0.5),
            "signature_likelihood": default.get("signature_likelihood", 0.6),
            "tiers": copy.deepcopy(default.get("tiers", {
                "tier1_min": 0.0,
                "tier1_max": 0.33,
                "tier2_max": 0.66,
                "tier3_max": 0.85,
            })),
            "mitigations_tier2": mit,
            "mitigations_tier3": mit,
            "mitigations_tier4": mit,
            "allow_mitigation": False,
        }
        scenarios[scenario_id] = skeleton
        _write(p, data)


def unbind_scenario(radar_root: str | Path, scenario_id: str) -> None:
    p = _ar_path(radar_root)
    with _lock:
        with p.open() as f:
            data = yaml.safe_load(f) or {}
        scenarios = data.get("scenarios", {})
        if scenario_id in scenarios:
            del scenarios[scenario_id]
            _write(p, data)


def is_deployed(radar_root: str | Path, scenario_id: str) -> bool:
    return bool(get_scenario(radar_root, scenario_id).get("active"))


def mark_deployed(radar_root: str | Path, scenario_id: str, deployed: bool) -> None:
    update_scenario(radar_root, scenario_id, {"active": deployed})


def update_scenario(radar_root: str | Path, scenario_id: str, patch: dict) -> None:
    p = _ar_path(radar_root)
    with _lock:
        with p.open() as f:
            data = yaml.safe_load(f) or {}
        scenarios = data.setdefault("scenarios", {})
        existing = scenarios.get(scenario_id, {})
        _deep_merge(existing, patch)
        scenarios[scenario_id] = existing
        _write(p, data)


def _write(p: Path, data: dict) -> None:
    tmp = p.with_suffix(".yaml.tmp")
    with tmp.open("w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    tmp.replace(p)


def _deep_merge(base: dict, override: dict) -> None:
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v