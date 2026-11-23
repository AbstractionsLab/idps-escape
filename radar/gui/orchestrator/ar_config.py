from __future__ import annotations

import copy
import re
import threading
from pathlib import Path
from typing import Any

import yaml

_lock = threading.Lock()

BUILTIN_MITIGATIONS = ("firewall-drop",)

LEGACY_MITIGATION_ALIASES = {
    "lock_user_linux": "lock_user_linux.sh",
    "terminate_service": "terminate_service.sh",
}

MITIGATION_KEYS = ("mitigations_tier2", "mitigations_tier3", "mitigations_tier4")

_AR_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_SCRIPT_PATH_RE = re.compile(r"^active_responses/[A-Za-z0-9._/-]+$")


class CatalogError(Exception):
    """radar-agent/ar-scripts.yaml is missing or invalid."""


def _ar_path(radar_root: str | Path) -> Path:
    return Path(radar_root) / "scenarios" / "active_responses" / "ar.yaml"


def _catalog_path(radar_root: str | Path) -> Path:
    return Path(radar_root) / "radar-agent" / "ar-scripts.yaml"


def load_catalog(radar_root: str | Path) -> dict[str, str]:
    """Endpoint script catalog: {active response name: script path}.

    Read-only for the GUI. It is the list of shell actions every enrolled
    endpoint can run; which scenario uses them is ar.yaml's job.
    """
    p = _catalog_path(radar_root)
    try:
        data = yaml.safe_load(p.read_text()) or {}
    except FileNotFoundError:
        raise CatalogError(f"{p} not found")
    except yaml.YAMLError as e:
        raise CatalogError(f"{p} is not valid YAML: {e}")
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if scripts is None:
        scripts = {}
    if not isinstance(scripts, dict):
        raise CatalogError(f"{p}: 'scripts' must map active response names to script paths")
    catalog: dict[str, str] = {}
    for name, path in scripts.items():
        if not isinstance(name, str) or not _AR_NAME_RE.match(name):
            raise CatalogError(f"{p}: invalid active response name {name!r}")
        if not isinstance(path, str) or not _SCRIPT_PATH_RE.match(path) or \
                any(seg in ("", ".", "..") for seg in path.split("/")):
            raise CatalogError(f"{p}: invalid script path {path!r} for {name!r}")
        catalog[name] = path
    return catalog


def catalog_problem(radar_root: str | Path) -> str | None:
    """Why the catalog cannot be used, or None if it is fine."""
    try:
        load_catalog(radar_root)
        return None
    except CatalogError as e:
        return str(e)


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
    try:
        catalog = load_catalog(radar_root)
    except CatalogError:
        catalog = {}
    return list(BUILTIN_MITIGATIONS) + [n for n in catalog if n not in BUILTIN_MITIGATIONS]


def normalize_mitigations(radar_root: str | Path, values: Any) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        raise ValueError("mitigations must be a list of action names")
    known = list_known_mitigations(radar_root)
    out: list[str] = []
    unknown: list[str] = []
    for v in values:
        name = LEGACY_MITIGATION_ALIASES.get(v.strip(), v.strip())
        if name not in known:
            unknown.append(v)
        elif name not in out:
            out.append(name)
    if unknown:
        problem = catalog_problem(radar_root)
        hint = (f" (the endpoint script catalog is unusable: {problem})" if problem
                else " -- add it to radar-agent/ar-scripts.yaml first")
        raise ValueError(
            f"unknown mitigation(s): {', '.join(unknown)}. "
            f"Available: {', '.join(known)}{hint}"
        )
    return out


def _normalize_patch_mitigations(radar_root: str | Path, patch: dict) -> dict:
    patch = dict(patch)
    for key in MITIGATION_KEYS:
        if key in patch:
            patch[key] = normalize_mitigations(radar_root, patch[key])
    return patch


def bind_scenario(radar_root: str | Path, scenario_id: str,
                  mitigations: list[str] | None = None) -> None:
    if mitigations is not None:
        mitigations = normalize_mitigations(radar_root, mitigations)
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
    if not isinstance(patch, dict):
        raise ValueError("expected a JSON object")
    patch = _normalize_patch_mitigations(radar_root, patch)
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