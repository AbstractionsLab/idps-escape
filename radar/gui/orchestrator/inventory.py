from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import yaml

_lock = threading.Lock()


def _inv_path(root: str) -> Path:
    return Path(root) / "inventory.yaml"


def _hv_dir(root: str) -> Path:
    return Path(root) / "host_vars"


def _hv_path(root: str, name: str) -> Path:
    return _hv_dir(root) / f"{name}.yml"


def _load(root: str) -> dict:
    p = _inv_path(root)
    if not p.exists():
        return {"all": {"children": {}}}
    with p.open() as f:
        return yaml.safe_load(f) or {}


def _save(root: str, data: dict) -> None:
    p = _inv_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".yaml.tmp")
    with tmp.open("w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    tmp.replace(p)


def _children(data: dict) -> dict:
    return data.setdefault("all", {}).setdefault("children", {})


def _hosts_of(data: dict, group: str) -> dict:
    return ((_children(data).get(group) or {}).get("hosts")) or {}


def save_credential(root: str, hostname: str, become_password: str, vault_session_id: str) -> None:
    from . import vault
    if not vault.has_password(vault_session_id):
        raise vault.VaultPasswordMissing("vault password required")
    _hv_dir(root).mkdir(exist_ok=True)
    p = _hv_path(root, hostname)
    vault.encrypt_host_vars(vault_session_id, p, become_password)


def has_credential(root: str, hostname: str) -> bool:
    p = _hv_path(root, hostname)
    if not p.exists():
        return False
    try:
        with p.open() as f:
            head = f.read(32)
        if head.startswith("$ANSIBLE_VAULT"):
            return True
        with p.open() as f:
            data = yaml.safe_load(f)
        return bool(isinstance(data, dict) and data.get("ansible_become_password"))
    except Exception:
        return p.stat().st_size > 0


def delete_credential(root: str, hostname: str) -> None:
    p = _hv_path(root, hostname)
    if p.exists():
        p.unlink()


def _norm_manager(name: str, vars_: dict, connection: str) -> dict:
    v = vars_ or {}
    raw_mode = v.get("manager_mode", "docker_local" if connection == "local" else "docker_remote")
    ui_kind = "docker" if raw_mode in ("docker_local", "docker_remote") else "host"
    return {
        "name": name,
        "manager_mode": raw_mode,
        "ui_kind": ui_kind,
        "connection": connection,
        "ip": v.get("manager_address_public") or v.get("ansible_host") or v.get("manager_address") or "",
        "container": v.get("manager_container_name", "wazuh.manager"),
        "service": v.get("manager_service_name", "wazuh.manager"),
        "ansible_user": v.get("ansible_user", ""),
        "ansible_port": v.get("ansible_port", 22) if connection == "remote" else 0,
        "ansible_become_method": v.get("ansible_become_method", "sudo"),
    }


def _norm_agent(name: str, vars_: dict) -> dict:
    v = vars_ or {}
    mode = v.get("agent_mode", "ssh")
    return {
        "name": name,
        "agent_mode": mode,
        "connection": "local" if mode == "container" else "remote",
        "container": v.get("container_name", name) if mode == "container" else "",
        "ip": v.get("ansible_host", "") if mode == "ssh" else "",
        "ansible_user": v.get("ansible_user", "") if mode == "ssh" else "",
        "ansible_port": v.get("ansible_port", 22) if mode == "ssh" else 0,
        "ansible_become_method": v.get("ansible_become_method", "sudo"),
    }


def get_managers(root: str) -> list:
    data = _load(root)
    out = []
    for name, v in _hosts_of(data, "wazuh_manager_local").items():
        m = _norm_manager(name, v, "local")
        m["has_credential"] = has_credential(root, name)
        out.append(m)
    for name, v in _hosts_of(data, "wazuh_manager_ssh").items():
        m = _norm_manager(name, v, "remote")
        m["has_credential"] = has_credential(root, name)
        out.append(m)
    return out


def get_agents(root: str) -> list:
    data = _load(root)
    out = []
    for name, v in _hosts_of(data, "wazuh_agents_container").items():
        a = _norm_agent(name, v)
        a["has_credential"] = has_credential(root, name)
        out.append(a)
    for name, v in _hosts_of(data, "wazuh_agents_ssh").items():
        a = _norm_agent(name, v)
        a["has_credential"] = has_credential(root, name)
        out.append(a)
    return out


def get_summary(root: str) -> dict:
    managers = get_managers(root)
    agents = get_agents(root)
    return {
        "managers": managers,
        "agents": agents,
        "manager_count": len(managers),
        "agent_count": len(agents),
        "local_managers": [m for m in managers if m["connection"] == "local"],
        "remote_managers": [m for m in managers if m["connection"] == "remote"],
        "container_agents": [a for a in agents if a["agent_mode"] == "container"],
        "ssh_agents": [a for a in agents if a["agent_mode"] == "ssh"],
    }


def _resolve_manager_mode(spec: dict) -> str:
    m = spec.get("manager_mode")
    if m in ("docker_local", "docker_remote", "host_remote"):
        return m
    ui_kind = (spec.get("ui_kind") or "docker").lower()
    is_local = bool(spec.get("is_local"))
    ip = (spec.get("ip") or "").strip()
    if ui_kind == "host":
        return "host_remote"
    if is_local or not ip:
        return "docker_local"
    return "docker_remote"


def _manager_hostvars(spec: dict) -> tuple[str, dict]:
    manager_mode = _resolve_manager_mode(spec)
    is_local = manager_mode == "docker_local"

    container = (spec.get("container") or "").strip() or "wazuh.manager"
    service = (spec.get("service") or "").strip() or container

    hv: dict[str, Any] = {
        "manager_mode": manager_mode,
        "manager_container_name": container,
        "manager_service_name": service,
    }

    if is_local:
        hv["ansible_connection"] = "local"
        hv["manager_address"] = container
        hv["manager_address_public"] = spec.get("ip", "") or ""
    else:
        ip = (spec.get("ip") or "").strip()
        hv.update({
            "ansible_host": ip,
            "ansible_user": spec.get("ansible_user", ""),
            "ansible_port": int(spec.get("ansible_port") or 22),
            "manager_address": ip,
            "manager_address_public": ip,
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_become": True,
            "ansible_become_method": spec.get("ansible_become_method", "sudo"),
            "ansible_ssh_common_args": "-o StrictHostKeyChecking=no -o ConnectTimeout=10",
        })
    return manager_mode, hv


def _agent_hostvars(spec: dict, fallback_name: str) -> tuple[str, dict]:
    is_cont = spec["agent_mode"] == "container"
    if is_cont:
        container = (spec.get("container") or "").strip() or fallback_name
        return "wazuh_agents_container", {
            "agent_mode": "container",
            "container_name": container,
        }
    return "wazuh_agents_ssh", {
        "agent_mode": "ssh",
        "ansible_host": (spec.get("ip") or "").strip(),
        "ansible_user": spec.get("ansible_user", ""),
        "ansible_port": int(spec.get("ansible_port") or 22),
        "ansible_become": True,
        "ansible_become_method": spec.get("ansible_become_method", "sudo"),
    }


def _ensure_manager_parent_group(data: dict) -> None:
    ch = _children(data)
    ch.setdefault("wazuh_manager", {}).setdefault("children", {}).update(
        {"wazuh_manager_local": None, "wazuh_manager_ssh": None}
    )


def add_manager(root: str, spec: dict) -> None:
    name = spec["name"].strip()
    manager_mode, hv = _manager_hostvars(spec)
    is_local = manager_mode == "docker_local"

    with _lock:
        data = _load(root)
        for grp in ("wazuh_manager_local", "wazuh_manager_ssh"):
            if name in _hosts_of(data, grp):
                raise ValueError(f"Manager '{name}' already exists")
        grp = "wazuh_manager_local" if is_local else "wazuh_manager_ssh"
        _children(data).setdefault(grp, {}).setdefault("hosts", {})[name] = hv
        _ensure_manager_parent_group(data)
        _save(root, data)


def update_manager(root: str, name: str, spec: dict) -> None:
    manager_mode, hv = _manager_hostvars(spec)
    new_is_local = manager_mode == "docker_local"
    new_grp = "wazuh_manager_local" if new_is_local else "wazuh_manager_ssh"

    with _lock:
        data = _load(root)
        found_grp = None
        for grp in ("wazuh_manager_local", "wazuh_manager_ssh"):
            hosts = _hosts_of(data, grp)
            if name in hosts:
                found_grp = grp
                break
        if not found_grp:
            raise ValueError(f"Manager '{name}' not found")
        if found_grp != new_grp:
            del _hosts_of(data, found_grp)[name]
        _children(data).setdefault(new_grp, {}).setdefault("hosts", {})[name] = hv
        _ensure_manager_parent_group(data)
        _save(root, data)


def delete_manager(root: str, name: str) -> None:
    with _lock:
        data = _load(root)
        for grp in ("wazuh_manager_local", "wazuh_manager_ssh"):
            hosts = _hosts_of(data, grp)
            if name in hosts:
                del hosts[name]
                break
        _save(root, data)
    delete_credential(root, name)


def add_agent(root: str, spec: dict) -> None:
    name = spec["name"].strip()
    grp, hv = _agent_hostvars(spec, name)
    with _lock:
        data = _load(root)
        for g in ("wazuh_agents_container", "wazuh_agents_ssh"):
            if name in _hosts_of(data, g):
                raise ValueError(f"Agent '{name}' already exists")
        _children(data).setdefault(grp, {}).setdefault("hosts", {})[name] = hv
        _save(root, data)


def update_agent(root: str, name: str, spec: dict) -> None:
    new_grp, hv = _agent_hostvars(spec, name)
    with _lock:
        data = _load(root)
        found_grp = None
        for grp in ("wazuh_agents_container", "wazuh_agents_ssh"):
            hosts = _hosts_of(data, grp)
            if name in hosts:
                found_grp = grp
                break
        if not found_grp:
            raise ValueError(f"Agent '{name}' not found")
        if found_grp != new_grp:
            del _hosts_of(data, found_grp)[name]
        _children(data).setdefault(new_grp, {}).setdefault("hosts", {})[name] = hv
        _save(root, data)


def delete_agent(root: str, name: str) -> None:
    with _lock:
        data = _load(root)
        for grp in ("wazuh_agents_container", "wazuh_agents_ssh"):
            hosts = _hosts_of(data, grp)
            if name in hosts:
                del hosts[name]
                break
        _save(root, data)
    delete_credential(root, name)