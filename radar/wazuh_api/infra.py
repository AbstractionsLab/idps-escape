from __future__ import annotations

import re
import socket
import subprocess
import sys
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    yaml = None

COMPONENTS = ("indexer", "manager", "dashboard")
MULTI_COMPONENTS = ("indexer", "manager")
SINGLE_COMPONENTS = ("dashboard",)

_DEFAULT_CONTAINER_NAMES = {
    "indexer": "wazuh.indexer",
    "manager": "wazuh.manager",
    "dashboard": "wazuh.dashboard",
}
_DEFAULT_PORTS = {
    "indexer": (9200, "https"),
    "manager": (55000, "https"),
    "dashboard": (5601, "https"),
}


class NotConfigured(Exception):
    pass


_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")


def validate_name(value, what: str, allow_empty: bool = False) -> str:
    value = "" if value is None else str(value).strip()
    if not value and allow_empty:
        return ""
    if not _NAME_RE.match(value):
        raise ValueError(f"{what} must match [A-Za-z0-9][A-Za-z0-9._-]* (got {value!r})")
    return value


def validate_port(value, what: str = "port") -> int:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError(f"{what} must be an integer (got {value!r})")
    if not 1 <= port <= 65535:
        raise ValueError(f"{what} must be between 1 and 65535 (got {port})")
    return port


def validate_scheme(value) -> str:
    value = (value or "https").strip().lower()
    if value not in ("http", "https"):
        raise ValueError(f"scheme must be http or https (got {value!r})")
    return value


def _validated(cfg: dict) -> dict:
    out = dict(cfg)
    out["container_name"] = validate_name(cfg.get("container_name"), "container_name")
    out["host"] = validate_name(cfg.get("host"), "host", allow_empty=True)
    out["port"] = validate_port(cfg.get("port"))
    out["scheme"] = validate_scheme(cfg.get("scheme"))
    return out


def _infra_path(radar_root: str) -> Path:
    return Path(radar_root) / "infra.yaml"


def _load_raw(radar_root: str) -> dict:
    path = _infra_path(radar_root)
    if not path.exists() or yaml is None:
        return {}
    with path.open() as f:
        return yaml.safe_load(f) or {}


def save(radar_root: str, data: dict) -> None:
    if yaml is None:
        raise RuntimeError("PyYAML is required to save infra.yaml")
    with _infra_path(radar_root).open("w") as f:
        yaml.safe_dump(data, f, sort_keys=False)


def detect_local_ip() -> Optional[str]:
    try:
        proc = subprocess.run(["ip", "route", "get", "1.1.1.1"], capture_output=True, text=True, timeout=5)
        parts = (proc.stdout or "").split()
        for i, p in enumerate(parts):
            if p == "src" and i + 1 < len(parts):
                return parts[i + 1]
    except Exception:
        pass
    try:
        proc = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=5)
        ips = [ip for ip in (proc.stdout or "").split() if ip and not ip.startswith("127.")]
        return ips[0] if ips else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# dashboard: single instance
# ---------------------------------------------------------------------------

def _normalize_single(cfg: dict, component: str) -> dict:
    return {
        "container_name": cfg.get("container_name") or _DEFAULT_CONTAINER_NAMES[component],
        "host": cfg.get("host") or cfg.get("host_ip") or "",
        "port": cfg.get("port") or _DEFAULT_PORTS[component][0],
        "scheme": cfg.get("scheme") or _DEFAULT_PORTS[component][1],
    }


def get_component(radar_root: str, component: str) -> dict:
    comps = _load_raw(radar_root).get("components", {}) or {}
    return _normalize_single(comps.get(component) or {}, component)


def upsert_component(radar_root: str, component: str, cfg: dict) -> dict:
    if component not in SINGLE_COMPONENTS:
        raise ValueError(f"'{component}' is not a single-instance component")
    data = _load_raw(radar_root)
    comps = data.setdefault("components", {})
    comps[component] = _validated(_normalize_single(cfg, component))
    save(radar_root, data)
    return comps[component]


def delete_component(radar_root: str, component: str) -> None:
    data = _load_raw(radar_root)
    comps = data.get("components", {})
    if component in comps:
        del comps[component]
        save(radar_root, data)


# ---------------------------------------------------------------------------
# indexer / manager: list of named nodes each, supports clusters
# ---------------------------------------------------------------------------

def _nodes_key(role: str) -> str:
    return f"{role}_nodes"


def _normalize_node(node: dict, node_id: str, role: str) -> dict:
    return {
        "id": node.get("id", node_id),
        "container_name": node.get("container_name") or _DEFAULT_CONTAINER_NAMES[role],
        "host": node.get("host") or node.get("host_ip") or "",
        "port": node.get("port") or _DEFAULT_PORTS[role][0],
        "scheme": node.get("scheme") or _DEFAULT_PORTS[role][1],
        "primary": bool(node.get("primary", False)),
    }


def list_nodes(radar_root: str, role: str) -> list[dict]:
    comps = _load_raw(radar_root).get("components", {}) or {}
    raw = comps.get(_nodes_key(role)) or []
    nodes = []
    seen = set()
    for i, n in enumerate(raw):
        if not isinstance(n, dict):
            continue
        node_id = n.get("id") or f"{role}-{i + 1}"
        while node_id in seen:
            node_id = f"{node_id}-2"
        seen.add(node_id)
        nodes.append(_normalize_node(n, node_id, role))
    if nodes and not any(n["primary"] for n in nodes):
        nodes[0]["primary"] = True
    return nodes


def primary_node(radar_root: str, role: str) -> Optional[dict]:
    nodes = list_nodes(radar_root, role)
    if not nodes:
        return None
    return next((n for n in nodes if n["primary"]), nodes[0])


def _next_node_id(nodes: list[dict], role: str) -> str:
    i = len(nodes) + 1
    existing = {n["id"] for n in nodes}
    while f"{role}-{i}" in existing:
        i += 1
    return f"{role}-{i}"


def upsert_node(radar_root: str, role: str, cfg: dict, node_id: Optional[str] = None) -> dict:
    data = _load_raw(radar_root)
    comps = data.setdefault("components", {})
    nodes = list_nodes(radar_root, role)

    is_new = node_id is None or not any(n["id"] == node_id for n in nodes)
    if is_new:
        new_id = node_id or _next_node_id(nodes, role)
        node = _validated(_normalize_node({**cfg, "id": new_id}, new_id, role))
        if node["primary"] or not nodes:
            for n in nodes:
                n["primary"] = False
            node["primary"] = True
        nodes.append(node)
        saved = node
    else:
        saved = None
        for i, n in enumerate(nodes):
            if n["id"] == node_id:
                nodes[i] = _validated(_normalize_node({**n, **cfg, "id": node_id}, node_id, role))
                if nodes[i]["primary"]:
                    for j, other in enumerate(nodes):
                        if j != i:
                            other["primary"] = False
                saved = nodes[i]
                break
        if not any(n["primary"] for n in nodes):
            nodes[0]["primary"] = True

    comps[_nodes_key(role)] = nodes
    save(radar_root, data)
    return saved


def delete_node(radar_root: str, role: str, node_id: str) -> None:
    nodes = list_nodes(radar_root, role)
    if len(nodes) <= 1:
        raise ValueError(f"Can't remove the only {role} node.")
    remaining = [n for n in nodes if n["id"] != node_id]
    if not any(n["primary"] for n in remaining):
        remaining[0]["primary"] = True
    data = _load_raw(radar_root)
    data.setdefault("components", {})[_nodes_key(role)] = remaining
    save(radar_root, data)


def set_primary_node(radar_root: str, role: str, node_id: str) -> None:
    nodes = list_nodes(radar_root, role)
    if not any(n["id"] == node_id for n in nodes):
        raise KeyError(f"No such {role} node '{node_id}'")
    for n in nodes:
        n["primary"] = (n["id"] == node_id)
    data = _load_raw(radar_root)
    data.setdefault("components", {})[_nodes_key(role)] = nodes
    save(radar_root, data)


def address(radar_root: str, component: str, path: str = "") -> str:
    if component in MULTI_COMPONENTS:
        node = primary_node(radar_root, component)
        if not node or not node.get("host"):
            raise NotConfigured(f"'{component}' has no host configured")
        return f"{node['scheme']}://{node['host']}:{node['port']}{path}"
    cfg = get_component(radar_root, component)
    if not cfg.get("host"):
        raise NotConfigured(f"'{component}' has no host configured")
    return f"{cfg['scheme']}://{cfg['host']}:{cfg['port']}{path}"


def container_for(radar_root: str, component: str, default: Optional[str] = None) -> str:
    if component in MULTI_COMPONENTS:
        node = primary_node(radar_root, component)
        name = (node or {}).get("container_name") or default or _DEFAULT_CONTAINER_NAMES[component]
    else:
        cfg = get_component(radar_root, component)
        name = cfg.get("container_name") or default or _DEFAULT_CONTAINER_NAMES.get(component, "")
    if name and not _NAME_RE.match(str(name)):
        raise ValueError(f"infra.yaml: invalid container_name for {component}: {name!r}")
    return name


def test_reachable(radar_root: str, from_component: str, to_component: str, timeout: float = 5.0) -> dict:
    try:
        from_container = container_for(radar_root, from_component)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    if not from_container:
        return {"ok": False, "error": f"'{from_component}' has no container to exec into"}
    try:
        url = address(radar_root, to_component)
    except NotConfigured as e:
        return {"ok": False, "error": str(e)}

    cmd = ["docker", "exec", from_container, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
           "--max-time", str(timeout), "-k", url]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
    except Exception as e:
        return {"ok": False, "error": str(e), "url": url}
    status = (proc.stdout or "").strip()
    if status.isdigit():
        return {"ok": True, "url": url, "http_status": status}
    return {"ok": False, "error": (proc.stderr or "no response").strip(), "url": url}


def ensure_radar_components_registered(radar_root: str) -> None:
    default_host = detect_local_ip()
    data = _load_raw(radar_root)
    comps = data.setdefault("components", {})
    for name in SINGLE_COMPONENTS:
        normalized = _normalize_single(comps.get(name) or {}, name)
        if not normalized["host"]:
            normalized["host"] = default_host or ""
        comps[name] = normalized
    for role in MULTI_COMPONENTS:
        key = _nodes_key(role)
        if not comps.get(key):
            node = _normalize_node({"primary": True}, f"{role}-1", role)
            node["host"] = default_host or ""
            comps[key] = [node]
    save(radar_root, data)


def _read_env_value(radar_root: str, key: str, default: str = "") -> str:
    from wazuh_api import envfile
    return envfile.load(Path(radar_root) / ".env").get(key) or default


def _http_probe(radar_root: str, from_component: str, url: str, timeout: float) -> bool:
    cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", str(timeout), "-k", url]
    if from_component != "host":
        try:
            c = container_for(radar_root, from_component)
        except ValueError:
            return False
        if not c:
            return False
        cmd = ["docker", "exec", c] + cmd
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
    except Exception:
        return False
    code = (proc.stdout or "").strip()
    return proc.returncode == 0 and code.isdigit() and code != "000"


def _tcp_probe(radar_root: str, from_component: str, host: str, port, timeout: float) -> bool:
    try:
        host = validate_name(host, "host")
        port = validate_port(port)
    except ValueError:
        return False
    if from_component == "host":
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False
    try:
        c = container_for(radar_root, from_component)
    except ValueError:
        return False
    if not c:
        return False
    cmd = ["docker", "exec", c, "timeout", str(timeout), "bash", "-c",
           'exec 3<>"/dev/tcp/$1/$2"', "_", host, str(port)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
    except Exception:
        return False
    return proc.returncode == 0


def _candidates(declared_host: str, declared_port, container_name: Optional[str], container_port) -> list[tuple[str, str]]:
    out = []
    if declared_host:
        out.append((declared_host, declared_port))
    if container_name:
        out.append((container_name, container_port or declared_port))
    return out


def resolve_host(radar_root: str, from_component: str, declared_host: str, declared_port,
                  container_name: Optional[str] = None, container_port=None,
                  protocol: str = "http", scheme: str = "https", path: str = "",
                  timeout: float = 3.0) -> tuple[str, str]:
    candidates = _candidates(declared_host, declared_port, container_name, container_port)
    if not candidates:
        return declared_host, declared_port
    for host, port in candidates:
        if protocol == "tcp":
            ok = _tcp_probe(radar_root, from_component, host, port, timeout)
        else:
            ok = _http_probe(radar_root, from_component, f"{scheme}://{host}:{port}{path}", timeout)
        if ok:
            return host, port
    return candidates[-1]


def resolve_url(radar_root: str, from_component: str, to_component: str, path: str = "",
                 timeout: float = 3.0) -> str:
    if to_component in MULTI_COMPONENTS:
        node = primary_node(radar_root, to_component)
        if not node:
            raise NotConfigured(f"'{to_component}' has no host configured")
        declared_host, declared_port, scheme = node.get("host") or "", node["port"], node["scheme"]
        container_name = node.get("container_name")
    else:
        cfg = get_component(radar_root, to_component)
        declared_host, declared_port, scheme = cfg.get("host") or "", cfg["port"], cfg["scheme"]
        container_name = cfg.get("container_name")
    if not declared_host and not container_name:
        raise NotConfigured(f"'{to_component}' has no host configured")
    host, port = resolve_host(radar_root, from_component, declared_host, declared_port,
                               container_name=container_name, container_port=declared_port,
                               protocol="http", scheme=scheme, path=path, timeout=timeout)
    return f"{scheme}://{host}:{port}{path}"


def resolve_webhook_url(radar_root: str, from_component: str, declared_url: str,
                          timeout: float = 3.0) -> str:
    if not declared_url:
        raise NotConfigured("WEBHOOK_URL is not configured")
    container_name = _read_env_value(radar_root, "WEBHOOK_CONTAINER_NAME", "ad-webhook")
    container_port = _read_env_value(radar_root, "WEBHOOK_INTERNAL_PORT", "8080")
    scheme, _, rest = declared_url.partition("://")
    hostport, _, path = rest.partition("/")
    path = f"/{path}" if path else ""
    declared_host, _, declared_port = hostport.partition(":")
    declared_port = declared_port or (443 if scheme == "https" else 80)
    host, port = resolve_host(radar_root, from_component, declared_host, declared_port,
                               container_name=container_name, container_port=container_port,
                               protocol="http", scheme=scheme or "http", path=path, timeout=timeout)
    return f"{scheme or 'http'}://{host}:{port}{path}"


def resolve_manager_host(radar_root: str, from_component: str, declared_host: str,
                          port=1515, timeout: float = 3.0) -> str:
    node = primary_node(radar_root, "manager")
    container_name = (node or {}).get("container_name")
    host, _ = resolve_host(radar_root, from_component, declared_host, port,
                            container_name=container_name, container_port=1515,
                            protocol="tcp", timeout=timeout)
    return host


def _cli() -> None:
    args = sys.argv[1:]
    if len(args) >= 1 and args[0] == "register-radar-components":
        ensure_radar_components_registered(".")
        print("ok")
        return

    if len(args) >= 2 and args[0] == "container":
        name = container_for(".", args[1])
        if not name:
            print(f"'{args[1]}' has no container_name configured", file=sys.stderr)
            sys.exit(1)
        print(name)
        return

    if len(args) >= 2 and args[0] == "address":
        path = args[2] if len(args) > 2 else ""
        try:
            print(address(".", args[1], path=path))
        except NotConfigured as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)
        return

    if len(args) >= 3 and args[0] == "resolve":
        from_component, to_component = args[1], args[2]
        path = args[3] if len(args) > 3 else ""
        try:
            print(resolve_url(".", from_component, to_component, path=path))
        except NotConfigured as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)
        return

    if len(args) >= 3 and args[0] == "resolve-webhook":
        from_component, declared_url = args[1], args[2]
        try:
            print(resolve_webhook_url(".", from_component, declared_url))
        except NotConfigured as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)
        return

    if len(args) >= 3 and args[0] == "resolve-manager-host":
        from_component, declared_host = args[1], args[2]
        print(resolve_manager_host(".", from_component, declared_host))
        return

    print("usage: python3 -m wazuh_api.infra address <component> [path]", file=sys.stderr)
    print("       python3 -m wazuh_api.infra resolve <from> <to> [path]", file=sys.stderr)
    print("       python3 -m wazuh_api.infra resolve-webhook <from> <declared_url>", file=sys.stderr)
    print("       python3 -m wazuh_api.infra resolve-manager-host <from> <declared_host>", file=sys.stderr)
    print("       python3 -m wazuh_api.infra container <component>", file=sys.stderr)
    print("       python3 -m wazuh_api.infra register-radar-components", file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":
    _cli()