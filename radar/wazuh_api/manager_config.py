"""
ossec.conf management via the Wazuh API.
"""
from __future__ import annotations

import re
import time
from typing import Tuple

import requests

from .client import WazuhAPIClient, WazuhAPIError

CONFIG_INVALID_ERROR = 1125


def get_raw_config(client: WazuhAPIClient) -> str:
    resp = client.get("/manager/configuration", params={"raw": "true"})
    return resp.text


def get_raw_config_for_node(client: WazuhAPIClient, node_name: str) -> str:
    resp = client.get(f"/cluster/{node_name}/configuration", params={"raw": "true"})
    return resp.text


def update_raw_config(client: WazuhAPIClient, content: str) -> str:
    resp = client.put(
        "/manager/configuration",
        data=content.encode("utf-8"),
        headers={"Content-Type": "application/octet-stream"},
    )
    return resp.json().get("message", "")


def update_raw_config_for_node(client: WazuhAPIClient, node_name: str, content: str) -> str:
    resp = client.put(
        f"/cluster/{node_name}/configuration",
        data=content.encode("utf-8"),
        headers={"Content-Type": "application/octet-stream"},
    )
    return resp.json().get("message", "")


def restart_manager(client: WazuhAPIClient) -> str:
    resp = client.put("/manager/restart")
    return resp.json().get("message", "")


def _yesish(v) -> bool:
    if isinstance(v, bool):
        return v
    return _safe_str(v).strip().lower() in ("yes", "true", "1")


def cluster_status(client: WazuhAPIClient) -> dict:
    resp = client.get("/cluster/status")
    data = resp.json().get("data") or {}
    return {
        "enabled": _yesish(data.get("enabled")),
        "running": _yesish(data.get("running")),
        "raw": data,
    }


def cluster_node_names(client: WazuhAPIClient) -> list:
    resp = client.get("/cluster/nodes")
    items = (resp.json().get("data") or {}).get("affected_items") or []
    return [n["name"] for n in items if n.get("name")]


def cluster_nodes(client: WazuhAPIClient) -> list:
    resp = client.get("/cluster/nodes")
    items = (resp.json().get("data") or {}).get("affected_items") or []
    return [{"name": n["name"], "type": n.get("type", "")} for n in items if n.get("name")]


def restart_cluster(client: WazuhAPIClient, nodes_list: list = None) -> str:
    params = {"nodes_list": ",".join(nodes_list)} if nodes_list else {}
    resp = client.put("/cluster/restart", params=params)
    return resp.json().get("message", "")


def restart_manager_or_cluster(client: WazuhAPIClient) -> dict:
    try:
        status = cluster_status(client)
    except WazuhAPIError as e:
        return {"mode": "manager", "reason": f"/cluster/status failed: {e}", "message": restart_manager(client)}
    if status.get("enabled"):
        return {"mode": "cluster", "cluster_status": status, "message": restart_cluster(client)}
    return {"mode": "manager", "reason": f"cluster not enabled ({status.get('raw')})", "message": restart_manager(client)}


def get_ruleset_validation(client: WazuhAPIClient) -> dict:
    resp = client.get("/manager/configuration/validation")
    data = resp.json().get("data") or {}
    items = data.get("affected_items") or []
    status = _safe_str((items[0] or {}).get("status")) if items else ""
    return {"ok": status.lower() == "ok", "status": status, "raw": data}


def check_lists_loaded(client: WazuhAPIClient, list_names: list) -> dict:
    if not list_names:
        return {"ok": True, "failures": []}
    resp = client.get("/manager/logs", params={
        "tag": "wazuh-analysisd", "level": "warning",
        "search": "could not be loaded", "limit": 500, "sort": "-timestamp",
    })
    items = (resp.json().get("data") or {}).get("affected_items") or []
    failures = []
    for item in items:
        desc = _safe_str(item.get("description"))
        for name in list_names:
            if name in desc and name not in failures:
                failures.append(name)
    return {"ok": not failures, "failures": sorted(failures)}


def _safe_str(v) -> str:
    return "" if v is None else str(v)


def wait_for_api(base_url: str, user: str, password: str,
                  timeout: float = 90.0, poll_interval: float = 3.0,
                  verify_ssl: bool = False, on_tick=None) -> bool:
    start = time.monotonic()
    deadline = start + timeout
    while time.monotonic() < deadline:
        try:
            resp = requests.post(
                f"{base_url.rstrip('/')}/security/user/authenticate",
                auth=(user, password), timeout=5, verify=verify_ssl,
            )
            if resp.status_code == 200:
                return True
        except requests.RequestException:
            pass
        if on_tick:
            on_tick(time.monotonic() - start, timeout)
        time.sleep(poll_interval)
    return False


def wait_for_opensearch(os_url: str, os_user: str, os_pass: str,
                         timeout: float = 90.0, poll_interval: float = 3.0,
                         verify_ssl: bool = False, on_tick=None) -> bool:
    start = time.monotonic()
    deadline = start + timeout
    while time.monotonic() < deadline:
        try:
            resp = requests.get(
                f"{os_url.rstrip('/')}/_cluster/health",
                auth=(os_user, os_pass), timeout=5, verify=verify_ssl,
            )
            if resp.status_code == 200 and resp.json().get("status") in ("yellow", "green"):
                return True
        except (requests.RequestException, ValueError):
            pass
        if on_tick:
            on_tick(time.monotonic() - start, timeout)
        time.sleep(poll_interval)
    return False


def apply_marked_block(content: str, marker_name: str, block: str,
                        insert_before: str = None, insert_after: str = None) -> Tuple[str, bool]:
    if (insert_before is None) == (insert_after is None):
        raise ValueError("Exactly one of insert_before or insert_after must be given")

    begin = f"<!-- RADAR: {marker_name} BEGIN -->"
    end = f"<!-- RADAR: {marker_name} END -->"
    block_body = block.strip("\n")
    new_block_text = f"{begin}\n{block_body}\n{end}"

    pattern = re.compile(re.escape(begin) + r".*?" + re.escape(end), re.DOTALL)
    if pattern.search(content):
        new_content = pattern.sub(lambda _m: new_block_text, content, count=1)
        return new_content, new_content != content

    if insert_before is not None:
        idx = content.find(insert_before)
        if idx == -1:
            raise ValueError(f"Could not find insertion anchor {insert_before!r} in ossec.conf content")
        new_content = content[:idx] + new_block_text + "\n" + content[idx:]
    else:
        idx = content.find(insert_after)
        if idx == -1:
            raise ValueError(f"Could not find insertion anchor {insert_after!r} in ossec.conf content")
        insert_at = idx + len(insert_after)
        new_content = content[:insert_at] + "\n" + new_block_text + content[insert_at:]
    return new_content, True


def remove_marked_block(content: str, marker_name: str) -> Tuple[str, bool]:
    begin = f"<!-- RADAR: {marker_name} BEGIN -->"
    end = f"<!-- RADAR: {marker_name} END -->"
    pattern = re.compile(r"[ \t]*" + re.escape(begin) + r".*?" + re.escape(end) + r"[ \t]*\n?", re.DOTALL)
    new_content, count = pattern.subn("", content, count=1)
    return new_content, count > 0


def apply_tag_value(content: str, tag: str, value: str) -> Tuple[str, bool]:
    pattern = re.compile(rf"(<{tag}>)[^<]*(</{tag}>)")
    new_content, count = pattern.subn(rf"\g<1>{value}\g<2>", content)
    return new_content, (count > 0 and new_content != content)