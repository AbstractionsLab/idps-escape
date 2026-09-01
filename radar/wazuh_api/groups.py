"""
Wazuh agent-group operations: create groups, upload agent.conf content to a
group, resolve an agent's numeric ID by name, and assign/unassign an agent
to/from one or more groups.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from .client import WazuhAPIClient, WazuhAPIError

GROUP_ALREADY_EXISTS = 1711


def ensure_group(client: WazuhAPIClient, group_id: str) -> bool:
    resp = client.post("/groups", json={"group_id": group_id},
                        tolerate_error_codes=[GROUP_ALREADY_EXISTS])
    body = resp.json()
    return body.get("error", 0) == 0


def upload_group_config(client: WazuhAPIClient, group_id: str, xml_content: str) -> str:
    resp = client.put(
        f"/groups/{group_id}/configuration",
        data=xml_content.encode("utf-8"),
        headers={"Content-Type": "application/xml"},
    )
    return resp.json().get("message", "")


def upload_group_config_from_file(client: WazuhAPIClient, group_id: str, file_path: str) -> str:
    with open(file_path, "r", encoding="utf-8") as f:
        return upload_group_config(client, group_id, f.read())


def get_agent_by_name(client: WazuhAPIClient, name: str) -> Optional[Dict]:
    """Return the agent's raw API record."""
    resp = client.get("/agents", params={"name": name})
    items = resp.json().get("data", {}).get("affected_items", [])
    return items[0] if items else None


def get_agent_by_ip(client: WazuhAPIClient, ip: str) -> Optional[Dict]:
    if not ip:
        return None
    resp = client.get("/agents", params={"ip": ip})
    items = resp.json().get("data", {}).get("affected_items", [])
    return items[0] if items else None


def resolve_agent(client: WazuhAPIClient, name: str, ip: Optional[str] = None) -> Optional[Dict]:
    agent = get_agent_by_name(client, name)
    if agent is None and ip:
        agent = get_agent_by_ip(client, ip)
    return agent


def assign_agent_to_group(client: WazuhAPIClient, agent_id: str, group_id: str) -> str:
    resp = client.put(f"/agents/{agent_id}/group/{group_id}")
    return resp.json().get("message", "")


def assign_agent_to_groups(client: WazuhAPIClient, agent_id: str, group_ids: List[str]) -> List[str]:
    """Assign an agent to each of the given groups, additively."""
    return [assign_agent_to_group(client, agent_id, g) for g in group_ids]


def remove_agent_from_group(client: WazuhAPIClient, agent_id: str, group_id: str) -> str:
    try:
        resp = client.delete(f"/agents/{agent_id}/group/{group_id}")
        return resp.json().get("message", "")
    except WazuhAPIError as e:
        return f"not removed from group '{group_id}' (already not a member, or it's the agent's last group): {e.message}"


def remove_agent_from_groups(client: WazuhAPIClient, agent_id: str, group_ids: List[str]) -> List[str]:
    """Undo of assign_agent_to_groups."""
    return [remove_agent_from_group(client, agent_id, g) for g in group_ids]


def delete_agent(client: WazuhAPIClient, agent_id: str, purge: bool = True) -> str:
    try:
        resp = client.delete("/agents", params={
            "agents_list": agent_id,
            "status": "all",
            "older_than": "0s",
            "purge": str(purge).lower(),
        })
        body = resp.json()
        data = body.get("data", {})
        if data.get("total_affected_items", 0) >= 1:
            return f"agent {agent_id} removed"
        failed = data.get("failed_items", [])
        if failed:
            msg = failed[0].get("error", {}).get("message", "unknown reason")
            return f"agent {agent_id} not removed: {msg}"
        return body.get("message", f"agent {agent_id}: no change")
    except WazuhAPIError as e:
        return f"agent {agent_id} already removed or not found: {e.message}"


def list_agents(client: WazuhAPIClient, **filters) -> List[Dict]:
    items: List[Dict] = []
    offset = 0
    limit = 500
    while True:
        params = dict(filters)
        params.update({"offset": offset, "limit": limit})
        resp = client.get("/agents", params=params)
        data = resp.json().get("data", {})
        batch = data.get("affected_items", [])
        items.extend(batch)
        total = data.get("total_affected_items", len(items))
        offset += len(batch)
        if not batch or offset >= total:
            break
    return items