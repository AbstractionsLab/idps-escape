"""
Health checks that go through the Wazuh API / OpenSearch / webhook HTTP.
"""
from __future__ import annotations

from typing import Dict, List, Optional
import requests
from . import config as config_module
from .client import WazuhAPIClient, WazuhAPIError
from .groups import resolve_agent
from .manager_config import get_raw_config
from .scenario_ops import SHARED_GROUP

CORE_DAEMONS = ["wazuh-analysisd", "wazuh-remoted", "wazuh-logcollector", "wazuh-db"]

SCENARIO_RULESET_FILES: Dict[str, Dict[str, List[str]]] = {
    "geoip_detection": {"decoders": ["0310-ssh.xml", "0375-web-accesslog.xml"],
                         "rules": ["a2-geoip-detection.xml"]},
    "suspicious_login": {"decoders": ["0310-ssh.xml"], "rules": ["a3-suspicious-login.xml"]},
    "log_volume": {"decoders": ["0001-ad-common.xml", "0001-log-volume.xml"], "rules": ["a1-log-volume.xml"]},
    "scanning_detection": {"rules": ["a4-scanning-detection.xml"]},
}


def check_agent(client: WazuhAPIClient, name: str, ip: Optional[str] = None) -> str:
    try:
        agent = resolve_agent(client, name, ip)
    except WazuhAPIError as e:
        return f"FAIL - could not check agent {name}: {e}"
    if agent is None:
        return f"FAIL - agent {name} not found via API"
    status = agent.get("status", "unknown")
    if status == "active":
        return f"OK - agent {name} active"
    if status == "never_connected":
        return f"FAIL - agent {name} registered but never connected"
    return f"WARN - agent {name} status: {status}"


def check_agent_groups(client: WazuhAPIClient, name: str, expected_groups: List[str],
                        ip: Optional[str] = None) -> str:
    try:
        agent = resolve_agent(client, name, ip)
    except WazuhAPIError as e:
        return f"FAIL - could not check groups for agent {name}: {e}"
    if agent is None:
        return f"FAIL - agent {name} not found via API (cannot check groups)"
    current = set(agent.get("group", []))
    missing = [g for g in expected_groups if g not in current]
    if not missing:
        return f"OK - agent {name} is in groups {sorted(current)}"
    return f"FAIL - agent {name} missing group(s) {missing} (has: {sorted(current)})"

def check_agents(client: WazuhAPIClient, hosts: List[tuple]) -> List[str]:
    return [check_agent(client, name, ip) for name, ip in hosts]


def _group_config_nonempty(client: WazuhAPIClient, group_id: str) -> bool:
    resp = client.get(f"/groups/{group_id}/configuration")
    items = resp.json().get("data", {}).get("affected_items", [])
    config = items[0].get("config", []) if items else []
    return bool(config)


def check_scenario_group_config(client: WazuhAPIClient, scenario: str,
                                 agent_group_override: Optional[str] = None,
                                 radar_root: str = ".") -> str:
    own_group = agent_group_override or scenario
    try:
        if _group_config_nonempty(client, own_group):
            return f"OK - '{own_group}' group has active configuration"
    except WazuhAPIError as e:
        return f"FAIL - could not fetch '{own_group}' group config: {e}"

    if scenario in config_module.shared_scenarios(radar_root):
        try:
            if _group_config_nonempty(client, SHARED_GROUP):
                return (f"OK - '{own_group}' group config lives in '{SHARED_GROUP}' by design for this "
                        f"scenario, and it has active configuration (note: this can't distinguish 'this "
                        f"scenario is deployed' from 'another scenario sharing {SHARED_GROUP} still is')")
        except WazuhAPIError as e:
            return f"FAIL - could not fetch '{SHARED_GROUP}' group config: {e}"
        return (f"FAIL - '{own_group}' group is empty by design (config lives in '{SHARED_GROUP}') "
                f"and '{SHARED_GROUP}' is also empty -- scenario not deployed, or was undeployed")

    return f"FAIL - '{own_group}' group agent.conf is empty (scenario not deployed, or was undeployed)"


def check_scenario_agents(client: WazuhAPIClient, scenario: str, radar_root: str = ".") -> List[str]:
    from .groups import list_agents
    from .scenario_ops import scenario_groups

    groups = [g for g in scenario_groups(scenario, radar_root=radar_root) if g != "default"]
    if not groups:
        return [f"WARN - {scenario} has no scenario-specific group to check"]

    agents_by_id: Dict[str, Dict] = {}
    id_sets: List[set] = []
    for g in groups:
        try:
            batch = list_agents(client, group=g)
        except WazuhAPIError as e:
            return [f"FAIL - could not list agents in group '{g}' for {scenario}: {e}"]
        ids = set()
        for a in batch:
            agent_id = a.get("id")
            if agent_id is not None:
                ids.add(agent_id)
                agents_by_id[agent_id] = a
        id_sets.append(ids)

    common_ids = set.intersection(*id_sets) if id_sets else set()
    agents = [agents_by_id[i] for i in common_ids]

    groups_label = ", ".join(groups)
    if not agents:
        return [f"FAIL - no agents assigned to all of {scenario}'s group(s) ({groups_label})"]

    report = [f"OK - {len(agents)} agent(s) assigned to all of {scenario}'s group(s) ({groups_label}) -- "
              f"membership only, not proof the scenario is currently deployed"]
    for a in agents:
        name = a.get("name", "?")
        status = a.get("status", "unknown")
        if status == "active":
            report.append(f"OK - agent {name} active")
        elif status == "never_connected":
            report.append(f"FAIL - agent {name} registered but never connected")
        else:
            report.append(f"WARN - agent {name} status: {status}")
    return report


def check_manager_daemons(client: WazuhAPIClient, daemons: List[str] = None) -> List[str]:
    daemons = daemons or CORE_DAEMONS
    try:
        resp = client.get("/manager/status")
    except WazuhAPIError as e:
        return [f"FAIL - could not reach /manager/status: {e}"]
    statuses = resp.json()["data"]["affected_items"][0]
    return [
        f"OK - {d} running" if statuses.get(d) == "running" else f"FAIL - {d} is {statuses.get(d, 'unknown')}"
        for d in daemons
    ]


def check_config_contains(client: WazuhAPIClient, markers: Dict[str, str]) -> List[str]:
    """markers: label -> substring expected somewhere in ossec.conf."""
    try:
        content = get_raw_config(client)
    except WazuhAPIError as e:
        return [f"FAIL - could not fetch manager configuration: {e}"]
    return [
        f"OK - {label} wired into ossec.conf" if needle in content else f"FAIL - {label} not found in ossec.conf"
        for label, needle in markers.items()
    ]


def _ruleset_filenames(client: WazuhAPIClient, kind: str) -> set:
    names: set = set()
    offset = 0
    limit = 500
    while True:
        resp = client.get(f"/{kind}/files", params={"offset": offset, "limit": limit})
        data = resp.json().get("data", {})
        items = data.get("affected_items", [])
        for item in items:
            if isinstance(item, str):
                names.add(item)
            elif isinstance(item, dict):
                fname = item.get("filename") or item.get("name")
                if fname:
                    names.add(fname)
        total = data.get("total_affected_items", len(names))
        offset += len(items)
        if not items or offset >= total:
            break
    return names


def check_ruleset_files(client: WazuhAPIClient, kind: str, filenames: List[str]) -> List[str]:
    """kind: 'decoders' | 'rules' | 'lists'."""
    try:
        existing = _ruleset_filenames(client, kind)
    except WazuhAPIError as e:
        return [f"FAIL - could not list {kind} files: {e}"]
    out = []
    for name in filenames:
        if name in existing:
            out.append(f"OK - {name} present ({kind})")
        else:
            out.append(f"FAIL - {name} not found ({kind})")
    return out


def check_manager_api(client: WazuhAPIClient, scenarios: List[str], os_url: str = "", os_user: str = "",
                       os_pass: str = "", webhook_url: str = "", radar_root: str = ".") -> List[str]:
    report: List[str] = []
    report += check_manager_daemons(client)

    scenarios_with_ar_wiring = set(SCENARIO_RULESET_FILES.keys())
    for s in scenarios:
        if s in scenarios_with_ar_wiring:
            report += check_config_contains(client, {f"{s} active-response wiring": f"<!-- RADAR: {s} BEGIN -->"})
        report.append(check_scenario_group_config(client, s, radar_root=radar_root))

    decoders, rules = set(), set()
    for s in scenarios:
        cfg = SCENARIO_RULESET_FILES.get(s, {})
        decoders.update(cfg.get("decoders", []))
        rules.update(cfg.get("rules", []))
    if decoders:
        report += check_ruleset_files(client, "decoders", sorted(decoders))
    if rules:
        report += check_ruleset_files(client, "rules", sorted(rules))
    if "geoip_detection" in scenarios:
        report += check_ruleset_files(client, "lists", ["whitelist_countries"])

    for s in scenarios:
        report += check_scenario_agents(client, s, radar_root=radar_root)

    if os_url:
        try:
            r = requests.get(f"{os_url.rstrip('/')}/_cluster/health", auth=(os_user, os_pass),
                              verify=False, timeout=10)
            report.append(f"OK - OpenSearch reachable (cluster: {r.json().get('status', '?')})"
                           if r.status_code == 200 else f"FAIL - OpenSearch not reachable at {os_url}")
        except requests.RequestException:
            report.append(f"FAIL - OpenSearch not reachable at {os_url}")

        if "log_volume" in scenarios:
            try:
                r = requests.get(f"{os_url.rstrip('/')}/_index_template/radar-log-volume",
                                  auth=(os_user, os_pass), verify=False, timeout=10)
                report.append("OK - radar-log-volume index template found" if r.status_code == 200
                               else "FAIL - radar-log-volume index template missing (run build-radar.sh)")
            except requests.RequestException:
                report.append("FAIL - radar-log-volume index template missing (run build-radar.sh)")

    if webhook_url:
        try:
            r = requests.get(webhook_url, verify=False, timeout=10)
            report.append(f"OK - Webhook reachable at {webhook_url}" if r.status_code in (200, 404, 405)
                           else f"WARN - Webhook not reachable at {webhook_url}")
        except requests.RequestException:
            report.append(f"WARN - Webhook not reachable at {webhook_url}")

    return report