"""
Higher-level scenario orchestration on top of wazuh_api.groups.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import config as config_module
from .client import WazuhAPIClient, WazuhAPIError
from .groups import assign_agent_to_groups, ensure_group, get_agent_by_ip, get_agent_by_name, list_agents, remove_agent_from_groups, upload_group_config
from .manager_config import (
    apply_marked_block, apply_tag_value, check_lists_loaded, get_raw_config,
    remove_marked_block, restart_manager, update_raw_config, wait_for_api,
)
from .ruleset import delete_decoder_file, delete_list_file, delete_rule_file, upload_decoder_file, upload_list_file, upload_rule_file

SHARED_GROUP = "radar_shared"


def scenario_groups(scenario_name: str, agent_group_override: Optional[str] = None,
                     radar_root: str = ".") -> List[str]:
    own_group = agent_group_override or scenario_name
    groups = ["default", own_group]
    if scenario_name in config_module.shared_scenarios(radar_root):
        groups.append(SHARED_GROUP)
    return groups


def scenario_snippet_path(scenario_name: str, agent_configs_dir: str) -> str:
    slug = scenario_name.replace("_", "-")
    return str(Path(agent_configs_dir) / scenario_name / f"radar-{slug}-agent-snippet.xml")


def shared_snippet_path(agent_configs_dir: str) -> str:
    return str(Path(agent_configs_dir) / "_shared" / "radar-shared-auth-log-agent-snippet.xml")


def ossec_default_snippet_path(scenarios_dir: str) -> str:
    return str(Path(scenarios_dir) / "ossec" / "radar-default-ossec-snippet.xml")


def ossec_scenario_snippet_path(scenario_name: str, scenarios_dir: str) -> str:
    slug = scenario_name.replace("_", "-")
    return str(Path(scenarios_dir) / "ossec" / f"radar-{slug}-ossec-snippet.xml")


def ossec_shared_snippet_path(scenarios_dir: str) -> str:
    return str(Path(scenarios_dir) / "ossec" / "radar-shared-auth-log-ossec-snippet.xml")


def decoder_path(scenario_name: str, decoder_filename: str, scenarios_dir: str) -> str:
    return str(Path(scenarios_dir) / "decoders" / scenario_name / decoder_filename)


def deploy_scenario_config(client: WazuhAPIClient, scenario_name: str, agent_configs_dir: str,
                            agent_group_override: Optional[str] = None) -> Dict:
    own_group = agent_group_override or scenario_name
    results = {}

    created = ensure_group(client, own_group)
    results[own_group] = {"group_created": created,
                           "config_message": _upload_group_config_if_nonempty(
                               client, own_group, scenario_snippet_path(scenario_name, agent_configs_dir))}

    if scenario_name in config_module.shared_scenarios(str(Path(agent_configs_dir).parent.parent)):
        shared_created = ensure_group(client, SHARED_GROUP)
        results[SHARED_GROUP] = {"group_created": shared_created,
                                  "config_message": _upload_group_config_if_nonempty(
                                      client, SHARED_GROUP, shared_snippet_path(agent_configs_dir))}

    return results


def undo_scenario_config(client: WazuhAPIClient, scenario_name: str,
                          agent_group_override: Optional[str] = None,
                          radar_root: str = ".") -> Dict:
    own_group = agent_group_override or scenario_name
    message = upload_group_config(client, own_group, "<agent_config>\n</agent_config>")
    result: Dict = {own_group: {"config_message": message}}

    groups_to_clear = list(scenario_specific_groups(scenario_name, agent_group_override, radar_root))
    errors: List[str] = []

    also_clear_shared = False
    if scenario_name in config_module.shared_scenarios(radar_root):
        scenarios_dir = str(Path(radar_root) / "scenarios")
        try:
            ossec_content = get_raw_config(client)
            other_shared = config_module.shared_scenarios(radar_root) - {scenario_name}
            still_needed = any(
                _other_scenario_still_deployed(ossec_content, s, scenarios_dir) for s in other_shared
            )
            also_clear_shared = not still_needed
        except WazuhAPIError as e:
            errors.append(f"could not check whether '{SHARED_GROUP}' is still needed by another scenario: {e}")

    if also_clear_shared and SHARED_GROUP not in groups_to_clear:
        groups_to_clear.append(SHARED_GROUP)

    unenrolled: Dict[str, List[str]] = {}
    seen_ids = set()
    for g in groups_to_clear:
        try:
            agents = list_agents(client, group=g)
        except WazuhAPIError as e:
            errors.append(f"could not list agents in group '{g}': {e}")
            continue
        for agent in agents:
            agent_id = agent.get("id")
            if agent_id is None or agent_id in seen_ids:
                continue
            seen_ids.add(agent_id)
            messages = remove_agent_from_groups(client, agent_id, groups_to_clear)
            unenrolled[agent.get("name", agent_id)] = messages

    result["agents_unenrolled"] = unenrolled
    result["radar_shared_also_cleared"] = also_clear_shared
    if errors:
        result["errors"] = errors
    return result


def _upload_group_config_if_nonempty(client: WazuhAPIClient, group_id: str, snippet_path: str) -> str:
    content = Path(snippet_path).read_text()
    if not content.strip():
        return "skipped -- snippet file has no configuration content (comment-only or empty)"
    return upload_group_config(client, group_id, content)


def assign_hosts_to_scenario_groups(client: WazuhAPIClient, hosts: List[Tuple[str, Optional[str]]],
                                     scenario_name: str, agent_group_override: Optional[str] = None) -> Dict:
    groups = scenario_groups(scenario_name, agent_group_override)
    results = {}
    for name, ip in hosts:
        key = name or ip or "unknown"
        agent = None
        resolved_via = None
        if ip:
            agent = get_agent_by_ip(client, ip)
            resolved_via = "ip"
        if agent is None and name:
            agent = get_agent_by_name(client, name)
            resolved_via = "name"
        if agent is None:
            tried_parts = []
            if ip:
                tried_parts.append(f"GET /agents?ip={ip}")
            if name:
                tried_parts.append(f"GET /agents?name={name}")
            tried = " and ".join(tried_parts) if tried_parts else "no name or IP given"
            results[key] = {
                "resolved": False,
                "warning": (
                    f"could not resolve agent for {key} via {tried}. Group assignment "
                    "skipped."
                ),
            }
            continue
        messages = assign_agent_to_groups(client, agent["id"], groups)
        results[key] = {
            "resolved": True, "agent_id": agent["id"], "resolved_via": resolved_via,
            "groups": groups, "messages": messages,
        }
    return results


def scenario_specific_groups(scenario_name: str, agent_group_override: Optional[str] = None,
                              radar_root: str = ".") -> List[str]:
    return [g for g in scenario_groups(scenario_name, agent_group_override, radar_root)
            if g not in ("default", SHARED_GROUP)]


def unassign_hosts_from_scenario_groups(client: WazuhAPIClient, hosts: List[Tuple[str, Optional[str]]],
                                         scenario_name: str, agent_group_override: Optional[str] = None) -> Dict:
    groups = scenario_specific_groups(scenario_name, agent_group_override)
    results = {}
    for name, ip in hosts:
        key = name or ip or "unknown"
        agent = None
        resolved_via = None
        if ip:
            agent = get_agent_by_ip(client, ip)
            resolved_via = "ip"
        if agent is None and name:
            agent = get_agent_by_name(client, name)
            resolved_via = "name"
        if agent is None:
            tried_parts = []
            if ip:
                tried_parts.append(f"GET /agents?ip={ip}")
            if name:
                tried_parts.append(f"GET /agents?name={name}")
            tried = " and ".join(tried_parts) if tried_parts else "no name or IP given"
            results[key] = {
                "resolved": False,
                "warning": (
                    f"could not resolve agent for {key} via {tried}. Nothing to "
                    "unassign -- it may already not be enrolled."
                ),
            }
            continue
        messages = remove_agent_from_groups(client, agent["id"], groups)
        results[key] = {
            "resolved": True, "agent_id": agent["id"], "resolved_via": resolved_via,
            "groups": groups, "messages": messages,
        }
    return results


class MissingListFileError(RuntimeError):
    """Raised when a scenario's rules reference a CDB list with no matching source file."""


_LIST_REF_RE = re.compile(r"<list\b[^>]*>\s*([^<\s]+)\s*</list>", re.IGNORECASE)


def _referenced_list_basenames(rule_xml_texts: List[str]) -> set:
    names = set()
    for text in rule_xml_texts:
        for m in _LIST_REF_RE.finditer(text):
            names.add(Path(m.group(1)).name)
    return names


def _available_list_basenames(scenario_name: str, scenarios_dir: str) -> set:
    names = {f.name for f in scenario_list_files(scenario_name, scenarios_dir)}
    if (Path(scenarios_dir) / "lists" / "whitelist_countries").is_file():
        names.add("whitelist_countries")
    return names


def check_referenced_lists_exist(scenario_name: str, scenarios_dir: str) -> None:
    rule_texts = []
    default_rules_dir = Path(scenarios_dir) / "rules" / "default"
    if default_rules_dir.is_dir():
        rule_texts += [f.read_text() for f in sorted(default_rules_dir.glob("*.xml"))]
    scenario_rules_dir = Path(scenarios_dir) / "rules" / scenario_name
    if scenario_rules_dir.is_dir():
        rule_texts += [f.read_text() for f in sorted(scenario_rules_dir.glob("*.xml"))]

    referenced = _referenced_list_basenames(rule_texts)
    available = _available_list_basenames(scenario_name, scenarios_dir)
    missing = sorted(referenced - available)
    if missing:
        raise MissingListFileError(
            f"Scenario '{scenario_name}' has rules referencing CDB list(s) "
            f"{missing} with no matching source file under "
            f"{Path(scenarios_dir) / 'lists' / scenario_name}. Refusing to "
            f"deploy: the rule(s) would upload successfully and then be "
            f"silently dropped by analysisd at load time."
        )


def deploy_ruleset_files(client: WazuhAPIClient, scenario_name: str, scenarios_dir: str) -> Dict:
    check_referenced_lists_exist(scenario_name, scenarios_dir)

    changes: Dict[str, bool] = {}

    decoders_dir = Path(scenarios_dir) / "decoders" / scenario_name
    if decoders_dir.is_dir():
        for f in sorted(decoders_dir.glob("*.xml")):
            changes[f"decoder:{f.name}"] = upload_decoder_file(client, f.name, f.read_text())

    default_rules_dir = Path(scenarios_dir) / "rules" / "default"
    if default_rules_dir.is_dir():
        for f in sorted(default_rules_dir.glob("*.xml")):
            changes[f"rule:{f.name}"] = upload_rule_file(client, f.name, f.read_text())

    scenario_rules_dir = Path(scenarios_dir) / "rules" / scenario_name
    if scenario_rules_dir.is_dir():
        for f in sorted(scenario_rules_dir.glob("*.xml")):
            changes[f"rule:{f.name}"] = upload_rule_file(client, f.name, f.read_text())

    if scenario_name in config_module.whitelist_scenarios(str(Path(scenarios_dir).parent)):
        whitelist_file = Path(scenarios_dir) / "lists" / "whitelist_countries"
        if whitelist_file.is_file():
            changes["list:whitelist_countries"] = upload_list_file(
                client, "whitelist_countries", whitelist_file.read_text()
            )

    for f in scenario_list_files(scenario_name, scenarios_dir):
        changes[f"list:{f.name}"] = upload_list_file(client, f.name, f.read_text())

    return changes


def scenario_list_files(scenario_name: str, scenarios_dir: str) -> List[Path]:
    """CDB lists owned by one scenario, in scenarios/lists/<scenario>/."""
    lists_dir = Path(scenarios_dir) / "lists" / scenario_name
    if not lists_dir.is_dir():
        return []
    return sorted(f for f in lists_dir.iterdir() if f.is_file())


def _other_scenario_still_deployed(ossec_content: str, other_scenario: str, scenarios_dir: str) -> bool:
    snippet_path = ossec_scenario_snippet_path(other_scenario, scenarios_dir)
    if not Path(snippet_path).exists():
        return True
    return f"<!-- RADAR: {other_scenario} BEGIN -->" in ossec_content


def _file_shared_with_deployed_scenario(ossec_content: str, scenarios_dir: str, kind: str,
                                         filename: str, scenario_name: str) -> Optional[str]:
    base = Path(scenarios_dir) / kind
    if not base.is_dir():
        return None
    for other_dir in sorted(base.iterdir()):
        if not other_dir.is_dir() or other_dir.name in (scenario_name, "default", "_shared"):
            continue
        if (other_dir / filename).is_file():
            if _other_scenario_still_deployed(ossec_content, other_dir.name, scenarios_dir):
                return other_dir.name
    return None


def undo_ruleset_files(client: WazuhAPIClient, scenario_name: str, scenarios_dir: str, ossec_content: str) -> Dict:
    removed: Dict[str, bool] = {}
    kept_shared: Dict[str, str] = {}
    errors: Dict[str, str] = {}

    def _try_delete(key: str, delete_fn, *args) -> None:
        try:
            removed[key] = delete_fn(*args)
        except RuntimeError as e:
            errors[key] = str(e)

    decoders_dir = Path(scenarios_dir) / "decoders" / scenario_name
    if decoders_dir.is_dir():
        for f in sorted(decoders_dir.glob("*.xml")):
            other = _file_shared_with_deployed_scenario(ossec_content, scenarios_dir, "decoders", f.name, scenario_name)
            if other:
                kept_shared[f"decoder:{f.name}"] = other
            else:
                _try_delete(f"decoder:{f.name}", delete_decoder_file, client, f.name)

    scenario_rules_dir = Path(scenarios_dir) / "rules" / scenario_name
    if scenario_rules_dir.is_dir():
        for f in sorted(scenario_rules_dir.glob("*.xml")):
            other = _file_shared_with_deployed_scenario(ossec_content, scenarios_dir, "rules", f.name, scenario_name)
            if other:
                kept_shared[f"rule:{f.name}"] = other
            else:
                _try_delete(f"rule:{f.name}", delete_rule_file, client, f.name)

    if scenario_name in config_module.whitelist_scenarios(str(Path(scenarios_dir).parent)):
        other_whitelist_users = [
            s for s in config_module.whitelist_scenarios(str(Path(scenarios_dir).parent)) - {scenario_name}
            if _other_scenario_still_deployed(ossec_content, s, scenarios_dir)
        ]
        if other_whitelist_users:
            kept_shared["list:whitelist_countries"] = sorted(other_whitelist_users)[0]
        else:
            _try_delete("list:whitelist_countries", delete_list_file, client, "whitelist_countries")

    for f in scenario_list_files(scenario_name, scenarios_dir):
        other = _file_shared_with_deployed_scenario(ossec_content, scenarios_dir, "lists", f.name, scenario_name)
        if other:
            kept_shared[f"list:{f.name}"] = other
        else:
            _try_delete(f"list:{f.name}", delete_list_file, client, f.name)

    return {
        "removed": removed,
        "kept_shared": kept_shared,
        "errors": errors,
        "note": "'rules/default/*.xml' (universal baseline rules used by every scenario) is never touched.",
    }


def deploy_manager_config(client: WazuhAPIClient, scenario_name: str, scenarios_dir: str, *,
                          wait_for_restart: bool = True,
                          restart_timeout: float = 90.0,
                          indexer_host: str = "https://wazuh.indexer:9200") -> Dict:
    ruleset_changes = deploy_ruleset_files(client, scenario_name, scenarios_dir)

    content = get_raw_config(client)
    ossec_changes: Dict[str, bool] = {}

    default_snippet = ossec_default_snippet_path(scenarios_dir)
    if Path(default_snippet).exists():
        content, changed = apply_marked_block(
            content, "default", Path(default_snippet).read_text(), "</ossec_config>"
        )
        ossec_changes["default"] = changed

    scenario_snippet = ossec_scenario_snippet_path(scenario_name, scenarios_dir)
    if Path(scenario_snippet).exists():
        content, changed = apply_marked_block(
            content, scenario_name, Path(scenario_snippet).read_text(), "</ossec_config>"
        )
        ossec_changes[scenario_name] = changed

    if scenario_name in config_module.shared_scenarios(str(Path(scenarios_dir).parent)):
        shared_snippet = ossec_shared_snippet_path(scenarios_dir)
        if Path(shared_snippet).exists():
            content, changed = apply_marked_block(
                content, "shared auth_log_enrichment", Path(shared_snippet).read_text(), "</ossec_config>"
            )
            ossec_changes["shared_auth_log_enrichment"] = changed

    if Path(decoder_path(scenario_name, "0310-ssh.xml", scenarios_dir)).exists():
        content, changed = apply_marked_block(
            content, "ssh decoder_exclude",
            "<decoder_exclude>0310-ssh_decoders.xml</decoder_exclude>", "</ruleset>",
        )
        ossec_changes["ssh_decoder_exclude"] = changed

    if Path(decoder_path(scenario_name, "0375-web-accesslog.xml", scenarios_dir)).exists():
        content, changed = apply_marked_block(
            content, "web-accesslog decoder_exclude",
            "<decoder_exclude>0375-web-accesslog_decoders.xml</decoder_exclude>", "</ruleset>",
        )
        ossec_changes["web_accesslog_decoder_exclude"] = changed

    if scenario_name in config_module.whitelist_scenarios(str(Path(scenarios_dir).parent)):
        whitelist_file = Path(scenarios_dir) / "lists" / "whitelist_countries"
        if whitelist_file.is_file():
            content, changed = apply_marked_block(
                content, "whitelist_countries list",
                "<list>etc/lists/whitelist_countries</list>", insert_after="<ruleset>",
            )
            ossec_changes["whitelist_countries_list"] = changed

    for f in scenario_list_files(scenario_name, scenarios_dir):
        content, changed = apply_marked_block(
            content, f"{f.name} list",
            f"<list>etc/lists/{f.name}</list>", insert_after="<ruleset>",
        )
        ossec_changes[f"list_{f.name}"] = changed

    content, changed = apply_tag_value(content, "logall", "yes")
    ossec_changes["logall"] = changed
    content, changed = apply_tag_value(content, "logall_json", "yes")
    ossec_changes["logall_json"] = changed
    content, changed = apply_tag_value(content, "host", indexer_host)
    ossec_changes["indexer_host"] = changed

    ossec_content_changed = any(ossec_changes.values())
    ruleset_files_changed = any(ruleset_changes.values())
    restart_needed = ossec_content_changed or ruleset_files_changed

    result: Dict = {
        "ossec_changes": ossec_changes,
        "ruleset_changes": ruleset_changes,
        "restart_triggered": False,
    }

    if restart_needed:
        if ossec_content_changed:
            update_raw_config(client, content)
        restart_manager(client)
        result["restart_triggered"] = True
        if wait_for_restart:
            result["api_back_up"] = wait_for_api(
                client.base_url, client.user, client.password,
                timeout=restart_timeout, verify_ssl=client.verify_ssl,
            )
            if result["api_back_up"]:
                deployed_lists = [name.split(":", 1)[1] for name in ruleset_changes if name.startswith("list:")]
                result["list_verification"] = check_lists_loaded(client, deployed_lists)

    return result


def undo_manager_config(client: WazuhAPIClient, scenario_name: str, scenarios_dir: str, *,
                         wait_for_restart: bool = True, restart_timeout: float = 90.0) -> Dict:
    content = get_raw_config(client)
    ruleset_result = undo_ruleset_files(client, scenario_name, scenarios_dir, content)

    new_content, changed = remove_marked_block(content, scenario_name)

    result: Dict = {
        "scenario_block_removed": changed,
        "ruleset_files_removed": ruleset_result["removed"],
        "ruleset_files_kept_shared": ruleset_result["kept_shared"],
        "ruleset_files_errors": ruleset_result["errors"],
        "restart_triggered": False,
        "skipped_deliberately": [
            "'default' ossec.conf block (shared by every scenario)",
            "'shared auth_log_enrichment' ossec.conf block (shared across scenarios)",
            "decoder_exclude / whitelist_countries ossec.conf blocks (not scenario-namespaced)",
            "'rules/default/*.xml' (universal baseline rules used by every scenario)",
            "enrichment integration scripts and active-response scripts on the manager filesystem",
            "filebeat pipeline patch",
        ],
    }

    restart_needed = changed or any(ruleset_result["removed"].values())

    if restart_needed:
        if changed:
            update_raw_config(client, new_content)
        restart_manager(client)
        result["restart_triggered"] = True
        if wait_for_restart:
            result["api_back_up"] = wait_for_api(
                client.base_url, client.user, client.password,
                timeout=restart_timeout, verify_ssl=client.verify_ssl,
            )
            if changed and result["api_back_up"]:
                verify_content = get_raw_config(client)
                if f"<!-- RADAR: {scenario_name} BEGIN -->" in verify_content:
                    result["scenario_block_removed"] = False
                    result["error"] = (
                        f"Restarted the manager after writing the updated ossec.conf, but the "
                        f"'{scenario_name}' marker is still present after the restart -- the "
                        f"write genuinely did not take effect (it may have been rejected). The "
                        f"ruleset file changes above (if any) still went through independently."
                    )

    return result