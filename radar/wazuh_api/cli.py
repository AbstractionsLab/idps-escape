#!/usr/bin/env python3
"""
CLI entrypoint for the wazuh_api package.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import config as config_module
from . import fleet as fleet_module
from .client import WazuhAPIClient, WazuhAPIError
from .groups import (
    assign_agent_to_groups,
    delete_agent,
    ensure_group,
    get_agent_by_name,
    list_agents,
    resolve_agent,
    upload_group_config_from_file,
)
from .manager_config import wait_for_api, wait_for_opensearch
from .scenario_ops import (
    assign_hosts_to_scenario_groups,
    deploy_manager_config,
    deploy_scenario_config,
    unassign_hosts_from_scenario_groups,
    undo_manager_config,
    undo_scenario_config,
)


def _client_from_env() -> WazuhAPIClient:
    url = os.environ.get("WAZUH_API_URL")
    user = os.environ.get("WAZUH_AUTH_USER")
    password = os.environ.get("WAZUH_AUTH_PASS")
    missing = [name for name, value in
               [("WAZUH_API_URL", url), ("WAZUH_AUTH_USER", user), ("WAZUH_AUTH_PASS", password)]
               if not value]
    if missing:
        print(f"[!] Missing required environment variables: {', '.join(missing)}", file=sys.stderr)
        sys.exit(2)
    verify_ssl = os.environ.get("WAZUH_API_VERIFY_SSL", "false").strip().lower() in ("1", "true", "yes")
    return WazuhAPIClient(url, user, password, verify_ssl=verify_ssl)  # type: ignore[arg-type]


def cmd_wait_for_api(args: argparse.Namespace) -> int:
    client = _client_from_env()
    last_reported = [0]

    def on_tick(elapsed: float, timeout: float) -> None:
        if int(elapsed) // 15 > last_reported[0]:
            last_reported[0] = int(elapsed) // 15
            print(f">>> still waiting for Wazuh API... ({int(elapsed)}s / {int(timeout)}s)", file=sys.stderr)

    ok = wait_for_api(client.base_url, client.user, client.password,
                       timeout=args.timeout, verify_ssl=client.verify_ssl, on_tick=on_tick)
    if ok:
        print(json.dumps({"api_reachable": True}))
        return 0
    print(f"[!] Wazuh API at {client.base_url} did not respond within {args.timeout}s.", file=sys.stderr)
    return 1


def cmd_wait_for_opensearch(args: argparse.Namespace) -> int:
    os_url = os.environ.get("OS_URL")
    os_user = os.environ.get("OS_USER", "")
    os_pass = os.environ.get("OS_PASS", "")
    if not os_url:
        print("[!] OS_URL is not set in .env.", file=sys.stderr)
        return 1
    last_reported = [0]

    def on_tick(elapsed: float, timeout: float) -> None:
        if int(elapsed) // 15 > last_reported[0]:
            last_reported[0] = int(elapsed) // 15
            print(f">>> still waiting for OpenSearch... ({int(elapsed)}s / {int(timeout)}s)", file=sys.stderr)

    ok = wait_for_opensearch(os_url, os_user, os_pass, timeout=args.timeout, on_tick=on_tick)
    if ok:
        print(json.dumps({"opensearch_reachable": True}))
        return 0
    print(f"[!] OpenSearch at {os_url} did not report a healthy cluster within {args.timeout}s.", file=sys.stderr)
    return 1


def cmd_deploy_scenario_config(args: argparse.Namespace) -> int:
    client = _client_from_env()
    try:
        results = deploy_scenario_config(client, args.scenario, args.agent_config_dir, args.group)
        print(json.dumps(results))
        return 0
    except WazuhAPIError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1


def cmd_agent_status(args: argparse.Namespace) -> int:
    client = _client_from_env()
    try:
        agent = resolve_agent(client, args.name, args.ip)
        if agent is None:
            print(json.dumps({"resolved": False}))
            return 0
        print(json.dumps({"resolved": True, "agent_id": agent["id"], "status": agent.get("status", "unknown")}))
        return 0
    except WazuhAPIError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1


def cmd_assign_hosts_to_groups(args: argparse.Namespace) -> int:
    client = _client_from_env()
    hosts: list = []
    for pair in args.hosts.split(","):
        pair = pair.strip()
        if not pair:
            continue
        if ":" in pair:
            name, ip = pair.split(":", 1)
        else:
            name, ip = pair, ""
        hosts.append((name.strip(), ip.strip() or None))
    try:
        results = assign_hosts_to_scenario_groups(client, hosts, args.scenario, args.group)
        print(json.dumps(results))
        try:
            fleet_module.update_fleet_from_assignment_results(args.radar_root, results, args.scenario)
        except Exception as e:
            print(f"[!] fleet.yaml update failed (group assignment itself still succeeded): {e}", file=sys.stderr)
        if any(not r.get("resolved", False) for r in results.values()):
            return 1
        return 0
    except WazuhAPIError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1


def cmd_unassign_hosts_from_groups(args: argparse.Namespace) -> int:
    client = _client_from_env()
    hosts: list = []
    for pair in args.hosts.split(","):
        pair = pair.strip()
        if not pair:
            continue
        if ":" in pair:
            name, ip = pair.split(":", 1)
        else:
            name, ip = pair, ""
        hosts.append((name.strip(), ip.strip() or None))
    try:
        results = unassign_hosts_from_scenario_groups(client, hosts, args.scenario, args.group)
        print(json.dumps(results))
        return 0
    except WazuhAPIError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1


def cmd_deregister_agent(args: argparse.Namespace) -> int:
    """True deletion via Wazuh's DELETE /agents -- the manager stops
    accepting this agent's key entirely."""
    client = _client_from_env()
    try:
        agent = resolve_agent(client, args.name, args.ip)
        if agent is None:
            known = sorted(a.get("name", "?") for a in list_agents(client))
            print(json.dumps({
                "resolved": False,
                "message": (
                    f"No agent found matching name={args.name!r} ip={args.ip!r} -- nothing was "
                    f"deregistered. This is NOT the same as 'already removed': it means the name/IP "
                    f"didn't match exactly (Wazuh's name filter is case- and whitespace-sensitive). "
                    f"Known agent names on this manager: {known}"
                ),
            }))
            return 1
        message = delete_agent(client, agent["id"], purge=not args.no_purge)
        succeeded = "not removed" not in message and ": no change" not in message
        print(json.dumps({"resolved": True, "agent_id": agent["id"], "message": message}))
        if not succeeded:
            print(f"[!] {message}", file=sys.stderr)
            return 1
        return 0
    except WazuhAPIError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1


def cmd_deploy_manager_config(args: argparse.Namespace) -> int:
    client = _client_from_env()
    try:
        result = deploy_manager_config(
            client, args.scenario, args.scenarios_dir,
            wait_for_restart=not args.no_wait,
            restart_timeout=args.restart_timeout,
            indexer_host=os.environ.get("WAZUH_INDEXER_HOST", "https://wazuh.indexer:9200"),
        )
        print(json.dumps(result))
        if result["restart_triggered"] and not result.get("api_back_up", True):
            print(f"[!] Manager restart triggered but the API did not respond within "
                  f"{args.restart_timeout}s -- check the manager manually.", file=sys.stderr)
            return 1
        return 0
    except WazuhAPIError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1


def cmd_undo_scenario_config(args: argparse.Namespace) -> int:
    client = _client_from_env()
    try:
        result = undo_scenario_config(client, args.scenario, args.group, args.radar_root)
        print(json.dumps(result))
        return 0
    except WazuhAPIError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1


def cmd_undo_manager_config(args: argparse.Namespace) -> int:
    client = _client_from_env()
    try:
        result = undo_manager_config(
            client, args.scenario, args.scenarios_dir,
            wait_for_restart=not args.no_wait,
            restart_timeout=args.restart_timeout,
        )
        print(json.dumps(result))
        if result["restart_triggered"] and not result.get("api_back_up", True):
            print(f"[!] Manager restart triggered but the API did not respond within "
                  f"{args.restart_timeout}s -- check the manager manually.", file=sys.stderr)
            return 1
        return 0
    except WazuhAPIError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1


def cmd_ensure_group(args: argparse.Namespace) -> int:
    client = _client_from_env()
    try:
        created = ensure_group(client, args.group)
        print(json.dumps({"group": args.group, "created": created}))
        return 0
    except WazuhAPIError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1


def cmd_upload_group_config(args: argparse.Namespace) -> int:
    client = _client_from_env()
    try:
        message = upload_group_config_from_file(client, args.group, args.file)
        print(json.dumps({"group": args.group, "message": message}))
        return 0
    except (WazuhAPIError, OSError) as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1


def cmd_assign_agent_groups(args: argparse.Namespace) -> int:
    client = _client_from_env()
    groups = [g.strip() for g in args.groups.split(",") if g.strip()]
    try:
        agent = get_agent_by_name(client, args.agent_name)
        if agent is None:
            print(json.dumps({
                "agent_name": args.agent_name,
                "resolved": False,
                "warning": (
                    f"could not resolve agent id for {args.agent_name} via "
                    f"GET /agents?name={args.agent_name} -- group assignment "
                    "skipped this run. Re-run to retry once the agent is visible."
                ),
            }))
            return 0
        messages = assign_agent_to_groups(client, agent["id"], groups)
        print(json.dumps({
            "agent_name": args.agent_name,
            "agent_id": agent["id"],
            "resolved": True,
            "groups": groups,
            "messages": messages,
        }))
        return 0
    except WazuhAPIError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1

def cmd_scenario_info(args: argparse.Namespace) -> int:
    scenarios = config_module.valid_scenarios()
    if args.scenario not in scenarios:
        print(f"[!] Invalid scenario '{args.scenario}'. Must be one of: {sorted(scenarios)}", file=sys.stderr)
        return 1
    container_name = config_module.agent_service_by_scenario().get(args.scenario, "")
    shared = args.scenario in config_module.shared_scenarios()
    print(f"container_name={container_name}")
    print(f"shared={'true' if shared else 'false'}")
    return 0


def cmd_list_scenarios(args: argparse.Namespace) -> int:
    print(" ".join(sorted(config_module.valid_scenarios())))
    return 0


def cmd_manager_health_api(args: argparse.Namespace) -> int:
    """Pure Wazuh API / OpenSearch / webhook checks for the manager."""
    from .health import check_manager_api
    client = _client_from_env()
    scenarios = sorted(config_module.valid_scenarios()) if args.scenario == "all" else [args.scenario]
    try:
        for line in check_manager_api(client, scenarios, os.environ.get("OS_URL", ""),
                                       os.environ.get("OS_USER", ""), os.environ.get("OS_PASS", ""),
                                       os.environ.get("WEBHOOK_URL", ""), radar_root="."):
            print(line)
        return 0
    except WazuhAPIError as e:
        print(f"FAIL - {e.message}")
        return 1


def cmd_agent_health(args: argparse.Namespace) -> int:
    """Agent status + group membership via the Wazuh API only."""
    from .health import check_agent, check_agent_groups
    client = _client_from_env()
    names = [n.strip() for n in args.agent_name.split(",") if n.strip()]
    expected_groups = ["default"] + ([args.scenario] if args.scenario != "all" else [])
    had_failure = False
    for name in names:
        try:
            print(check_agent(client, name))
            print(check_agent_groups(client, name, expected_groups))
        except WazuhAPIError as e:
            print(f"FAIL - {name}: {e.message}")
            had_failure = True
    return 1 if had_failure else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Wazuh API operations for RADAR (groups/agents)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_wait = sub.add_parser("wait-for-api",
                             help="Poll until the Wazuh API responds (use after a fresh manager bootstrap)")
    p_wait.add_argument("--timeout", type=float, default=120.0)
    p_wait.set_defaults(func=cmd_wait_for_api)

    p_wait_os = sub.add_parser("wait-for-opensearch",
                                help="Poll until OpenSearch reports a healthy (yellow/green) cluster "
                                     "(use after a fresh bring-up, before anything that talks to "
                                     "OpenSearch directly -- e.g. the log_volume index template)")
    p_wait_os.add_argument("--timeout", type=float, default=120.0)
    p_wait_os.set_defaults(func=cmd_wait_for_opensearch)

    p_deploy = sub.add_parser("deploy-scenario-config",
                               help="Ensure a scenario's group(s) exist and push their agent.conf content")
    p_deploy.add_argument("--scenario", required=True)
    p_deploy.add_argument("--agent-config-dir", required=True, help="Path to scenarios/agent_configs")
    p_deploy.add_argument("--group", required=False, help="Override the scenario's own group name")
    p_deploy.set_defaults(func=cmd_deploy_scenario_config)

    p_deploy_mgr = sub.add_parser("deploy-manager-config",
                                   help="Deploy decoders/rules/CDB-list files and ossec.conf changes "
                                        "(default/scenario/shared snippets, decoder excludes, logall/"
                                        "logall_json), restarting the manager once if anything changed")
    p_deploy_mgr.add_argument("--scenario", required=True)
    p_deploy_mgr.add_argument("--scenarios-dir", required=True, help="Path to the scenarios/ directory")
    p_deploy_mgr.add_argument("--no-wait", action="store_true",
                               help="Don't wait for the API to come back after a restart")
    p_deploy_mgr.add_argument("--restart-timeout", type=float, default=90.0)
    p_deploy_mgr.set_defaults(func=cmd_deploy_manager_config)

    p_undo_scenario = sub.add_parser("undo-scenario-config",
                                      help="Undo of deploy-scenario-config: reset the scenario's own group "
                                           "agent.conf to empty, and unenroll every agent currently in that "
                                           "group from it. Idempotent. Leaves the group itself, 'default', "
                                           "and 'radar_shared' untouched.")
    p_undo_scenario.add_argument("--scenario", required=True)
    p_undo_scenario.add_argument("--group", required=False, help="Override the scenario's own group name")
    p_undo_scenario.add_argument("--radar-root", default=".",
                                  help="RADAR root, used to check shared_scenarios(). Defaults to cwd.")
    p_undo_scenario.set_defaults(func=cmd_undo_scenario_config)

    p_undo_mgr = sub.add_parser("undo-manager-config",
                                 help="Undo of deploy-manager-config: remove the ossec.conf block marked with "
                                      "the scenario's own name, and any decoder/rule/list file this scenario "
                                      "ships -- unless another scenario sharing that same filename is still "
                                      "currently deployed, in which case it's left in place until that other "
                                      "scenario is undeployed too. Idempotent. Deliberately leaves shared "
                                      "ossec.conf blocks and filesystem-level changes in place -- see the "
                                      "function docstring for why.")
    p_undo_mgr.add_argument("--scenario", required=True)
    p_undo_mgr.add_argument("--scenarios-dir", required=True, help="Path to the scenarios/ directory")
    p_undo_mgr.add_argument("--no-wait", action="store_true",
                             help="Don't wait for the API to come back after a restart")
    p_undo_mgr.add_argument("--restart-timeout", type=float, default=90.0)
    p_undo_mgr.set_defaults(func=cmd_undo_manager_config)

    p_status = sub.add_parser("agent-status", help="Resolve an agent by name/ip and report its connection status")
    p_status.add_argument("--name", required=True)
    p_status.add_argument("--ip", required=False, default="")
    p_status.set_defaults(func=cmd_agent_status)

    p_assign_hosts = sub.add_parser("assign-hosts-to-groups",
                                     help="Assign an explicit, comma-separated list of hosts to a scenario's Wazuh "
                                          "groups -- no ansible-inventory subprocess, no vault concerns")
    p_assign_hosts.add_argument("--hosts", required=True,
                                 help="Comma-separated 'name:ip' pairs, ip optional (e.g. 'host1:,host2:10.0.0.5')")
    p_assign_hosts.add_argument("--scenario", required=True)
    p_assign_hosts.add_argument("--group", required=False, help="Override the scenario's own group name")
    p_assign_hosts.add_argument("--radar-root", default=".",
                                 help="RADAR root, used to locate fleet.yaml for tracking. Defaults to cwd.")
    p_assign_hosts.set_defaults(func=cmd_assign_hosts_to_groups)

    p_unassign_hosts = sub.add_parser("unassign-hosts-from-groups",
                                       help="Undo of assign-hosts-to-groups: remove hosts from a scenario's own "
                                            "Wazuh group(s), leaving 'default' membership untouched. Idempotent -- "
                                            "a host that isn't currently enrolled is treated as already done.")
    p_unassign_hosts.add_argument("--hosts", required=True,
                                   help="Comma-separated 'name:ip' pairs, ip optional (e.g. 'host1:,host2:10.0.0.5')")
    p_unassign_hosts.add_argument("--scenario", required=True)
    p_unassign_hosts.add_argument("--group", required=False, help="Override the scenario's own group name")
    p_unassign_hosts.set_defaults(func=cmd_unassign_hosts_from_groups)

    p_deregister = sub.add_parser("deregister-agent",
                                   help="Undo of enrollment: resolve an agent by name/ip and remove it from the "
                                        "manager entirely. Idempotent -- an already-removed or never-enrolled "
                                        "agent is treated as already done, not an error.")
    p_deregister.add_argument("--name", required=True)
    p_deregister.add_argument("--ip", required=False, default="")
    p_deregister.add_argument("--no-purge", action="store_true",
                               help="Keep the agent's entry reserved instead of freeing its name/IP for reuse")
    p_deregister.set_defaults(func=cmd_deregister_agent)

    p_ensure = sub.add_parser("ensure-group", help="Create a Wazuh agent group if it doesn't already exist")
    p_ensure.add_argument("--group", required=True)
    p_ensure.set_defaults(func=cmd_ensure_group)

    p_upload = sub.add_parser("upload-group-config", help="Replace a group's agent.conf from a local file")
    p_upload.add_argument("--group", required=True)
    p_upload.add_argument("--file", required=True)
    p_upload.set_defaults(func=cmd_upload_group_config)

    p_assign = sub.add_parser("assign-agent-groups",
                               help="Resolve an agent by name and assign it to one or more groups (additive)")
    p_assign.add_argument("--agent-name", required=True)
    p_assign.add_argument("--groups", required=True, help="Comma-separated group names")
    p_assign.set_defaults(func=cmd_assign_agent_groups)

    p_scenario_info = sub.add_parser("scenario-info",
                                      help="Validate a scenario name and print its container_name from config.yaml")
    p_scenario_info.add_argument("scenario")
    p_scenario_info.set_defaults(func=cmd_scenario_info)

    p_list_scenarios = sub.add_parser("list-scenarios",
                                       help="Print every valid scenario name from config.yaml, space-separated")
    p_list_scenarios.set_defaults(func=cmd_list_scenarios)

    p_mgr_health = sub.add_parser("manager-health-api",
                                   help="Manager checks that are plain HTTP: daemons, ossec.conf wiring, "
                                        "decoder/rule/list files, OpenSearch, webhook. Pair with "
                                        "radar_deploy/manager-health.sh for filesystem-level checks.")
    p_mgr_health.add_argument("--scenario", default="all")
    p_mgr_health.set_defaults(func=cmd_manager_health_api)

    p_agent_health = sub.add_parser("agent-health",
                                     help="Agent status + group membership via the Wazuh API only")
    p_agent_health.add_argument("--agent-name", required=True, help="Comma-separated agent name(s)")
    p_agent_health.add_argument("--scenario", default="all")
    p_agent_health.set_defaults(func=cmd_agent_health)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())