"""
Wazuh API client library for RADAR.
"""
from .client import WazuhAPIClient, WazuhAPIError
from .groups import (
    assign_agent_to_group,
    assign_agent_to_groups,
    ensure_group,
    get_agent_by_name,
    list_agents,
    upload_group_config,
    upload_group_config_from_file,
)
from .manager_config import (
    apply_marked_block,
    apply_tag_value,
    get_raw_config,
    restart_manager,
    update_raw_config,
    wait_for_api,
)
from .ruleset import upload_decoder_file, upload_list_file, upload_rule_file
from .scenario_ops import (
    SHARED_GROUP,
    deploy_manager_config,
    deploy_ruleset_files,
    deploy_scenario_config,
    scenario_groups,
)

__all__ = [
    "WazuhAPIClient",
    "WazuhAPIError",
    "ensure_group",
    "upload_group_config",
    "upload_group_config_from_file",
    "get_agent_by_name",
    "assign_agent_to_group",
    "assign_agent_to_groups",
    "list_agents",
    "get_raw_config",
    "update_raw_config",
    "restart_manager",
    "wait_for_api",
    "apply_marked_block",
    "apply_tag_value",
    "upload_decoder_file",
    "upload_rule_file",
    "upload_list_file",
    "scenario_groups",
    "deploy_scenario_config",
    "deploy_manager_config",
    "deploy_ruleset_files",
    "SHARED_GROUP",
]