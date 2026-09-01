import json
from pathlib import Path

import pytest
import responses
import yaml

from wazuh_api import config
from wazuh_api.client import WazuhAPIClient
from wazuh_api.manager_config import apply_marked_block, apply_tag_value
from wazuh_api.ruleset import DECODER_NOT_FOUND, LIST_NOT_FOUND, RULE_NOT_FOUND
from wazuh_api.scenario_ops import (
    SHARED_GROUP,
    assign_hosts_to_scenario_groups,
    deploy_manager_config,
    deploy_ruleset_files,
    deploy_scenario_config,
    scenario_groups,
    scenario_list_files,
    scenario_snippet_path,
    shared_snippet_path,
)

BASE = "https://manager:55000"


def _add_auth_mock():
    responses.add(responses.POST, f"{BASE}/security/user/authenticate",
                   json={"data": {"token": "fake-jwt-token"}, "error": 0}, status=200)


def _client():
    return WazuhAPIClient(BASE, "user", "pass")

def test_scenario_groups_suspicious_login_includes_shared():
    assert scenario_groups("suspicious_login") == ["default", "suspicious_login", SHARED_GROUP]


def test_scenario_groups_geoip_detection_includes_shared():
    assert scenario_groups("geoip_detection") == ["default", "geoip_detection", SHARED_GROUP]


def test_scenario_groups_other_scenario_excludes_shared():
    assert scenario_groups("log_volume") == ["default", "log_volume"]


def test_scenario_groups_respects_override():
    assert scenario_groups("suspicious_login", agent_group_override="custom_group") == \
        ["default", "custom_group", SHARED_GROUP]


def test_snippet_path_helpers():
    assert scenario_snippet_path("suspicious_login", "scenarios/agent_configs") == \
        "scenarios/agent_configs/suspicious_login/radar-suspicious-login-agent-snippet.xml"
    assert shared_snippet_path("scenarios/agent_configs") == \
        "scenarios/agent_configs/_shared/radar-shared-auth-log-agent-snippet.xml"


@responses.activate
def test_deploy_scenario_config_shared_scenario_deploys_both_groups(tmp_path):
    _add_auth_mock()
    responses.add(responses.POST, f"{BASE}/groups",
                   json={"message": "created", "error": 0}, status=200)
    responses.add(responses.PUT, f"{BASE}/groups/suspicious_login/configuration",
                   json={"message": "own config uploaded", "error": 0}, status=200)
    responses.add(responses.PUT, f"{BASE}/groups/radar_shared/configuration",
                   json={"message": "shared config uploaded", "error": 0}, status=200)

    agent_configs_dir = tmp_path / "scenarios" / "agent_configs"
    (agent_configs_dir / "suspicious_login").mkdir(parents=True)
    (agent_configs_dir / "suspicious_login" / "radar-suspicious-login-agent-snippet.xml").write_text("<agent_config/>")
    (agent_configs_dir / "_shared").mkdir(parents=True)
    (agent_configs_dir / "_shared" / "radar-shared-auth-log-agent-snippet.xml").write_text("<agent_config/>")
    (tmp_path / "config.yaml").write_text(yaml.safe_dump({"shared_scenarios": ["suspicious_login"]}))
    config.load.cache_clear()

    client = _client()
    results = deploy_scenario_config(client, "suspicious_login", str(agent_configs_dir))

    assert results["suspicious_login"]["config_message"] == "own config uploaded"
    assert results["radar_shared"]["config_message"] == "shared config uploaded"


@responses.activate
def test_deploy_scenario_config_skips_upload_for_empty_snippet_file(tmp_path):
    _add_auth_mock()
    responses.add(responses.POST, f"{BASE}/groups", json={"message": "created", "error": 0}, status=200)
    responses.add(responses.PUT, f"{BASE}/groups/{SHARED_GROUP}/configuration",
                   json={"message": "shared config uploaded", "error": 0}, status=200)

    agent_configs_dir = tmp_path / "agent_configs"
    (agent_configs_dir / "suspicious_login").mkdir(parents=True)
    (agent_configs_dir / "suspicious_login" / "radar-suspicious-login-agent-snippet.xml").write_text("")
    (agent_configs_dir / "_shared").mkdir(parents=True)
    (agent_configs_dir / "_shared" / "radar-shared-auth-log-agent-snippet.xml").write_text("<agent_config/>")

    client = _client()
    results = deploy_scenario_config(client, "suspicious_login", str(agent_configs_dir))

    assert results["suspicious_login"]["group_created"] is True
    assert "skipped" in results["suspicious_login"]["config_message"]
    own_group_put_calls = [c for c in responses.calls
                            if c.request.method == "PUT" and "/groups/suspicious_login/" in c.request.url]
    assert own_group_put_calls == []


@responses.activate
def test_deploy_scenario_config_skips_upload_for_whitespace_only_snippet_file(tmp_path):
    _add_auth_mock()
    responses.add(responses.POST, f"{BASE}/groups", json={"message": "created", "error": 0}, status=200)
    responses.add(responses.PUT, f"{BASE}/groups/{SHARED_GROUP}/configuration",
                   json={"message": "shared config uploaded", "error": 0}, status=200)

    agent_configs_dir = tmp_path / "agent_configs"
    (agent_configs_dir / "suspicious_login").mkdir(parents=True)
    (agent_configs_dir / "suspicious_login" / "radar-suspicious-login-agent-snippet.xml").write_text("   \n\n  ")
    (agent_configs_dir / "_shared").mkdir(parents=True)
    (agent_configs_dir / "_shared" / "radar-shared-auth-log-agent-snippet.xml").write_text("<agent_config/>")

    client = _client()
    results = deploy_scenario_config(client, "suspicious_login", str(agent_configs_dir))

    assert "skipped" in results["suspicious_login"]["config_message"]
    own_group_put_calls = [c for c in responses.calls
                            if c.request.method == "PUT" and "/groups/suspicious_login/" in c.request.url]
    assert own_group_put_calls == []


@responses.activate
def test_deploy_scenario_config_still_uploads_comment_only_snippet_file(tmp_path):
    _add_auth_mock()
    responses.add(responses.POST, f"{BASE}/groups", json={"message": "created", "error": 0}, status=200)
    responses.add(responses.PUT, f"{BASE}/groups/suspicious_login/configuration",
                   json={"message": "Agent configuration was successfully updated", "error": 0}, status=200)
    responses.add(responses.PUT, f"{BASE}/groups/{SHARED_GROUP}/configuration",
                   json={"message": "shared config uploaded", "error": 0}, status=200)

    agent_configs_dir = tmp_path / "agent_configs"
    (agent_configs_dir / "suspicious_login").mkdir(parents=True)
    (agent_configs_dir / "suspicious_login" / "radar-suspicious-login-agent-snippet.xml").write_text(
        "<!-- nothing to configure here, see shared snippet -->\n"
    )
    (agent_configs_dir / "_shared").mkdir(parents=True)
    (agent_configs_dir / "_shared" / "radar-shared-auth-log-agent-snippet.xml").write_text("<agent_config/>")

    client = _client()
    results = deploy_scenario_config(client, "suspicious_login", str(agent_configs_dir))

    assert results["suspicious_login"]["config_message"] == "Agent configuration was successfully updated"
    own_group_put_calls = [c for c in responses.calls
                            if c.request.method == "PUT" and "/groups/suspicious_login/" in c.request.url]
    assert len(own_group_put_calls) == 1


@responses.activate
def test_deploy_scenario_config_non_shared_scenario_only_deploys_own_group(tmp_path):
    _add_auth_mock()
    responses.add(responses.POST, f"{BASE}/groups", json={"message": "created", "error": 0}, status=200)
    responses.add(responses.PUT, f"{BASE}/groups/log_volume/configuration",
                   json={"message": "own config uploaded", "error": 0}, status=200)

    agent_configs_dir = tmp_path / "agent_configs"
    (agent_configs_dir / "log_volume").mkdir(parents=True)
    (agent_configs_dir / "log_volume" / "radar-log-volume-agent-snippet.xml").write_text("<agent_config/>")

    client = _client()
    results = deploy_scenario_config(client, "log_volume", str(agent_configs_dir))

    assert "log_volume" in results
    assert SHARED_GROUP not in results
    # Confirm no PUT was attempted against the shared group's endpoint.
    shared_calls = [c for c in responses.calls if f"/groups/{SHARED_GROUP}/configuration" in c.request.url]
    assert shared_calls == []


@responses.activate
def test_assign_hosts_to_scenario_groups_assigns_each_resolved_host():
    _add_auth_mock()
    responses.add(responses.GET, f"{BASE}/agents",
                   json={"data": {"affected_items": [{"id": "001", "name": "edge-vm-1"}], "total_affected_items": 1}},
                   status=200)
    responses.add(responses.GET, f"{BASE}/agents",
                   json={"data": {"affected_items": [{"id": "002", "name": "edge-vm-2"}], "total_affected_items": 1}},
                   status=200)
    for group in ("default", "suspicious_login", "radar_shared"):
        responses.add(responses.PUT, f"{BASE}/agents/001/group/{group}",
                       json={"message": f"assigned 001 to {group}", "error": 0}, status=200)
        responses.add(responses.PUT, f"{BASE}/agents/002/group/{group}",
                       json={"message": f"assigned 002 to {group}", "error": 0}, status=200)

    client = _client()
    results = assign_hosts_to_scenario_groups(
        client, [("edge-vm-1", None), ("edge-vm-2", None)], "suspicious_login"
    )

    assert results["edge-vm-1"]["resolved"] is True
    assert results["edge-vm-1"]["agent_id"] == "001"
    assert results["edge-vm-1"]["resolved_via"] == "name"
    assert results["edge-vm-2"]["agent_id"] == "002"
    assert results["edge-vm-1"]["groups"] == ["default", "suspicious_login", "radar_shared"]


@responses.activate
def test_assign_hosts_to_scenario_groups_tolerates_unresolved_host():
    _add_auth_mock()
    responses.add(responses.GET, f"{BASE}/agents",
                   json={"data": {"affected_items": [], "total_affected_items": 0}}, status=200)

    client = _client()
    results = assign_hosts_to_scenario_groups(client, [("not-yet-enrolled", None)], "geoip_detection")

    assert results["not-yet-enrolled"]["resolved"] is False
    assert "warning" in results["not-yet-enrolled"]


@responses.activate
def test_assign_hosts_to_scenario_groups_no_ansible_inventory_call_at_all():
    _add_auth_mock()
    responses.add(responses.GET, f"{BASE}/agents",
                   json={"data": {"affected_items": [{"id": "005", "name": "host1"}], "total_affected_items": 1}},
                   status=200)
    responses.add(responses.PUT, f"{BASE}/agents/005/group/default",
                   json={"message": "ok", "error": 0}, status=200)
    responses.add(responses.PUT, f"{BASE}/agents/005/group/log_volume",
                   json={"message": "ok", "error": 0}, status=200)

    client = _client()
    results = assign_hosts_to_scenario_groups(client, [("host1", None)], "log_volume")

    assert results["host1"]["resolved"] is True


@responses.activate
def test_assign_hosts_to_scenario_groups_falls_back_to_ip_when_name_fails():
    _add_auth_mock()
    # Name lookup for the inventory alias finds nothing...
    responses.add(responses.GET, f"{BASE}/agents?name=edge.vm",
                   json={"data": {"affected_items": [], "total_affected_items": 0}}, status=200)
    responses.add(responses.GET, f"{BASE}/agents?ip=203.0.113.10",
                   json={"data": {"affected_items": [{"id": "001", "name": "edge-vm-01"}],
                                   "total_affected_items": 1}}, status=200)
    for group in ("default", "suspicious_login", "radar_shared"):
        responses.add(responses.PUT, f"{BASE}/agents/001/group/{group}",
                       json={"message": f"assigned to {group}", "error": 0}, status=200)

    client = _client()
    results = assign_hosts_to_scenario_groups(client, [("edge.vm", "203.0.113.10")], "suspicious_login")

    assert results["edge.vm"]["resolved"] is True
    assert results["edge.vm"]["agent_id"] == "001"
    assert results["edge.vm"]["resolved_via"] == "ip"


@responses.activate
def test_assign_hosts_to_scenario_groups_tries_ip_before_name(tmp_path):
    """Current behavior: when both a name and an IP are given, IP is tried
    first; name is only tried if the IP lookup comes back empty."""
    _add_auth_mock()
    responses.add(responses.GET, f"{BASE}/agents?ip=203.0.113.10",
                   json={"data": {"affected_items": [{"id": "001", "name": "edge.vm"}],
                                   "total_affected_items": 1}}, status=200)
    responses.add(responses.PUT, f"{BASE}/agents/001/group/default",
                   json={"message": "ok", "error": 0}, status=200)
    responses.add(responses.PUT, f"{BASE}/agents/001/group/log_volume",
                   json={"message": "ok", "error": 0}, status=200)

    client = _client()
    results = assign_hosts_to_scenario_groups(client, [("edge.vm", "203.0.113.10")], "log_volume")

    assert results["edge.vm"]["resolved_via"] == "ip"
    name_calls = [c for c in responses.calls if "name=" in c.request.url]
    assert name_calls == []


@responses.activate
def test_assign_hosts_to_scenario_groups_no_ip_available_skips_fallback_cleanly():
    _add_auth_mock()
    responses.add(responses.GET, f"{BASE}/agents?name=edge.vm",
                   json={"data": {"affected_items": [], "total_affected_items": 0}}, status=200)

    client = _client()
    results = assign_hosts_to_scenario_groups(client, [("edge.vm", None)], "suspicious_login")

    assert results["edge.vm"]["resolved"] is False
    assert "GET /agents?ip=" not in results["edge.vm"]["warning"]
    ip_calls = [c for c in responses.calls if "ip=" in c.request.url]
    assert ip_calls == []


@responses.activate
def test_assign_hosts_to_scenario_groups_unresolved_via_both_name_and_ip():
    _add_auth_mock()
    responses.add(responses.GET, f"{BASE}/agents?name=ghost.vm",
                   json={"data": {"affected_items": [], "total_affected_items": 0}}, status=200)
    responses.add(responses.GET, f"{BASE}/agents?ip=10.0.0.99",
                   json={"data": {"affected_items": [], "total_affected_items": 0}}, status=200)

    client = _client()
    results = assign_hosts_to_scenario_groups(client, [("ghost.vm", "10.0.0.99")], "suspicious_login")

    assert results["ghost.vm"]["resolved"] is False
    assert "name=ghost.vm" in results["ghost.vm"]["warning"]
    assert "ip=10.0.0.99" in results["ghost.vm"]["warning"]


REALISTIC_OSSEC_CONF = """<ossec_config>
  <global>
    <logall>no</logall>
    <logall_json>no</logall_json>
  </global>
  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
  </ruleset>
</ossec_config>
"""


def _make_scenarios_dir(tmp_path, scenario_name, with_shared=False, with_ssh_decoder=False,
                         with_web_decoder=False, with_whitelist=False,
                         with_default_rules=False, with_scenario_rules=False,
                         shared_scenario_names=(), whitelist_scenario_names=(),
                         scenario_lists=()):
    scenarios_dir = tmp_path / "scenarios"
    (scenarios_dir / "ossec").mkdir(parents=True)
    (scenarios_dir / "ossec" / "radar-default-ossec-snippet.xml").write_text(
        "<command><name>radar_ar_default</name></command>"
    )
    slug = scenario_name.replace("_", "-")
    (scenarios_dir / "ossec" / f"radar-{slug}-ossec-snippet.xml").write_text(
        f"<command><name>radar_ar_{scenario_name}</name></command>"
    )
    if with_shared:
        (scenarios_dir / "ossec" / "radar-shared-auth-log-ossec-snippet.xml").write_text(
            "<integration><name>custom-radar-enrich</name></integration>"
        )
    (scenarios_dir / "decoders" / scenario_name).mkdir(parents=True)
    if with_ssh_decoder:
        (scenarios_dir / "decoders" / scenario_name / "0310-ssh.xml").write_text("<decoder name=\"x\"></decoder>")
    if with_web_decoder:
        (scenarios_dir / "decoders" / scenario_name / "0375-web-accesslog.xml").write_text(
            "<decoder name=\"y\"></decoder>"
        )
    if with_whitelist:
        (scenarios_dir / "lists").mkdir(parents=True, exist_ok=True)
        (scenarios_dir / "lists" / "whitelist_countries").write_text("US\nCA\n")
    if scenario_lists:
        (scenarios_dir / "lists" / scenario_name).mkdir(parents=True, exist_ok=True)
        for list_name in scenario_lists:
            (scenarios_dir / "lists" / scenario_name / list_name).write_text("10.0.0.1:note\n")
    if with_default_rules:
        (scenarios_dir / "rules" / "default").mkdir(parents=True)
        (scenarios_dir / "rules" / "default" / "radar_rules.xml").write_text("<group name=\"radar_default\"></group>")
    if with_scenario_rules:
        (scenarios_dir / "rules" / scenario_name).mkdir(parents=True)
        (scenarios_dir / "rules" / scenario_name / f"a2-{slug}.xml").write_text(
            f"<group name=\"{scenario_name}\"></group>"
        )

    config_yaml_path = tmp_path / "config.yaml"
    cfg = yaml.safe_load(config_yaml_path.read_text()) if config_yaml_path.exists() else {}
    cfg.setdefault("shared_scenarios", [])
    cfg.setdefault("whitelist_scenarios", [])
    for name in shared_scenario_names:
        if name not in cfg["shared_scenarios"]:
            cfg["shared_scenarios"].append(name)
    for name in whitelist_scenario_names:
        if name not in cfg["whitelist_scenarios"]:
            cfg["whitelist_scenarios"].append(name)
    config_yaml_path.write_text(yaml.safe_dump(cfg))
    config.load.cache_clear()

    return str(scenarios_dir)


def _mock_no_ruleset_files_exist():
    responses.add(responses.GET, f"{BASE}/decoders/files/0310-ssh.xml",
                   json={"title": "Not Found", "error": DECODER_NOT_FOUND}, status=400)
    responses.add(responses.GET, f"{BASE}/decoders/files/0375-web-accesslog.xml",
                   json={"title": "Not Found", "error": DECODER_NOT_FOUND}, status=400)
    responses.add(responses.GET, f"{BASE}/rules/files/radar_rules.xml",
                   json={"title": "Not Found", "error": RULE_NOT_FOUND}, status=400)
    responses.add(responses.GET, f"{BASE}/lists/files/whitelist_countries",
                   json={"title": "Not Found", "error": LIST_NOT_FOUND}, status=400)


@responses.activate
def test_deploy_manager_config_applies_changes_and_restarts(tmp_path):
    scenarios_dir = _make_scenarios_dir(tmp_path, "suspicious_login", with_shared=True, with_ssh_decoder=True,
                                         shared_scenario_names=["suspicious_login"])

    _add_auth_mock()
    _mock_no_ruleset_files_exist()
    responses.add(responses.PUT, f"{BASE}/decoders/files/0310-ssh.xml", json={"message": "ok", "error": 0}, status=200)
    responses.add(responses.GET, f"{BASE}/manager/configuration", body=REALISTIC_OSSEC_CONF, status=200)
    responses.add(responses.PUT, f"{BASE}/manager/configuration",
                   json={"message": "Configuration was successfully updated", "error": 0}, status=200)
    responses.add(responses.PUT, f"{BASE}/manager/restart",
                   json={"message": "Restart request sent", "error": 0}, status=200)
    responses.add(responses.POST, f"{BASE}/security/user/authenticate",
                   json={"data": {"token": "post-restart-token"}, "error": 0}, status=200)

    client = _client()
    result = deploy_manager_config(client, "suspicious_login", scenarios_dir, restart_timeout=5)

    assert result["restart_triggered"] is True
    assert result["api_back_up"] is True
    assert result["ossec_changes"]["default"] is True
    assert result["ossec_changes"]["suspicious_login"] is True
    assert result["ossec_changes"]["shared_auth_log_enrichment"] is True
    assert result["ossec_changes"]["ssh_decoder_exclude"] is True
    assert result["ossec_changes"]["logall"] is True
    assert result["ossec_changes"]["logall_json"] is True
    assert result["ruleset_changes"]["decoder:0310-ssh.xml"] is True
    assert "web_accesslog_decoder_exclude" not in result["ossec_changes"]


@responses.activate
def test_deploy_manager_config_second_run_is_a_noop_no_restart(tmp_path):
    scenarios_dir = _make_scenarios_dir(tmp_path, "suspicious_login", with_shared=True, with_ssh_decoder=True,
                                         shared_scenario_names=["suspicious_login"])

    _add_auth_mock()
    decoder_content = (Path(scenarios_dir) / "decoders" / "suspicious_login" / "0310-ssh.xml").read_text()
    responses.add(responses.GET, f"{BASE}/decoders/files/0310-ssh.xml", body=decoder_content, status=200)

    already_applied = REALISTIC_OSSEC_CONF
    for marker, path in [
        ("default", Path(scenarios_dir) / "ossec" / "radar-default-ossec-snippet.xml"),
        ("suspicious_login", Path(scenarios_dir) / "ossec" / "radar-suspicious-login-ossec-snippet.xml"),
        ("shared auth_log_enrichment", Path(scenarios_dir) / "ossec" / "radar-shared-auth-log-ossec-snippet.xml"),
    ]:
        already_applied, _ = apply_marked_block(already_applied, marker, path.read_text(), "</ossec_config>")
    already_applied, _ = apply_marked_block(
        already_applied, "ssh decoder_exclude",
        "<decoder_exclude>0310-ssh_decoders.xml</decoder_exclude>", "</ruleset>",
    )
    already_applied, _ = apply_tag_value(already_applied, "logall", "yes")
    already_applied, _ = apply_tag_value(already_applied, "logall_json", "yes")

    responses.add(responses.GET, f"{BASE}/manager/configuration", body=already_applied, status=200)

    client = _client()
    result = deploy_manager_config(client, "suspicious_login", scenarios_dir, restart_timeout=5)

    assert result["restart_triggered"] is False
    assert all(v is False for v in result["ossec_changes"].values())
    assert all(v is False for v in result["ruleset_changes"].values())
    put_calls = [c for c in responses.calls if c.request.method == "PUT"]
    assert put_calls == []


@responses.activate
def test_deploy_manager_config_non_shared_scenario_skips_shared_block(tmp_path):
    scenarios_dir = _make_scenarios_dir(tmp_path, "log_volume", with_shared=False)

    _add_auth_mock()
    _mock_no_ruleset_files_exist()
    responses.add(responses.GET, f"{BASE}/manager/configuration", body=REALISTIC_OSSEC_CONF, status=200)
    responses.add(responses.PUT, f"{BASE}/manager/configuration",
                   json={"message": "updated", "error": 0}, status=200)
    responses.add(responses.PUT, f"{BASE}/manager/restart", json={"message": "Restart request sent"}, status=200)
    responses.add(responses.POST, f"{BASE}/security/user/authenticate",
                   json={"data": {"token": "t2"}, "error": 0}, status=200)

    client = _client()
    result = deploy_manager_config(client, "log_volume", scenarios_dir, restart_timeout=5)

    assert "shared_auth_log_enrichment" not in result["ossec_changes"]
    assert "ssh_decoder_exclude" not in result["ossec_changes"]
    assert "web_accesslog_decoder_exclude" not in result["ossec_changes"]


@responses.activate
def test_deploy_manager_config_applies_whitelist_entry_for_geoip_detection(tmp_path):
    scenarios_dir = _make_scenarios_dir(tmp_path, "geoip_detection", with_whitelist=True,
                                         whitelist_scenario_names=["geoip_detection"])

    _add_auth_mock()
    responses.add(responses.GET, f"{BASE}/decoders/files/0310-ssh.xml",
                   json={"title": "Not Found", "error": DECODER_NOT_FOUND}, status=400)
    responses.add(responses.GET, f"{BASE}/decoders/files/0375-web-accesslog.xml",
                   json={"title": "Not Found", "error": DECODER_NOT_FOUND}, status=400)
    responses.add(responses.GET, f"{BASE}/rules/files/radar_rules.xml",
                   json={"title": "Not Found", "error": RULE_NOT_FOUND}, status=400)
    responses.add(responses.GET, f"{BASE}/lists/files/whitelist_countries",
                   json={"title": "Not Found", "error": LIST_NOT_FOUND}, status=400)
    responses.add(responses.PUT, f"{BASE}/lists/files/whitelist_countries",
                   json={"message": "ok", "error": 0}, status=200)
    responses.add(responses.GET, f"{BASE}/manager/logs",
                   json={"data": {"affected_items": []}, "error": 0}, status=200)
    responses.add(responses.GET, f"{BASE}/manager/configuration", body=REALISTIC_OSSEC_CONF, status=200)
    responses.add(responses.PUT, f"{BASE}/manager/configuration",
                   json={"message": "updated", "error": 0}, status=200)
    responses.add(responses.PUT, f"{BASE}/manager/restart", json={"message": "Restart request sent"}, status=200)
    responses.add(responses.POST, f"{BASE}/security/user/authenticate",
                   json={"data": {"token": "t3"}, "error": 0}, status=200)

    client = _client()
    result = deploy_manager_config(client, "geoip_detection", scenarios_dir, restart_timeout=5)

    assert result["ossec_changes"]["whitelist_countries_list"] is True
    assert result["ruleset_changes"]["list:whitelist_countries"] is True


@responses.activate
def test_deploy_manager_config_skips_whitelist_entry_when_file_absent(tmp_path):
    scenarios_dir = _make_scenarios_dir(tmp_path, "geoip_detection", with_whitelist=False,
                                         whitelist_scenario_names=["geoip_detection"])

    _add_auth_mock()
    _mock_no_ruleset_files_exist()
    responses.add(responses.GET, f"{BASE}/manager/configuration", body=REALISTIC_OSSEC_CONF, status=200)
    responses.add(responses.PUT, f"{BASE}/manager/configuration",
                   json={"message": "updated", "error": 0}, status=200)
    responses.add(responses.PUT, f"{BASE}/manager/restart", json={"message": "Restart request sent"}, status=200)
    responses.add(responses.POST, f"{BASE}/security/user/authenticate",
                   json={"data": {"token": "t4"}, "error": 0}, status=200)

    client = _client()
    result = deploy_manager_config(client, "geoip_detection", scenarios_dir, restart_timeout=5)

    assert "whitelist_countries_list" not in result["ossec_changes"]
    assert "list:whitelist_countries" not in result["ruleset_changes"]


@responses.activate
def test_deploy_manager_config_never_applies_whitelist_to_non_geoip_scenario(tmp_path):
    scenarios_dir = _make_scenarios_dir(tmp_path, "suspicious_login", with_shared=True, with_whitelist=True,
                                         shared_scenario_names=["suspicious_login"])

    _add_auth_mock()
    _mock_no_ruleset_files_exist()
    responses.add(responses.GET, f"{BASE}/manager/configuration", body=REALISTIC_OSSEC_CONF, status=200)
    responses.add(responses.PUT, f"{BASE}/manager/configuration",
                   json={"message": "updated", "error": 0}, status=200)
    responses.add(responses.PUT, f"{BASE}/manager/restart", json={"message": "Restart request sent"}, status=200)
    responses.add(responses.POST, f"{BASE}/security/user/authenticate",
                   json={"data": {"token": "t5"}, "error": 0}, status=200)

    client = _client()
    result = deploy_manager_config(client, "suspicious_login", scenarios_dir, restart_timeout=5)

    assert "whitelist_countries_list" not in result["ossec_changes"]
    assert "list:whitelist_countries" not in result["ruleset_changes"]
    list_put_calls = [c for c in responses.calls if "/lists/files/" in c.request.url and c.request.method == "PUT"]
    assert list_put_calls == []


@responses.activate
def test_deploy_ruleset_files_uploads_decoders_and_rules(tmp_path):
    scenarios_dir = _make_scenarios_dir(
        tmp_path, "suspicious_login", with_ssh_decoder=True, with_default_rules=True, with_scenario_rules=True
    )

    _add_auth_mock()
    responses.add(responses.GET, f"{BASE}/decoders/files/0310-ssh.xml",
                   json={"error": DECODER_NOT_FOUND}, status=400)
    responses.add(responses.PUT, f"{BASE}/decoders/files/0310-ssh.xml", json={"message": "ok", "error": 0}, status=200)
    responses.add(responses.GET, f"{BASE}/rules/files/radar_rules.xml", json={"error": RULE_NOT_FOUND}, status=400)
    responses.add(responses.PUT, f"{BASE}/rules/files/radar_rules.xml", json={"message": "ok", "error": 0}, status=200)
    responses.add(responses.GET, f"{BASE}/rules/files/a2-suspicious-login.xml",
                   json={"error": RULE_NOT_FOUND}, status=400)
    responses.add(responses.PUT, f"{BASE}/rules/files/a2-suspicious-login.xml",
                   json={"message": "ok", "error": 0}, status=200)

    client = _client()
    changes = deploy_ruleset_files(client, "suspicious_login", scenarios_dir)

    assert changes["decoder:0310-ssh.xml"] is True
    assert changes["rule:radar_rules.xml"] is True
    assert changes["rule:a2-suspicious-login.xml"] is True
    assert "list:whitelist_countries" not in changes


@responses.activate
def test_deploy_ruleset_files_only_uploads_whitelist_for_geoip_detection(tmp_path):
    scenarios_dir = _make_scenarios_dir(tmp_path, "suspicious_login", with_whitelist=True)

    client = _client()
    _add_auth_mock()
    changes = deploy_ruleset_files(client, "suspicious_login", scenarios_dir)

    assert "list:whitelist_countries" not in changes
    list_calls = [c for c in responses.calls if "/lists/" in c.request.url]
    assert list_calls == []

@responses.activate
def test_deploy_manager_config_uploads_and_declares_scenario_owned_lists(tmp_path):
    scenarios_dir = _make_scenarios_dir(
        tmp_path, "scanning_detection",
        scenario_lists=["radar_scanning_allowlist", "radar_webdav_apps"],
    )

    _add_auth_mock()
    _mock_no_ruleset_files_exist()
    for list_name in ("radar_scanning_allowlist", "radar_webdav_apps"):
        responses.add(responses.GET, f"{BASE}/lists/files/{list_name}",
                       json={"title": "Not Found", "error": LIST_NOT_FOUND}, status=400)
        responses.add(responses.PUT, f"{BASE}/lists/files/{list_name}",
                       json={"message": "ok", "error": 0}, status=200)
    responses.add(responses.GET, f"{BASE}/manager/logs",
                   json={"data": {"affected_items": []}, "error": 0}, status=200)
    responses.add(responses.GET, f"{BASE}/manager/configuration", body=REALISTIC_OSSEC_CONF, status=200)
    responses.add(responses.PUT, f"{BASE}/manager/configuration",
                   json={"message": "updated", "error": 0}, status=200)
    responses.add(responses.PUT, f"{BASE}/manager/restart", json={"message": "Restart request sent"}, status=200)
    responses.add(responses.POST, f"{BASE}/security/user/authenticate",
                   json={"data": {"token": "t4"}, "error": 0}, status=200)

    client = _client()
    result = deploy_manager_config(client, "scanning_detection", scenarios_dir, restart_timeout=5)

    assert result["ruleset_changes"]["list:radar_scanning_allowlist"] is True
    assert result["ruleset_changes"]["list:radar_webdav_apps"] is True
    assert result["ossec_changes"]["list_radar_scanning_allowlist"] is True
    assert result["ossec_changes"]["list_radar_webdav_apps"] is True

    written = [c for c in responses.calls
               if c.request.method == "PUT" and c.request.url.startswith(f"{BASE}/manager/configuration")]
    assert written, "ossec.conf was never written"
    body = written[0].request.body
    body = body.decode() if isinstance(body, bytes) else body
    assert "<list>etc/lists/radar_scanning_allowlist</list>" in body
    assert "<list>etc/lists/radar_webdav_apps</list>" in body


def test_scenario_list_files_is_empty_for_scenarios_without_lists(tmp_path):
    scenarios_dir = _make_scenarios_dir(tmp_path, "suspicious_login")
    assert scenario_list_files("suspicious_login", scenarios_dir) == []
