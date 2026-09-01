import json

import pytest
import responses

from wazuh_api.client import WazuhAPIClient, WazuhAPIError
from wazuh_api.groups import (
    assign_agent_to_group,
    assign_agent_to_groups,
    ensure_group,
    get_agent_by_ip,
    get_agent_by_name,
    list_agents,
    resolve_agent,
    upload_group_config,
    upload_group_config_from_file,
)

BASE = "https://manager:55000"


def _add_auth_mock():
    responses.add(
        responses.POST,
        f"{BASE}/security/user/authenticate",
        json={"data": {"token": "fake-jwt-token"}, "error": 0},
        status=200,
    )


def _client():
    return WazuhAPIClient(BASE, "user", "pass")


@responses.activate
def test_authenticates_once_and_reuses_token():
    _add_auth_mock()
    responses.add(responses.GET, f"{BASE}/agents", json={"data": {"affected_items": [], "total_affected_items": 0}})
    client = _client()

    client.get("/agents", params={"name": "a"})
    client.get("/agents", params={"name": "b"})

    auth_calls = [c for c in responses.calls if c.request.url.endswith("/security/user/authenticate")]
    assert len(auth_calls) == 1  # second call reused the cached token


@responses.activate
def test_reauthenticates_on_401():
    _add_auth_mock()
    # First call rejected (token considered invalid server-side), second succeeds.
    responses.add(responses.GET, f"{BASE}/agents", status=401, json={"title": "Unauthorized"})
    responses.add(responses.POST, f"{BASE}/security/user/authenticate",
                  json={"data": {"token": "fresh-token"}, "error": 0}, status=200)
    responses.add(responses.GET, f"{BASE}/agents", json={"data": {"affected_items": [], "total_affected_items": 0}})

    client = _client()
    resp = client.get("/agents", params={"name": "a"})
    assert resp.status_code == 200


@responses.activate
def test_authentication_failure_raises():
    responses.add(responses.POST, f"{BASE}/security/user/authenticate", status=401,
                  json={"title": "Unauthorized", "detail": "Invalid credentials"})
    client = _client()
    with pytest.raises(WazuhAPIError) as exc_info:
        client.get("/agents")
    assert exc_info.value.status_code == 401


@responses.activate
def test_ensure_group_creates_new_group():
    _add_auth_mock()
    responses.add(responses.POST, f"{BASE}/groups",
                  json={"data": {}, "message": "Group 'suspicious_login' created", "error": 0}, status=200)
    client = _client()

    created = ensure_group(client, "suspicious_login")
    assert created is True


@responses.activate
def test_ensure_group_tolerates_already_exists():
    _add_auth_mock()
    responses.add(responses.POST, f"{BASE}/groups",
                  json={"title": "Bad Request", "detail": "The group already exists", "error": 1711}, status=400)
    client = _client()

    created = ensure_group(client, "suspicious_login")
    assert created is False  # tolerated, not raised


@responses.activate
def test_ensure_group_raises_on_unexpected_error():
    _add_auth_mock()
    responses.add(responses.POST, f"{BASE}/groups",
                  json={"title": "Forbidden", "detail": "no permission", "error": 4000}, status=403)
    client = _client()

    with pytest.raises(WazuhAPIError) as exc_info:
        ensure_group(client, "suspicious_login")
    assert exc_info.value.status_code == 403
    assert exc_info.value.error_code == 4000


@responses.activate
def test_upload_group_config_sends_raw_xml_with_correct_content_type():
    _add_auth_mock()

    def request_callback(request):
        assert request.headers["Content-Type"] == "application/xml"
        assert request.body.decode() == "<agent_config os=\"Linux\"></agent_config>"
        return (200, {}, json.dumps({"data": {}, "message": "Agent configuration was successfully updated", "error": 0}))

    responses.add_callback(
        responses.PUT, f"{BASE}/groups/suspicious_login/configuration",
        callback=request_callback, content_type="application/json",
    )
    client = _client()

    message = upload_group_config(client, "suspicious_login", '<agent_config os="Linux"></agent_config>')
    assert message == "Agent configuration was successfully updated"


@responses.activate
def test_upload_group_config_from_file(tmp_path):
    _add_auth_mock()
    responses.add(responses.PUT, f"{BASE}/groups/geoip_detection/configuration",
                  json={"data": {}, "message": "Agent configuration was successfully updated", "error": 0}, status=200)
    snippet = tmp_path / "snippet.xml"
    snippet.write_text('<agent_config os="Linux"><localfile><location>/var/log/apache2/access.log</location></localfile></agent_config>')

    client = _client()
    message = upload_group_config_from_file(client, "geoip_detection", str(snippet))
    assert message == "Agent configuration was successfully updated"

@responses.activate
def test_get_agent_by_name_found():
    _add_auth_mock()
    responses.add(responses.GET, f"{BASE}/agents",
                  json={"data": {"affected_items": [
                      {"id": "003", "name": "edge-vm-2", "status": "active", "group": ["default"]}
                  ], "total_affected_items": 1}, "error": 0}, status=200)
    client = _client()

    agent = get_agent_by_name(client, "edge-vm-2")
    assert agent is not None
    assert agent["id"] == "003"


@responses.activate
def test_get_agent_by_name_not_found():
    _add_auth_mock()
    responses.add(responses.GET, f"{BASE}/agents",
                  json={"data": {"affected_items": [], "total_affected_items": 0}, "error": 0}, status=200)
    client = _client()

    agent = get_agent_by_name(client, "does-not-exist")
    assert agent is None


@responses.activate
def test_get_agent_by_ip_found():
    _add_auth_mock()
    responses.add(responses.GET, f"{BASE}/agents",
                  json={"data": {"affected_items": [
                      {"id": "003", "name": "edge-vm-01", "status": "active"}
                  ], "total_affected_items": 1}, "error": 0}, status=200)
    client = _client()

    agent = get_agent_by_ip(client, "203.0.113.10")
    assert agent is not None
    assert agent["id"] == "003"


def test_get_agent_by_ip_returns_none_for_empty_ip():
    client = _client()
    assert get_agent_by_ip(client, "") is None


@responses.activate
def test_resolve_agent_finds_by_name_without_trying_ip():
    _add_auth_mock()
    responses.add(responses.GET, f"{BASE}/agents",
                  json={"data": {"affected_items": [{"id": "001", "name": "edge.vm"}],
                                  "total_affected_items": 1}, "error": 0}, status=200)
    client = _client()

    agent = resolve_agent(client, "edge.vm", "203.0.113.10")
    assert agent["id"] == "001"
    ip_calls = [c for c in responses.calls if "ip=" in c.request.url]
    assert ip_calls == []


@responses.activate
def test_resolve_agent_falls_back_to_ip():
    _add_auth_mock()
    responses.add(responses.GET, f"{BASE}/agents?name=edge.vm",
                  json={"data": {"affected_items": [], "total_affected_items": 0}}, status=200)
    responses.add(responses.GET, f"{BASE}/agents?ip=203.0.113.10",
                  json={"data": {"affected_items": [{"id": "003", "name": "edge-vm-01"}],
                                  "total_affected_items": 1}}, status=200)
    client = _client()

    agent = resolve_agent(client, "edge.vm", "203.0.113.10")
    assert agent["id"] == "003"


@responses.activate
def test_resolve_agent_returns_none_when_both_fail():
    _add_auth_mock()
    responses.add(responses.GET, f"{BASE}/agents?name=ghost.vm",
                  json={"data": {"affected_items": [], "total_affected_items": 0}}, status=200)
    responses.add(responses.GET, f"{BASE}/agents?ip=10.0.0.99",
                  json={"data": {"affected_items": [], "total_affected_items": 0}}, status=200)
    client = _client()

    assert resolve_agent(client, "ghost.vm", "10.0.0.99") is None


@responses.activate
def test_assign_agent_to_group_is_additive_call():
    _add_auth_mock()
    responses.add(responses.PUT, f"{BASE}/agents/003/group/suspicious_login",
                  json={"data": {"affected_items": ["003"], "total_affected_items": 1},
                        "message": "All selected agents were assigned to suspicious_login", "error": 0}, status=200)
    client = _client()

    message = assign_agent_to_group(client, "003", "suspicious_login")
    assert "suspicious_login" in message
    # Confirm force_single_group was NOT passed -- additive assignment is the point.
    assert "force_single_group" not in responses.calls[-1].request.url


@responses.activate
def test_assign_agent_to_groups_calls_each_group():
    _add_auth_mock()
    for group in ("suspicious_login", "radar_shared"):
        responses.add(responses.PUT, f"{BASE}/agents/003/group/{group}",
                      json={"message": f"assigned to {group}", "error": 0}, status=200)
    client = _client()

    messages = assign_agent_to_groups(client, "003", ["suspicious_login", "radar_shared"])
    assert messages == ["assigned to suspicious_login", "assigned to radar_shared"]

@responses.activate
def test_list_agents_paginates_across_multiple_pages():
    _add_auth_mock()
    page1 = {"data": {"affected_items": [{"id": "001"}, {"id": "002"}], "total_affected_items": 3}, "error": 0}
    page2 = {"data": {"affected_items": [{"id": "003"}], "total_affected_items": 3}, "error": 0}
    responses.add(responses.GET, f"{BASE}/agents", json=page1, status=200)
    responses.add(responses.GET, f"{BASE}/agents", json=page2, status=200)
    client = _client()

    agents = list_agents(client, status="active")
    assert [a["id"] for a in agents] == ["001", "002", "003"]


@responses.activate
def test_list_agents_stops_on_empty_batch_even_if_total_mismatched():
    _add_auth_mock()
    # Defensive case: total_affected_items overstates what's actually returned.
    responses.add(responses.GET, f"{BASE}/agents",
                  json={"data": {"affected_items": [], "total_affected_items": 5}, "error": 0}, status=200)
    client = _client()

    agents = list_agents(client)
    assert agents == []

@responses.activate
def test_retries_once_on_429(monkeypatch):
    import wazuh_api.client as client_mod
    monkeypatch.setattr(client_mod.time, "sleep", lambda _s: None)  # don't actually wait in tests

    _add_auth_mock()
    responses.add(responses.GET, f"{BASE}/agents", status=429, json={"title": "Too Many Requests", "error": 429})
    responses.add(responses.GET, f"{BASE}/agents", json={"data": {"affected_items": [], "total_affected_items": 0}}, status=200)
    client = _client()

    resp = client.get("/agents")
    assert resp.status_code == 200