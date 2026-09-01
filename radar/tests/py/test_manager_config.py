import pytest
import responses

from wazuh_api.client import WazuhAPIClient, WazuhAPIError
from wazuh_api.manager_config import (
    CONFIG_INVALID_ERROR,
    apply_marked_block,
    apply_tag_value,
    get_raw_config,
    restart_manager,
    update_raw_config,
    wait_for_api,
)

BASE = "https://manager:55000"

REALISTIC_OSSEC_CONF = """<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
  </global>

  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_dir>etc/rules</rule_dir>
    <decoder_dir>etc/decoders</decoder_dir>
    <list>etc/lists/audit-keys</list>
  </ruleset>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
  </remote>
</ossec_config>
"""


def _add_auth_mock():
    responses.add(responses.POST, f"{BASE}/security/user/authenticate",
                   json={"data": {"token": "fake-jwt-token"}, "error": 0}, status=200)


def _client():
    return WazuhAPIClient(BASE, "user", "pass")


def test_apply_marked_block_inserts_when_absent():
    block = "<command>\n    <name>radar_ar_default</name>\n    <executable>radar_ar.py</executable>\n</command>"
    new_content, changed = apply_marked_block(REALISTIC_OSSEC_CONF, "default", block, "</ossec_config>")

    assert changed is True
    assert "<!-- RADAR: default BEGIN -->" in new_content
    assert "<!-- RADAR: default END -->" in new_content
    assert "radar_ar_default" in new_content
    assert new_content.index("radar_ar_default") < new_content.index("</ossec_config>")
    assert "<port>1514</port>" in new_content


def test_apply_marked_block_is_idempotent_on_second_call():
    block = "<command><name>radar_ar_default</name></command>"
    first, changed1 = apply_marked_block(REALISTIC_OSSEC_CONF, "default", block, "</ossec_config>")
    second, changed2 = apply_marked_block(first, "default", block, "</ossec_config>")

    assert changed1 is True
    assert changed2 is False  # nothing to do, block already present with identical content
    assert first == second
    assert second.count("<!-- RADAR: default BEGIN -->") == 1  # not duplicated


def test_apply_marked_block_replaces_existing_content_when_it_changes():
    block_v1 = "<command><name>radar_ar_default</name></command>"
    block_v2 = "<command><name>radar_ar_default_v2</name></command>"

    with_v1, _ = apply_marked_block(REALISTIC_OSSEC_CONF, "default", block_v1, "</ossec_config>")
    with_v2, changed = apply_marked_block(with_v1, "default", block_v2, "</ossec_config>")

    assert changed is True
    assert "radar_ar_default_v2" in with_v2
    assert "radar_ar_default</name>" not in with_v2  # old content is gone, not duplicated alongside
    assert with_v2.count("<!-- RADAR: default BEGIN -->") == 1


def test_apply_marked_block_multiple_independent_markers_coexist():
    default_block = "<command><name>radar_ar_default</name></command>"
    scenario_block = "<integration><name>custom-radar-enrich</name></integration>"

    step1, _ = apply_marked_block(REALISTIC_OSSEC_CONF, "default", default_block, "</ossec_config>")
    step2, _ = apply_marked_block(step1, "shared auth_log_enrichment", scenario_block, "</ossec_config>")

    assert "radar_ar_default" in step2
    assert "custom-radar-enrich" in step2
    assert step2.count("<!-- RADAR:") == 4  # 2 BEGIN + 2 END, independent of each other


def test_apply_marked_block_decoder_exclude_uses_ruleset_anchor():
    new_content, changed = apply_marked_block(
        REALISTIC_OSSEC_CONF, "ssh decoder_exclude",
        "<decoder_exclude>0310-ssh_decoders.xml</decoder_exclude>", "</ruleset>",
    )
    assert changed is True
    assert new_content.index("decoder_exclude") < new_content.index("</ruleset>")
    # Must not accidentally land inside <ossec_config> at the very end instead.
    assert new_content.index("</ruleset>") < new_content.index("</ossec_config>")


def test_apply_marked_block_insert_after_places_content_right_after_anchor():
    new_content, changed = apply_marked_block(
        REALISTIC_OSSEC_CONF, "whitelist_countries list",
        "<list>etc/lists/whitelist_countries</list>", insert_after="<ruleset>",
    )
    assert changed is True
    assert new_content.index("<ruleset>") < new_content.index("whitelist_countries")
    assert new_content.index("whitelist_countries") < new_content.index("<decoder_dir>")


def test_apply_marked_block_rejects_both_or_neither_anchor_given():
    with pytest.raises(ValueError):
        apply_marked_block(REALISTIC_OSSEC_CONF, "x", "y")
    with pytest.raises(ValueError):
        apply_marked_block(REALISTIC_OSSEC_CONF, "x", "y", insert_before="</ruleset>", insert_after="<ruleset>")


def test_apply_marked_block_raises_on_missing_anchor():
    try:
        apply_marked_block("<ossec_config></ossec_config>", "x", "y", "</nonexistent>")
        assert False, "expected ValueError"
    except ValueError as e:
        assert "nonexistent" in str(e)

def test_apply_tag_value_changes_no_to_yes():
    new_content, changed = apply_tag_value(REALISTIC_OSSEC_CONF, "logall", "yes")
    assert changed is True
    assert "<logall>yes</logall>" in new_content
    assert "<logall>no</logall>" not in new_content


def test_apply_tag_value_idempotent_when_already_set():
    first, changed1 = apply_tag_value(REALISTIC_OSSEC_CONF, "logall", "yes")
    second, changed2 = apply_tag_value(first, "logall", "yes")
    assert changed1 is True
    assert changed2 is False
    assert first == second


def test_apply_tag_value_does_not_touch_similarly_named_tags():
    # logall and logall_json must not cross-contaminate each other.
    new_content, _ = apply_tag_value(REALISTIC_OSSEC_CONF, "logall", "yes")
    assert "<logall_json>no</logall_json>" in new_content  # untouched


def test_apply_tag_value_noop_when_tag_absent():
    content = "<ossec_config><global></global></ossec_config>"
    new_content, changed = apply_tag_value(content, "logall", "yes")
    assert changed is False
    assert new_content == content


# ---------------------------------------------------------------------------
# API interaction
# ---------------------------------------------------------------------------

@responses.activate
def test_get_raw_config_returns_plain_text_not_json():
    _add_auth_mock()
    responses.add(responses.GET, f"{BASE}/manager/configuration",
                   body=REALISTIC_OSSEC_CONF, status=200, content_type="application/xml")
    client = _client()

    content = get_raw_config(client)
    assert content == REALISTIC_OSSEC_CONF
    assert responses.calls[-1].request.params.get("raw") == "true"


@responses.activate
def test_update_raw_config_success():
    _add_auth_mock()
    responses.add(responses.PUT, f"{BASE}/manager/configuration",
                   json={"data": {}, "message": "Configuration was successfully updated", "error": 0}, status=200)
    client = _client()

    message = update_raw_config(client, REALISTIC_OSSEC_CONF)
    assert message == "Configuration was successfully updated"
    assert responses.calls[-1].request.headers["Content-Type"] == "application/octet-stream"


@responses.activate
def test_update_raw_config_raises_with_1125_on_invalid_xml():
    _add_auth_mock()
    responses.add(responses.PUT, f"{BASE}/manager/configuration",
                   json={"title": "Bad Request", "detail": "Configuration error", "error": CONFIG_INVALID_ERROR},
                   status=400)
    client = _client()

    try:
        update_raw_config(client, "<not><valid</xml>")
        assert False, "expected WazuhAPIError"
    except WazuhAPIError as e:
        assert e.error_code == CONFIG_INVALID_ERROR


@responses.activate
def test_restart_manager():
    _add_auth_mock()
    responses.add(responses.PUT, f"{BASE}/manager/restart",
                   json={"data": {}, "message": "Restart request sent", "error": 0}, status=200)
    client = _client()

    message = restart_manager(client)
    assert message == "Restart request sent"


@responses.activate
def test_wait_for_api_succeeds_immediately():
    _add_auth_mock()
    assert wait_for_api(BASE, "user", "pass", timeout=5, poll_interval=0.1) is True


def test_wait_for_api_times_out_when_unreachable():
    result = wait_for_api("http://127.0.0.1:1", "user", "pass", timeout=1, poll_interval=0.2)
    assert result is False


def test_wait_for_api_calls_on_tick_while_polling():
    ticks = []
    result = wait_for_api("http://127.0.0.1:1", "user", "pass", timeout=1, poll_interval=0.2,
                           on_tick=lambda elapsed, timeout: ticks.append((elapsed, timeout)))
    assert result is False
    assert len(ticks) >= 3
    assert all(t[1] == 1 for t in ticks)
    assert ticks[-1][0] <= 1.2


@responses.activate
def test_wait_for_api_recovers_after_initial_failures(monkeypatch):
    import wazuh_api.manager_config as mc_mod
    monkeypatch.setattr(mc_mod.time, "sleep", lambda _s: None)

    call_count = {"n": 0}

    def callback(request):
        call_count["n"] += 1
        if call_count["n"] < 3:
            return (503, {}, "")
        return (200, {}, '{"data": {"token": "t"}, "error": 0}')

    responses.add_callback(responses.POST, f"{BASE}/security/user/authenticate", callback=callback)

    result = wait_for_api(BASE, "user", "pass", timeout=5, poll_interval=0.01)
    assert result is True
    assert call_count["n"] == 3