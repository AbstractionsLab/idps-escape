import pytest
import responses

from wazuh_api.client import WazuhAPIClient, WazuhAPIError
from wazuh_api.ruleset import (
    DECODER_NOT_FOUND,
    LIST_NOT_FOUND,
    RULE_NOT_FOUND,
    upload_decoder_file,
    upload_list_file,
    upload_rule_file,
)

BASE = "https://manager:55000"


def _add_auth_mock():
    responses.add(responses.POST, f"{BASE}/security/user/authenticate",
                   json={"data": {"token": "fake-jwt-token"}, "error": 0}, status=200)


def _client():
    return WazuhAPIClient(BASE, "user", "pass")


@responses.activate
def test_upload_decoder_file_uploads_when_not_found():
    _add_auth_mock()
    responses.add(responses.GET, f"{BASE}/decoders/files/0310-ssh.xml",
                   json={"title": "Not Found", "error": DECODER_NOT_FOUND}, status=400)
    responses.add(responses.PUT, f"{BASE}/decoders/files/0310-ssh.xml",
                   json={"message": "Decoder was successfully uploaded", "error": 0}, status=200)
    client = _client()

    changed = upload_decoder_file(client, "0310-ssh.xml", "<decoder name=\"x\"></decoder>")
    assert changed is True
    put_calls = [c for c in responses.calls if c.request.method == "PUT"]
    assert len(put_calls) == 1
    assert put_calls[0].request.params.get("overwrite") == "true"
    assert put_calls[0].request.headers["Content-Type"] == "application/octet-stream"


@responses.activate
def test_upload_decoder_file_noop_when_content_matches():
    _add_auth_mock()
    content = "<decoder name=\"x\"></decoder>"
    responses.add(responses.GET, f"{BASE}/decoders/files/0310-ssh.xml", body=content, status=200)
    client = _client()

    changed = upload_decoder_file(client, "0310-ssh.xml", content)
    assert changed is False
    put_calls = [c for c in responses.calls if c.request.method == "PUT"]
    assert put_calls == []  # confirm no upload was attempted at all


@responses.activate
def test_upload_decoder_file_uploads_when_content_differs():
    _add_auth_mock()
    responses.add(responses.GET, f"{BASE}/decoders/files/0310-ssh.xml",
                   body="<decoder name=\"old\"></decoder>", status=200)
    responses.add(responses.PUT, f"{BASE}/decoders/files/0310-ssh.xml",
                   json={"message": "updated", "error": 0}, status=200)
    client = _client()

    changed = upload_decoder_file(client, "0310-ssh.xml", "<decoder name=\"new\"></decoder>")
    assert changed is True


@responses.activate
def test_upload_decoder_file_reraises_non_not_found_errors():
    _add_auth_mock()
    responses.add(responses.GET, f"{BASE}/decoders/files/0310-ssh.xml",
                   json={"title": "Forbidden", "error": 4000}, status=403)
    client = _client()

    with pytest.raises(WazuhAPIError) as exc_info:
        upload_decoder_file(client, "0310-ssh.xml", "<decoder></decoder>")
    assert exc_info.value.error_code == 4000
    # Confirm we didn't silently proceed to PUT after swallowing this error.
    put_calls = [c for c in responses.calls if c.request.method == "PUT"]
    assert put_calls == []


@responses.activate
def test_upload_rule_file_uploads_when_not_found():
    _add_auth_mock()
    responses.add(responses.GET, f"{BASE}/rules/files/a2-suspicious-login.xml",
                   json={"title": "Not Found", "error": RULE_NOT_FOUND}, status=400)
    responses.add(responses.PUT, f"{BASE}/rules/files/a2-suspicious-login.xml",
                   json={"message": "Rule was successfully uploaded", "error": 0}, status=200)
    client = _client()

    changed = upload_rule_file(client, "a2-suspicious-login.xml", "<group name=\"x\"></group>")
    assert changed is True


@responses.activate
def test_upload_rule_file_noop_when_content_matches():
    _add_auth_mock()
    content = "<group name=\"x\"></group>"
    responses.add(responses.GET, f"{BASE}/rules/files/a2-suspicious-login.xml", body=content, status=200)
    client = _client()

    changed = upload_rule_file(client, "a2-suspicious-login.xml", content)
    assert changed is False


@responses.activate
def test_upload_list_file_uploads_when_not_found():
    _add_auth_mock()
    responses.add(responses.GET, f"{BASE}/lists/files/whitelist_countries",
                   json={"title": "Not Found", "error": LIST_NOT_FOUND}, status=400)
    responses.add(responses.PUT, f"{BASE}/lists/files/whitelist_countries",
                   json={"message": "CDB list file uploaded successfully", "error": 0}, status=200)
    client = _client()

    changed = upload_list_file(client, "whitelist_countries", "LU:\nDE:\n")
    assert changed is True


@responses.activate
def test_upload_list_file_noop_when_content_matches():
    _add_auth_mock()
    content = "LU:\nDE:\n"
    responses.add(responses.GET, f"{BASE}/lists/files/whitelist_countries", body=content, status=200)
    client = _client()

    changed = upload_list_file(client, "whitelist_countries", content)
    assert changed is False