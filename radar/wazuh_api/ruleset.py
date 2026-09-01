"""
Decoder/rule/CDB-list file management via the Wazuh API.
"""
from __future__ import annotations

from typing import Optional

from .client import WazuhAPIClient, WazuhAPIError

RULE_NOT_FOUND = 1415
DECODER_NOT_FOUND = 1503
LIST_NOT_FOUND = 1802


def _get_existing_content(client: WazuhAPIClient, path: str, not_found_code: int) -> Optional[str]:
    try:
        resp = client.get(path, params={"raw": "true"})
        return resp.text
    except WazuhAPIError as e:
        if e.error_code == not_found_code:
            return None
        raise


def upload_decoder_file(client: WazuhAPIClient, filename: str, content: str) -> bool:
    """Push a decoder file if its content differs from what's already on the manager. Returns whether it changed."""
    existing = _get_existing_content(client, f"/decoders/files/{filename}", DECODER_NOT_FOUND)
    if existing == content:
        return False
    client.put(
        f"/decoders/files/{filename}", params={"overwrite": "true"},
        data=content.encode("utf-8"), headers={"Content-Type": "application/octet-stream"},
    )
    return True


def upload_rule_file(client: WazuhAPIClient, filename: str, content: str) -> bool:
    """Push a rule file if its content differs from what's already on the manager. Returns whether it changed."""
    existing = _get_existing_content(client, f"/rules/files/{filename}", RULE_NOT_FOUND)
    if existing == content:
        return False
    client.put(
        f"/rules/files/{filename}", params={"overwrite": "true"},
        data=content.encode("utf-8"), headers={"Content-Type": "application/octet-stream"},
    )
    return True


def upload_list_file(client: WazuhAPIClient, filename: str, content: str) -> bool:
    """Push a CDB list file if its content differs from what's already on the manager. Returns whether it changed."""
    existing = _get_existing_content(client, f"/lists/files/{filename}", LIST_NOT_FOUND)
    if existing == content:
        return False
    client.put(
        f"/lists/files/{filename}", params={"overwrite": "true"},
        data=content.encode("utf-8"), headers={"Content-Type": "application/octet-stream"},
    )
    return True


def _delete_ruleset_file(client: WazuhAPIClient, path: str, filename: str, not_found_code: int, kind_label: str) -> bool:
    try:
        resp = client.delete(path)
    except WazuhAPIError as e:
        if e.error_code == not_found_code:
            return False
        raise
    try:
        data = resp.json().get("data", {})
    except ValueError:
        return True
    if data.get("total_affected_items", 0) >= 1:
        return True
    failed = data.get("failed_items", [])
    if failed:
        err = failed[0].get("error", {})
        code = err.get("code")
        msg = err.get("message", "unknown reason")
        if code == not_found_code or "does not exist" in msg.lower() or "not found" in msg.lower():
            return False
        raise RuntimeError(f"could not delete {kind_label} '{filename}': {msg}")
    return False


def delete_decoder_file(client: WazuhAPIClient, filename: str) -> bool:
    """Undo of upload_decoder_file. Idempotent -- deleting an already-absent
    file returns False (nothing to do) rather than raising."""
    return _delete_ruleset_file(client, f"/decoders/files/{filename}", filename, DECODER_NOT_FOUND, "decoder")


def delete_rule_file(client: WazuhAPIClient, filename: str) -> bool:
    """Undo of upload_rule_file. Idempotent -- deleting an already-absent
    file returns False (nothing to do) rather than raising."""
    return _delete_ruleset_file(client, f"/rules/files/{filename}", filename, RULE_NOT_FOUND, "rule")


def delete_list_file(client: WazuhAPIClient, filename: str) -> bool:
    """Undo of upload_list_file. Idempotent -- deleting an already-absent
    file returns False (nothing to do) rather than raising."""
    return _delete_ruleset_file(client, f"/lists/files/{filename}", filename, LIST_NOT_FOUND, "list")