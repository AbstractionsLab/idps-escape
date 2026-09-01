from __future__ import annotations

import os
import secrets
import stat
import tempfile
import threading
from contextlib import contextmanager

_lock = threading.Lock()
_sudo_passwords: dict[str, str] = {}


def new_session_id() -> str:
    return secrets.token_urlsafe(24)


class SudoPasswordMissing(Exception):
    pass


def has_sudo_password(session_id: str) -> bool:
    with _lock:
        return bool(session_id and _sudo_passwords.get(session_id))


def set_sudo_password(session_id: str, password: str) -> None:
    if not session_id:
        raise ValueError("session_id required")
    with _lock:
        _sudo_passwords[session_id] = password


def clear_sudo_password(session_id: str) -> None:
    with _lock:
        _sudo_passwords.pop(session_id, None)


def _get_sudo_password(session_id: str) -> str:
    with _lock:
        pw = _sudo_passwords.get(session_id)
    if pw is None:
        raise SudoPasswordMissing("sudo password not set for this session")
    return pw


@contextmanager
def sudo_askpass_env(session_id: str, base_env: dict):
    pw = _get_sudo_password(session_id)
    helper_path = pw_path = None
    try:
        fd, pw_path = tempfile.mkstemp(prefix="radar_sudopw_", suffix=".txt")
        with os.fdopen(fd, "w") as f:
            f.write(pw)
        os.chmod(pw_path, stat.S_IRUSR | stat.S_IWUSR)

        fd2, helper_path = tempfile.mkstemp(prefix="radar_sudoaskpass_", suffix=".sh")
        with os.fdopen(fd2, "w") as f:
            f.write(f'#!/bin/sh\ncat "{pw_path}"\n')
        os.chmod(helper_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

        yield {**base_env, "SUDO_ASKPASS": helper_path}
    finally:
        for f in filter(None, [helper_path, pw_path]):
            try:
                os.unlink(f)
            except OSError:
                pass