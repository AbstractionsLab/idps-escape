from __future__ import annotations

import os
import secrets
import stat
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager

_lock = threading.Lock()
_sudo_passwords: dict[str, tuple[str, float]] = {}

IDLE_SECONDS = max(60, int(os.environ.get("RADAR_SUDO_IDLE_MINUTES", "15")) * 60)


def new_session_id() -> str:
    return secrets.token_urlsafe(24)


class SudoPasswordMissing(Exception):
    pass


def _expire_locked(now: float) -> None:
    for sid in [k for k, (_, t) in _sudo_passwords.items() if now - t > IDLE_SECONDS]:
        _sudo_passwords.pop(sid, None)


def has_sudo_password(session_id: str) -> bool:
    with _lock:
        _expire_locked(time.monotonic())
        return bool(session_id and session_id in _sudo_passwords)


def verify_sudo_password(password: str) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["sudo", "-S", "-k", "-p", "", "--", "true"],
            input=password + "\n", capture_output=True, text=True, timeout=15,
            env={**os.environ, "LC_ALL": "C"},
        )
    except FileNotFoundError:
        return False, "sudo is not installed on the GUI host"
    except subprocess.TimeoutExpired:
        return False, "sudo did not answer in time"
    if proc.returncode == 0:
        return True, ""
    return False, "sudo rejected this password"


def set_sudo_password(session_id: str, password: str) -> None:
    if not session_id:
        raise ValueError("session_id required")
    with _lock:
        _sudo_passwords[session_id] = (password, time.monotonic())


def clear_sudo_password(session_id: str) -> None:
    with _lock:
        _sudo_passwords.pop(session_id, None)


def _get_sudo_password(session_id: str) -> str:
    with _lock:
        now = time.monotonic()
        _expire_locked(now)
        entry = _sudo_passwords.get(session_id)
        if entry is None:
            raise SudoPasswordMissing("sudo password not set for this session")
        _sudo_passwords[session_id] = (entry[0], now)
    return entry[0]


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