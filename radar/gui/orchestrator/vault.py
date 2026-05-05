from __future__ import annotations

import os
import secrets
import stat
import subprocess
import sys
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path

_lock = threading.Lock()
_passwords: dict[str, str] = {}
_ssh_passphrases: dict[str, str] = {}


class VaultPasswordMissing(Exception):
    pass


class SSHPassphraseMissing(Exception):
    pass


def new_session_id() -> str:
    return secrets.token_urlsafe(24)


def has_password(session_id: str) -> bool:
    with _lock:
        return bool(session_id and _passwords.get(session_id))


def set_password(session_id: str, password: str) -> None:
    if not session_id or not password:
        raise ValueError("session_id and password required")
    with _lock:
        _passwords[session_id] = password


def clear_password(session_id: str) -> None:
    with _lock:
        _passwords.pop(session_id, None)


def _get_password(session_id: str) -> str:
    with _lock:
        pw = _passwords.get(session_id)
    if not pw:
        raise VaultPasswordMissing("Vault password not set for this session")
    return pw


@contextmanager
def password_file(session_id: str):
    pw = _get_password(session_id)
    fd, path = tempfile.mkstemp(prefix="radar_vault_", suffix=".pw")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(pw)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        yield path
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def verify_password(session_id: str, encrypted_file: Path) -> bool:
    if not encrypted_file.exists():
        return True
    head = encrypted_file.read_text(errors="ignore")[:32]
    if not head.startswith("$ANSIBLE_VAULT"):
        return True
    try:
        with password_file(session_id) as pf:
            r = subprocess.run(
                ["ansible-vault", "view", "--vault-password-file", pf, str(encrypted_file)],
                capture_output=True, text=True, timeout=15,
            )
        return r.returncode == 0
    except VaultPasswordMissing:
        return False


def encrypt_host_vars(session_id: str, target: Path, become_password: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    body = f"ansible_become_password: {_yaml_escape(become_password)}\n"
    target.write_text(body)
    os.chmod(target, 0o600)
    with password_file(session_id) as pf:
        r = subprocess.run(
            ["ansible-vault", "encrypt", "--vault-password-file", pf, str(target)],
            capture_output=True, text=True, timeout=20,
        )
    if r.returncode != 0:
        try:
            target.unlink()
        except OSError:
            pass
        raise RuntimeError(f"ansible-vault encrypt failed: {r.stderr.strip() or r.stdout.strip()}")
    os.chmod(target, 0o600)


def _yaml_escape(s: str) -> str:
    if any(c in s for c in ":#'\"\n\\") or s.strip() != s or s == "":
        escaped = s.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return s


def has_ssh_passphrase(session_id: str) -> bool:
    with _lock:
        return bool(session_id and _ssh_passphrases.get(session_id))


def set_ssh_passphrase(session_id: str, passphrase: str) -> None:
    if not session_id:
        raise ValueError("session_id required")
    with _lock:
        _ssh_passphrases[session_id] = passphrase


def clear_ssh_passphrase(session_id: str) -> None:
    with _lock:
        _ssh_passphrases.pop(session_id, None)


def get_ssh_passphrase(session_id: str) -> str:
    with _lock:
        pp = _ssh_passphrases.get(session_id)
    if pp is None:
        raise SSHPassphraseMissing("SSH key passphrase not set for this session")
    return pp


def _parse_agent_output(output: str) -> tuple[str, str]:
    sock = ""
    pid = ""
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("SSH_AUTH_SOCK="):
            val = line[len("SSH_AUTH_SOCK="):]
            sock = val.split(";")[0].strip()
        elif line.startswith("SSH_AGENT_PID="):
            val = line[len("SSH_AGENT_PID="):]
            pid = val.split(";")[0].strip()
    return sock, pid


@contextmanager
def ssh_askpass_env(session_id: str | None, base_env: dict):
    if not session_id or not has_ssh_passphrase(session_id):
        env_no_agent = {k: v for k, v in base_env.items()
                        if k not in ("SSH_AUTH_SOCK", "SSH_AGENT_PID")}
        env_no_agent["GIT_SSH_COMMAND"] = "ssh -o BatchMode=yes"
        env_no_agent["ANSIBLE_SSH_ARGS"] = "-o BatchMode=yes -o StrictHostKeyChecking=no"
        yield env_no_agent
        return

    passphrase = get_ssh_passphrase(session_id)
    ssh_key = base_env.get("ANSIBLE_PRIVATE_KEY_FILE", "")

    agent_pid = ""
    helper_path = None
    pp_path = None

    try:
        fd, helper_path = tempfile.mkstemp(prefix="radar_askpass_", suffix=".sh")
        fd2, pp_path = tempfile.mkstemp(prefix="radar_sshpp_", suffix=".txt")
        with os.fdopen(fd2, "w") as f:
            f.write(passphrase)
        os.chmod(pp_path, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w") as f:
            f.write(f'#!/bin/sh\ncat "{pp_path}"\n')
        os.chmod(helper_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

        agent_result = subprocess.run(
            ["ssh-agent", "-s"], capture_output=True, text=True, timeout=10,
        )
        if agent_result.returncode != 0:
            print(f"[vault] ssh-agent failed rc={agent_result.returncode} stderr={agent_result.stderr!r}", file=sys.stderr)
            yield base_env
            return

        agent_sock, agent_pid = _parse_agent_output(agent_result.stdout)

        if not agent_sock:
            print(f"[vault] could not parse SSH_AUTH_SOCK from agent output: {agent_result.stdout!r}", file=sys.stderr)
            yield base_env
            return

        if not ssh_key:
            ssh_key = os.path.expanduser("~/.ssh/id_ed25519")
            if not os.path.exists(ssh_key):
                ssh_key = ""

        agent_env = {
            **base_env,
            "SSH_AUTH_SOCK": agent_sock,
            "SSH_AGENT_PID": agent_pid,
            "SSH_ASKPASS": helper_path,
            "SSH_ASKPASS_REQUIRE": "force",
            "DISPLAY": "none",
        }

        add_cmd = ["ssh-add"] + ([ssh_key] if ssh_key else [])
        add_result = subprocess.run(
            add_cmd, env=agent_env,
            capture_output=True, text=True, timeout=15,
            stdin=subprocess.DEVNULL,
        )
        print(f"[vault] ssh-add rc={add_result.returncode} stdout={add_result.stdout.strip()!r} stderr={add_result.stderr.strip()!r}", file=sys.stderr)

        if add_result.returncode != 0:
            import shutil
            if shutil.which("sshpass") and ssh_key:
                sshpass_result = subprocess.run(
                    ["sshpass", "-p", passphrase, "ssh-add", ssh_key],
                    env=agent_env, capture_output=True, text=True, timeout=15,
                    stdin=subprocess.DEVNULL,
                )
                print(f"[vault] sshpass fallback rc={sshpass_result.returncode}", file=sys.stderr)

        final_env = {k: v for k, v in base_env.items() if k not in ("SSH_AUTH_SOCK", "SSH_AGENT_PID")}
        final_env["SSH_AUTH_SOCK"] = agent_sock
        final_env["SSH_AGENT_PID"] = agent_pid
        if ssh_key:
            final_env["ANSIBLE_PRIVATE_KEY_FILE"] = ssh_key
        final_env.setdefault("ANSIBLE_SSH_ARGS",
            "-o StrictHostKeyChecking=no -o BatchMode=yes -o PasswordAuthentication=no")
        yield final_env

    except FileNotFoundError as e:
        print(f"[vault] ssh-agent not found: {e}", file=sys.stderr)
        yield base_env
    finally:
        if agent_pid:
            try:
                subprocess.run(
                    ["ssh-agent", "-k"],
                    env={"SSH_AGENT_PID": agent_pid},
                    capture_output=True, timeout=5,
                )
            except Exception:
                pass
        for f in filter(None, [helper_path, pp_path]):
            try:
                os.unlink(f)
            except OSError:
                pass