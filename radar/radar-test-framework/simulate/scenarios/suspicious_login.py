#!/usr/bin/env python3
import datetime as dt
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

CONFIG = {
    "timezone_offset": "+01:00",
    "hostname": "edge.vm",
    "log_path": "/var/log/auth.log",
    "user": "test01",
    "sshd_pid": 1169457,
    "fail_port": 1045,
    "success_port": 60850,
    "key_fingerprint_fail": "ED25519 SHA256:A.",
    "key_fingerprint_success": "ED25519 SHA256:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "ip_pool": ["8.8.8.8", "1.0.136.99", "89.31.143.90", "47.91.170.222", "150.95.255.38", "84.32.84.32"],
    "window_seconds": 60,
    "sudo_tee": False,
}

_SYSLOG_RE = re.compile(r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b")
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\b")


def append_line_authlog(line: str, auth_log_path: str, sudo_tee: bool) -> None:
    cmd = ["tee", "-a", auth_log_path]
    if sudo_tee:
        cmd = ["sudo"] + cmd
    try:
        subprocess.run(cmd, input=(line + "\n").encode("utf-8"),
                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
    except subprocess.CalledProcessError as e:
        detail = (e.stderr or b"").decode("utf-8", errors="ignore").strip()
        raise RuntimeError(
            f"Could not write to '{auth_log_path}'"
            + (f": {detail}" if detail else "")
            + ". Check that the directory exists and is writable (or set "
              "sudo_tee=True in CONFIG)."
        ) from e


def _ensure_log_dir(log_path: str, sudo_tee: bool) -> None:
    log_dir = os.path.dirname(log_path)
    if not log_dir:
        return
    try:
        if sudo_tee:
            subprocess.run(["sudo", "mkdir", "-p", log_dir], check=True,
                            capture_output=True, text=True)
        else:
            os.makedirs(log_dir, exist_ok=True)
    except PermissionError as e:
        raise RuntimeError(
            f"Cannot create log directory '{log_dir}': permission denied. "
            f"Either run this script as a user with write access to that "
            f"path, or set sudo_tee=True in CONFIG so writes go through "
            f"'sudo tee'."
        ) from e
    except subprocess.CalledProcessError as e:
        detail = (e.stderr or "").strip() or "no further detail from sudo"
        raise RuntimeError(
            f"Cannot create log directory '{log_dir}' via sudo: {detail}"
        ) from e


def detect_authlog_timestamp_format(
    ts: Optional[dt.datetime],
    tz_offset: str,
    auth_log_path: str,
    max_lines: int = 200,
    micros: int = 227122,
) -> str:
    """Return a formatted timestamp string matching the existing auth log format."""
    ts = ts or dt.datetime.now()
    fmt = "syslog"
    p = Path(auth_log_path)

    if p.exists():
        try:
            with p.open("rb") as f:
                data = f.read(64 * 1024)
            lines_seen = 0
            for raw in data.splitlines():
                if lines_seen >= max_lines:
                    break
                line = raw.decode("utf-8", errors="ignore").strip()
                if not line:
                    continue
                lines_seen += 1
                if _SYSLOG_RE.match(line):
                    fmt = "syslog"
                    break
                if _ISO_RE.match(line):
                    fmt = "iso"
                    break
        except Exception:
            pass

    if fmt == "iso":
        base = ts.replace(microsecond=micros).strftime("%Y-%m-%dT%H:%M:%S.%f")
        return f"{base}{tz_offset}"

    return ts.strftime("%b %d %H:%M:%S")


def main() -> None:
    s = CONFIG

    tz = str(s["timezone_offset"])
    host = str(s["hostname"])

    auth_path = str(s["log_path"])
    sudo_tee = bool(s.get("sudo_tee", False))
    user = str(s["user"])
    sshd_pid = int(s["sshd_pid"])
    fail_port = int(s["fail_port"])
    success_port = int(s["success_port"])
    key_fail = str(s["key_fingerprint_fail"])
    key_ok = str(s["key_fingerprint_success"])
    ips = list(s["ip_pool"])
    window = int(s.get("window_seconds", 60))

    print("[*] Simulating suspicious_login ...")

    _ensure_log_dir(auth_path, sudo_tee)

    base = dt.datetime.now()
    step = max(1, window // max(1, len(ips) + 1))

    for i, ip in enumerate(ips):
        ts = base + dt.timedelta(seconds=i * step)
        ts_str = detect_authlog_timestamp_format(
            ts, tz, auth_path,
        )
        line = (
            f"{ts_str} {host} "
            f"sshd[{sshd_pid}]: Failed password for {user} from {ip} "
            f"port {fail_port} ssh2: {key_fail}"
        )
        append_line_authlog(line, auth_path, sudo_tee)

    ts = base + dt.timedelta(seconds=min(window - 1, len(ips) * step))
    ts_str = detect_authlog_timestamp_format(
        ts, tz, auth_path,
    )
    line = (
        f"{ts_str} {host} "
        f"sshd[{sshd_pid}]: Accepted publickey for {user} from {ips[0]} "
        f"port {success_port} ssh2: {key_ok}"
    )
    append_line_authlog(line, auth_path, sudo_tee)

    print("suspicious_login simulation completed")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        if os.environ.get("RATF_DEBUG"):
            raise
        print(f"ERROR: suspicious_login simulation failed: {e}", file=sys.stderr)
        print("(set RATF_DEBUG=1 for the full traceback)", file=sys.stderr)
        sys.exit(1)