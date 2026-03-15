#!/usr/bin/env python3
import datetime as dt

from common import load_config, append_line_authlog, detect_authlog_timestamp_format


def main() -> None:
    cfg = load_config()

    common = cfg["common"]
    s = cfg["suspicious_login"]

    tz = str(common["timezone_offset"])
    host = str(common["hostname"])

    auth_path = str(s["log_path"])
    sudo_tee = bool(s.get("sudo_tee", True))

    user = str(s["user"])
    sshd_pid = int(s["sshd_pid"])
    fail_port = int(s["fail_port"])
    success_port = int(s["success_port"])
    key_fail = str(s["key_fingerprint_fail"])
    key_ok = str(s["key_fingerprint_success"])
    ips = list(s["ip_pool"])
    window = int(s.get("window_seconds", 60))

    print("[*] Simulating suspicious_login ...")

    base = dt.datetime.now()
    step = max(1, window // max(1, len(ips) + 1))

    for i, ip in enumerate(ips):
        ts = base + dt.timedelta(seconds=i * step)
        line = (
            f"{detect_authlog_timestamp_format(ts, tz, auth_path)} {host} "
            f"sshd[{sshd_pid}]: Failed password for {user} from {ip} port {fail_port} ssh2: {key_fail}"
        )
        append_line_authlog(line, auth_path, sudo_tee)

    ts = base + dt.timedelta(seconds=min(window - 1, len(ips) * step))
    line = (
        f"{detect_authlog_timestamp_format(ts, tz, auth_path)} {host} "
        f"sshd[{sshd_pid}]: Accepted publickey for {user} from {ips[0]} port {success_port} ssh2: {key_ok}"
    )
    append_line_authlog(line, auth_path, sudo_tee)

    print("suspicious_login simulation completed")


if __name__ == "__main__":
    main()
