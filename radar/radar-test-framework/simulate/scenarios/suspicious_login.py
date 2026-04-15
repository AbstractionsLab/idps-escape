#!/usr/bin/env python3
import datetime as dt

from common import (
    load_config,
    get_scenario_simulate,
    append_line_authlog,
    detect_authlog_timestamp_format,
)


def main() -> None:
    cfg = load_config()
    s = get_scenario_simulate(cfg, "suspicious_login")

    tz = str(s["timezone_offset"])
    host = str(s["hostname"])

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
    main()