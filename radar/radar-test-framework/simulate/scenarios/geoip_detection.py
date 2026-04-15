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
    g = get_scenario_simulate(cfg, "geoip_detection")

    tz = str(g["timezone_offset"])
    host = str(g["hostname"])

    auth_path = str(g["log_path"])
    sudo_tee = bool(g.get("sudo_tee", True))
    user = str(g["user"])
    sshd_pid = int(g["sshd_pid"])
    success_port = int(g["success_port"])
    ip = str(g["ip"])
    key_ok = str(g["key_fingerprint_success"])

    print("[*] Simulating geoip_detection ...")

    ts = dt.datetime.now()
    ts_str = detect_authlog_timestamp_format(
        ts, tz, auth_path,
    )
    line = (
        f"{ts_str} {host} "
        f"sshd[{sshd_pid}]: Accepted publickey for {user} from {ip} "
        f"port {success_port} ssh2: {key_ok}"
    )
    append_line_authlog(line, auth_path, sudo_tee)

    print("geoip_detection simulation completed")


if __name__ == "__main__":
    main()