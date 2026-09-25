#!/usr/bin/env python3
"""Traffic generator for suspicious_login. Emits SSH auth log lines.

Cases, and what each one should produce:

  burst          6 failed logins in 60s, same user,
                 same country                          -> 210013 (level 8)
  travel         3 successful logins,
                 Poland->USA->Australia                 -> 210021 (level 10)
  failed_travel  3 failed logins,
                 France->USA->Australia                 -> 210020 (level 10)
  composite      baseline login, burst, then a
                 geo-impossible success within 300s     -> 210022 (level 12)
  benign         two successful logins, same
                 region, 1h apart                       -> nothing
"""
import datetime as dt
import os
import subprocess
import sys
import time

CONFIG = {
    "log_path": "/var/log/auth.log",
    "hostname": "edge.vm",
    "sshd_pid": 1169457,
    "fail_port": 1045,
    "success_port": 60850,
    "key_fail": "ED25519 SHA256:A.",
    "key_success": "ED25519 SHA256:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "fail_threshold": 5,
    "fail_margin": 1,
    "burst_window_seconds": 60,
    "case_gap_seconds": 2,
    "sudo_tee": False,
}

USERS = {
    "burst": "test01",
    "travel": "test02",
    "composite": "test03",
    "benign": "test04",
    "failed_travel": "test05",
}

BURST_IPS = ["185.220.101.1", "185.220.101.2", "185.220.101.3",
             "185.220.101.4", "185.220.101.5", "185.220.101.6"]
TRAVEL_IPS = [
    ("Poland", "194.204.159.1"),
    ("USA", "4.2.2.2"),
    ("Australia", "203.2.75.1"),
]
FAILED_TRAVEL_IPS = [
    ("France", "212.27.48.20"),
    ("USA", "4.2.2.3"),
    ("Australia", "203.2.75.30"),
]
COMPOSITE_BASELINE_IP = "212.27.48.10"
COMPOSITE_BURST_IPS = ["45.155.204.10", "45.155.204.11", "45.155.204.12",
                       "45.155.204.13", "45.155.204.14", "45.155.204.15"]
COMPOSITE_SUCCESS_IP = "203.2.75.1"
BENIGN_IPS = ["212.27.48.10", "212.27.48.11"]


def _ensure_log_dir(log_path, sudo_tee):
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
            f"Cannot create log directory '{log_dir}': permission denied. Either run "
            f"as a user with write access, or set sudo_tee=True in CONFIG."
        ) from e
    except subprocess.CalledProcessError as e:
        detail = (e.stderr or "").strip() or "no further detail from sudo"
        raise RuntimeError(f"Cannot create log directory '{log_dir}' via sudo: {detail}") from e


def _append(line, log_path, sudo_tee):
    cmd = ["tee", "-a", log_path]
    if sudo_tee:
        cmd = ["sudo"] + cmd
    try:
        subprocess.run(cmd, input=(line + "\n").encode("utf-8"),
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
    except subprocess.CalledProcessError as e:
        detail = (e.stderr or b"").decode("utf-8", errors="ignore").strip()
        raise RuntimeError(
            f"Could not write to '{log_path}'" + (f": {detail}" if detail else "")
            + ". Check the directory exists and is writable (or set sudo_tee=True)."
        ) from e


def _line(user, srcip, outcome, ts, cfg):
    ts_str = ts.strftime("%b %d %H:%M:%S")
    if outcome == "fail":
        return (
            f"{ts_str} {cfg['hostname']} sshd[{cfg['sshd_pid']}]: Failed password for "
            f"{user} from {srcip} port {cfg['fail_port']} ssh2: {cfg['key_fail']}"
        )
    return (
        f"{ts_str} {cfg['hostname']} sshd[{cfg['sshd_pid']}]: Accepted publickey for "
        f"{user} from {srcip} port {cfg['success_port']} ssh2: {cfg['key_success']}"
    )


class Emitter:
    def __init__(self, log_path, sudo_tee, cfg):
        self.log_path = log_path
        self.sudo_tee = sudo_tee
        self.cfg = cfg

    def send(self, user, srcip, outcome, ts):
        _append(_line(user, srcip, outcome, ts, self.cfg), self.log_path, self.sudo_tee)


def case_burst(em, cfg):
    user = USERS["burst"]
    n = cfg["fail_threshold"] + cfg["fail_margin"]
    window = cfg["burst_window_seconds"]
    print(f"burst: {n} failed logins in {window}s, same user -> expect 210013 at level 8")
    step = max(1, window // (n + 1))
    base = dt.datetime.now()
    for i, ip in enumerate(BURST_IPS[:n]):
        em.send(user, ip, "fail", base + dt.timedelta(seconds=i * step))
    em.send(user, BURST_IPS[0], "success", base + dt.timedelta(seconds=n * step))


def case_travel(em, cfg):
    user = USERS["travel"]
    print("travel: 3 successful logins, Poland -> USA -> Australia -> expect 210021 at level 10")
    base = dt.datetime.now()
    for i, (country, ip) in enumerate(TRAVEL_IPS):
        em.send(user, ip, "success", base + dt.timedelta(seconds=i * 60))
        print(f"    hop: {country} ({ip})")


def case_failed_travel(em, cfg):
    user = USERS["failed_travel"]
    print("failed_travel: 3 failed logins, France -> USA -> Australia -> expect 210020 at level 10")
    base = dt.datetime.now()
    for i, (country, ip) in enumerate(FAILED_TRAVEL_IPS):
        em.send(user, ip, "fail", base + dt.timedelta(seconds=i * 60))
        print(f"    hop: {country} ({ip})")


def case_composite(em, cfg):
    user = USERS["composite"]
    n = cfg["fail_threshold"] + cfg["fail_margin"]
    window = cfg["burst_window_seconds"]
    print("composite: baseline login, failed burst, then a geo-impossible success within 300s -> expect 210022 at level 12")
    step = max(1, window // (n + 1))
    base = dt.datetime.now()
    em.send(user, COMPOSITE_BASELINE_IP, "success", base)
    burst_start = base + dt.timedelta(seconds=5)
    for i, ip in enumerate(COMPOSITE_BURST_IPS[:n]):
        em.send(user, ip, "fail", burst_start + dt.timedelta(seconds=i * step))
    success_ts = burst_start + dt.timedelta(seconds=n * step + 30)
    em.send(user, COMPOSITE_SUCCESS_IP, "success", success_ts)


def case_benign(em, cfg):
    user = USERS["benign"]
    print("benign: two successful logins, same region, 1h apart -> expect nothing")
    base = dt.datetime.now()
    em.send(user, BENIGN_IPS[0], "success", base)
    em.send(user, BENIGN_IPS[1], "success", base + dt.timedelta(hours=1))


CASES = {
    "burst": case_burst,
    "travel": case_travel,
    "failed_travel": case_failed_travel,
    "composite": case_composite,
    "benign": case_benign,
}

EXPECT = {
    "burst": {
        "src_ips": BURST_IPS,
        "present": [{"rule": "210013", "level": 8}],
        "absent": ["210022"],
    },
    "travel": {
        "src_ips": [ip for _, ip in TRAVEL_IPS],
        "present": [{"rule": "210021", "level": 10}],
        "absent": ["210020", "210022"],
    },
    "failed_travel": {
        "src_ips": [ip for _, ip in FAILED_TRAVEL_IPS],
        "present": [{"rule": "210020", "level": 10}],
        "absent": ["210021", "210022"],
    },
    "composite": {
        "src_ips": [COMPOSITE_BASELINE_IP, COMPOSITE_SUCCESS_IP] + COMPOSITE_BURST_IPS,
        "present": [{"rule": "210022", "level": 12}],
        "absent": ["210020"],
    },
    "benign": {
        "src_ips": BENIGN_IPS,
        "present": [],
        "absent": ["210013", "210020", "210021", "210022"],
    },
}


def _fmt_rule_list(rule_ids):
    return ", ".join(rule_ids) if rule_ids else "(none)"


def _fmt_present(present):
    if not present:
        return "(none)"
    return ", ".join(f"{p['rule']} (level {p['level']})" for p in present)


def _print_case_hint(name, started_at, ended_at):
    expect = EXPECT[name]
    ips = " OR ".join(f'"{ip}"' for ip in expect["src_ips"])
    print(f"    Check now: data.srcip:({ips})")
    print(f"    Time window: {started_at} .. {ended_at}")
    print(f"    Expect present: {_fmt_present(expect['present'])}")
    print(f"    Expect absent:  {_fmt_rule_list(expect['absent'])}")


def _confirm_verified(name):
    while True:
        resp = input(f"    Did you verify {name}? [y]es / [n]o / [q]uit: ").strip().lower()
        if resp in ("y", "yes"):
            return True
        if resp in ("n", "no"):
            return False
        if resp in ("q", "quit"):
            return None


def _print_summary(rows, interactive):
    print()
    print("=" * 78)
    print("Summary - one row per case, for checking against the dashboard afterwards")
    print("=" * 78)
    verified_count = failed_count = not_verified_count = 0
    for name, started_at, ended_at, verified in rows:
        expect = EXPECT[name]
        print()
        print(f"[{name}]")
        if interactive:
            if verified is True:
                status = "SUCCESSFULLY VERIFIED"
                verified_count += 1
            elif verified is False:
                status = "FAILED VERIFICATION"
                failed_count += 1
            else:
                status = "NOT VERIFIED"
                not_verified_count += 1
            print(f"  status:      {status}")
        print(f"  src_ip:      {', '.join(expect['src_ips'])}")
        print(f"  window:      {started_at} .. {ended_at}")
        print(f"  present:     {_fmt_present(expect['present'])}")
        print(f"  absent:      {_fmt_rule_list(expect['absent'])}")
    if interactive:
        print()
        print(f"{verified_count} verified, {failed_count} failed, {not_verified_count} not verified")


def main():
    cfg = CONFIG
    log_path = str(cfg["log_path"])
    sudo_tee = bool(cfg.get("sudo_tee", False))

    args = sys.argv[1:]
    interactive = True
    for flag in ("-i", "-interactive"):
        if flag in args:
            args = [a for a in args if a != flag]
    for flag in ("-b", "-batch", "-non-interactive"):
        if flag in args:
            interactive = False
            args = [a for a in args if a != flag]

    requested = args or list(CASES)
    unknown = [c for c in requested if c not in CASES]
    if unknown:
        print(f"ERROR: unknown case(s): {', '.join(unknown)}", file=sys.stderr)
        print(f"Available: {', '.join(CASES)}", file=sys.stderr)
        sys.exit(2)

    print(f"Simulating suspicious_login: {log_path}")
    if interactive:
        print("Interactive mode: after each case, confirm you checked the dashboard before continuing.")
    _ensure_log_dir(log_path, sudo_tee)
    em = Emitter(log_path, sudo_tee, cfg)

    rows = []
    aborted = False
    for i, name in enumerate(requested):
        started_at = dt.datetime.now().astimezone().isoformat()
        CASES[name](em, cfg)
        ended_at = dt.datetime.now().astimezone().isoformat()
        _print_case_hint(name, started_at, ended_at)

        verified = _confirm_verified(name) if interactive else None
        rows.append((name, started_at, ended_at, verified))
        if interactive and verified is None:
            aborted = True
            print("Quitting - remaining cases were not run.")
            break

        is_last = i == len(requested) - 1
        if not interactive and len(requested) > 1 and not is_last:
            time.sleep(cfg["case_gap_seconds"])

    _print_summary(rows, interactive)
    print()
    if aborted:
        print("suspicious_login simulation stopped early (quit during verification)")
    else:
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