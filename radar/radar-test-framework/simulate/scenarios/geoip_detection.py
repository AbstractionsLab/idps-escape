#!/usr/bin/env python3
"""Traffic generator for geoip_detection. Emits SSH auth log and web access
log lines.

Cases, and what each one should produce:

  ssh_whitelisted       SSH login, whitelisted country     -> nothing
  ssh_non_whitelisted   SSH login, non-whitelisted country -> 100900 (level 10)
  ssh_private           SSH login, private source IP       -> nothing
  web_ip                web request, ip format, non-wl     -> 100902 (level 10)
  web_ip_whitelisted    web request, ip format, whitelisted -> nothing
  web_private           web request, private source IP     -> nothing
  web_domain            web request, domain+ip format      -> 100902 (level 10)
  web_domainport        web request, host:port+ip format   -> 100902 (level 10)
  web_ip_ip             web request, ip-vhost+ip format    -> 100902 (level 10)
"""
import datetime as dt
import os
import subprocess
import sys
import time

CONFIG = {
    "auth_log_path": "/var/log/auth.log",
    "web_log_path": "/var/log/apache2/access.log",
    "hostname": "edge.vm",
    "sshd_pid": 1169457,
    "ssh_user": "test01",
    "ssh_port": 60850,
    "ssh_key": "ED25519 SHA256:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "http_method": "GET",
    "http_path": "/index.html",
    "http_status": 404,
    "http_bytes": 4096,
    "case_gap_seconds": 2,
    "sudo_tee": False,
}

SOURCES = {
    "ssh_whitelisted": "212.27.48.10",
    "ssh_non_whitelisted": "8.8.8.8",
    "ssh_private": "192.168.1.10",
    "web_ip": "200.221.2.45",
    "web_ip_whitelisted": "194.25.2.129",
    "web_private": "192.168.1.20",
    "web_domain": "200.221.2.46",
    "web_domainport": "200.221.2.47",
    "web_ip_ip": "200.221.2.48",
}


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


def _ssh_line(srcip, cfg):
    ts = dt.datetime.now().strftime("%b %d %H:%M:%S")
    return (
        f"{ts} {cfg['hostname']} sshd[{cfg['sshd_pid']}]: Accepted publickey for "
        f"{cfg['ssh_user']} from {srcip} port {cfg['ssh_port']} ssh2: {cfg['ssh_key']}"
    )


def _web_line(srcip, fmt, cfg, domain=None, port=None, vhost_ip=None):
    ts = dt.datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
    request = f'{cfg["http_method"]} {cfg["http_path"]} HTTP/1.1'
    tail = f'"{request}" {cfg["http_status"]} {cfg["http_bytes"]} "-" "curl/8.5.0"'

    if fmt == "ip":
        return f"{srcip} - - [{ts}] {tail}"
    if fmt == "domain":
        return f"{domain} {srcip} - - [{ts}] {tail}"
    if fmt == "domainport":
        return f"{domain}:{port} {srcip} - - [{ts}] {tail}"
    if fmt == "ip_ip":
        return f"{vhost_ip} {srcip} - - [{ts}] {tail}"
    raise ValueError(f"Unknown web access log format: {fmt!r}")


class Emitter:
    def __init__(self, auth_log_path, web_log_path, sudo_tee, cfg):
        self.auth_log_path = auth_log_path
        self.web_log_path = web_log_path
        self.sudo_tee = sudo_tee
        self.cfg = cfg

    def send_ssh(self, srcip):
        _append(_ssh_line(srcip, self.cfg), self.auth_log_path, self.sudo_tee)

    def send_web(self, srcip, fmt, domain=None, port=None, vhost_ip=None):
        line = _web_line(srcip, fmt, self.cfg, domain=domain, port=port, vhost_ip=vhost_ip)
        _append(line, self.web_log_path, self.sudo_tee)


def case_ssh_whitelisted(em, cfg):
    print("ssh_whitelisted: SSH login from a whitelisted country -> expect nothing")
    em.send_ssh(SOURCES["ssh_whitelisted"])


def case_ssh_non_whitelisted(em, cfg):
    print("ssh_non_whitelisted: SSH login from a non-whitelisted country -> expect 100900 at level 10")
    em.send_ssh(SOURCES["ssh_non_whitelisted"])


def case_ssh_private(em, cfg):
    print("ssh_private: SSH login from a private source IP -> expect nothing (enrichment skipped)")
    em.send_ssh(SOURCES["ssh_private"])


def case_web_ip(em, cfg):
    print("web_ip: web request, ip format, non-whitelisted country -> expect 100902 at level 10")
    em.send_web(SOURCES["web_ip"], "ip")


def case_web_ip_whitelisted(em, cfg):
    print("web_ip_whitelisted: web request, ip format, whitelisted country -> expect nothing")
    em.send_web(SOURCES["web_ip_whitelisted"], "ip")


def case_web_private(em, cfg):
    print("web_private: web request from a private source IP -> expect nothing (enrichment skipped)")
    em.send_web(SOURCES["web_private"], "ip")


def case_web_domain(em, cfg):
    print("web_domain: web request, domain+ip format -> expect 100902 at level 10")
    em.send_web(SOURCES["web_domain"], "domain", domain="shop.example.com")


def case_web_domainport(em, cfg):
    print("web_domainport: web request, host:port+ip format -> expect 100902 at level 10")
    em.send_web(SOURCES["web_domainport"], "domainport", domain="shop.example.com", port=8443)


def case_web_ip_ip(em, cfg):
    print("web_ip_ip: web request, ip-based vhost+ip format -> expect 100902 at level 10")
    em.send_web(SOURCES["web_ip_ip"], "ip_ip", vhost_ip="203.0.113.10")


CASES = {
    "ssh_whitelisted": case_ssh_whitelisted,
    "ssh_non_whitelisted": case_ssh_non_whitelisted,
    "ssh_private": case_ssh_private,
    "web_ip": case_web_ip,
    "web_ip_whitelisted": case_web_ip_whitelisted,
    "web_private": case_web_private,
    "web_domain": case_web_domain,
    "web_domainport": case_web_domainport,
    "web_ip_ip": case_web_ip_ip,
}

EXPECT = {
    "ssh_whitelisted": {
        "src_ips": [SOURCES["ssh_whitelisted"]],
        "present": [],
        "absent": ["100900", "100901"],
    },
    "ssh_non_whitelisted": {
        "src_ips": [SOURCES["ssh_non_whitelisted"]],
        "present": [{"rule": "100900", "level": 10}],
        "absent": [],
    },
    "ssh_private": {
        "src_ips": [SOURCES["ssh_private"]],
        "present": [],
        "absent": ["100900", "100901"],
    },
    "web_ip": {
        "src_ips": [SOURCES["web_ip"]],
        "present": [{"rule": "100902", "level": 10}],
        "absent": [],
    },
    "web_ip_whitelisted": {
        "src_ips": [SOURCES["web_ip_whitelisted"]],
        "present": [],
        "absent": ["100902"],
    },
    "web_private": {
        "src_ips": [SOURCES["web_private"]],
        "present": [],
        "absent": ["100902"],
    },
    "web_domain": {
        "src_ips": [SOURCES["web_domain"]],
        "present": [{"rule": "100902", "level": 10}],
        "absent": [],
    },
    "web_domainport": {
        "src_ips": [SOURCES["web_domainport"]],
        "present": [{"rule": "100902", "level": 10}],
        "absent": [],
    },
    "web_ip_ip": {
        "src_ips": [SOURCES["web_ip_ip"]],
        "present": [{"rule": "100902", "level": 10}],
        "absent": [],
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
    print(f"    Check now: data.src_ip:({ips})")
    print(f"    Time window: {started_at} .. {ended_at}")
    print(f"    Expect present: {_fmt_present(expect['present'])}")
    print(f"    Expect absent:  {_fmt_rule_list(expect['absent'])}")


def _confirm_verified(name):
    """Blocks until an explicit y/n/q answer. Returns True/False/None (quit)."""
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
    auth_log_path = str(cfg["auth_log_path"])
    web_log_path = str(cfg["web_log_path"])
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

    print(f"Simulating geoip_detection: {auth_log_path} and {web_log_path}")
    if interactive:
        print("Interactive mode: after each case, confirm you checked the dashboard before continuing.")
    _ensure_log_dir(auth_log_path, sudo_tee)
    _ensure_log_dir(web_log_path, sudo_tee)
    em = Emitter(auth_log_path, web_log_path, sudo_tee, cfg)

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
        print("geoip_detection simulation stopped early (quit during verification)")
    else:
        print("geoip_detection simulation completed")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        if os.environ.get("RATF_DEBUG"):
            raise
        print(f"ERROR: geoip_detection simulation failed: {e}", file=sys.stderr)
        print("(set RATF_DEBUG=1 for the full traceback)", file=sys.stderr)
        sys.exit(1)