#!/usr/bin/env python3
"""Traffic generator for scanning_detection. Emits Suricata eve.json records.

Field names are load-bearing: src_ip, http.http_user_agent, http.status,
http.http_method. Indicator 2 only counts on event_type "http"; indicators 1
and 3 are emitted on both the alert and http streams.

Cases, and what each one should produce:

  i1_only        scanner User-Agent, one request      -> 100810 (level 3), no confirm
  i2_only        failed requests at threshold         -> 100825 (level 10), no confirm
  i2_below       one request fewer                    -> 100815 only, no 100825
  i2_spread      threshold spread over 4 sources      -> nothing
  i3_only        TRACE and PROPFIND, browser UA       -> 100820 / 100821, no confirm
  i3_excluded    OPTIONS, PUT, DELETE, PATCH          -> nothing
  webdav_app     PROPFIND from a listed vhost         -> nothing (CDB list)
  confirm_1_2    scanner UA + failed-request rate     -> 100830 (level 12)
  confirm_1_3    scanner UA + TRACE                   -> 100830
  confirm_2_3    failed-request rate + TRACE          -> 100830
  confirm_split  two indicators, two sources          -> no 100830
  legit          normal session, CORS preflight,
                 crawler, uptime monitor, CI          -> nothing above level 3

Run a single case with:  scanning_detection.py confirm_1_3
Default runs every case, spaced so alerts stay attributable.
"""
import datetime as dt
import json
import os
import subprocess
import sys
import time

CONFIG = {
    "log_path": "/var/log/suricata/eve.json",
    "host": "app.radar.test",
    "webdav_host": "owncloud.domain.com",
    "fail_threshold": 20,
    "indicator_gap_seconds": 2,
    "sudo_tee": False,
}

BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
CRAWLER_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
SCANNER_UA = "sqlmap/1.7.2#stable (https://sqlmap.org)"
MONITOR_UA = "Uptime-Monitor/1.0"
CI_UA = "curl/8.4.0"

SOURCES = {
    "i1_only": "198.51.100.11",
    "i2_only": "198.51.100.12",
    "i2_below": "198.51.100.13",
    "i3_only": "198.51.100.14",
    "i3_excluded": "198.51.100.15",
    "webdav_app": "198.51.100.16",
    "confirm_1_2": "198.51.100.21",
    "confirm_1_3": "198.51.100.22",
    "confirm_2_3": "198.51.100.23",
    "confirm_split_a": "198.51.100.24",
    "confirm_split_b": "198.51.100.25",
    "legit": "198.51.100.31",
    "crawler": "198.51.100.32",
    "monitor": "198.51.100.33",
    "ci": "198.51.100.34",
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


def _line(srcip, method, url, status, ua, host, event_type="http"):
    """One Suricata eve.json record.

    Mirrors the http object Suricata emits with "extended: yes". When
    event_type is "alert" an alert object is included too, which is the shape
    of the records this deployment currently produces.
    """
    record = {
        "timestamp": dt.datetime.now().astimezone().isoformat(),
        "flow_id": 1000000000000000.0,
        "event_type": event_type,
        "src_ip": srcip,
        "src_port": 49046,
        "dest_ip": "192.168.4.40",
        "dest_port": 80,
        "proto": "TCP",
        "app_proto": "http",
        "tx_id": 0,
        "http": {
            "hostname": host,
            "url": url,
            "http_user_agent": ua,
            "http_method": method,
            "protocol": "HTTP/1.1",
            "status": str(status),
            "length": 351,
        },
    }
    if event_type == "alert":
        record["alert"] = {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2221034,
            "rev": 1,
            "signature": "SURICATA HTTP Request unrecognized authorization method",
            "category": "Generic Protocol Command Decode",
            "severity": 3,
        }
    return json.dumps(record, separators=(",", ":"))


class Emitter:
    def __init__(self, log_path, sudo_tee, host):
        self.log_path = log_path
        self.sudo_tee = sudo_tee
        self.host = host

    def send(self, srcip, method, url, status, ua, host=None, event_type="http"):
        _append(_line(srcip, method, url, status, ua, host or self.host, event_type),
                self.log_path, self.sudo_tee)


def case_i1_only(em, cfg):
    print("i1_only: scanner User-Agent on both streams -> expect 100810 at level 3, no confirmation")
    em.send(SOURCES["i1_only"], "GET", "/", 200, SCANNER_UA)
    em.send(SOURCES["i1_only"], "GET", "/", 200, SCANNER_UA, event_type="alert")


def case_i2_only(em, cfg):
    n = cfg["fail_threshold"]
    print(f"i2_only: {n} failed requests -> expect 100825 at level 10, no confirmation")
    for i in range(n):
        em.send(SOURCES["i2_only"], "GET", f"/admin/backup{i}.zip", 404, BROWSER_UA)


def case_i2_below(em, cfg):
    n = cfg["fail_threshold"] - 1
    print(f"i2_below: {n} failed requests (one under threshold) -> expect 100815 only")
    for i in range(n):
        em.send(SOURCES["i2_below"], "GET", f"/old/page{i}.php", 404, BROWSER_UA)


def case_i2_spread(em, cfg):
    n = cfg["fail_threshold"]
    sources = [f"203.0.113.{40 + i}" for i in range(4)]
    print(f"i2_spread: {n} failed requests across {len(sources)} sources -> expect no 100825")
    for i in range(n):
        em.send(sources[i % len(sources)], "GET", f"/missing{i}", 404, BROWSER_UA)


def case_i3_only(em, cfg):
    print("i3_only: TRACE and PROPFIND with a browser UA -> expect 100820 and 100821, no confirmation")
    em.send(SOURCES["i3_only"], "TRACE", "/", 405, BROWSER_UA)
    em.send(SOURCES["i3_only"], "PROPFIND", "/webdav/", 405, BROWSER_UA)
    em.send(SOURCES["i3_only"], "TRACE", "/", 405, BROWSER_UA, event_type="alert")


def case_i3_excluded(em, cfg):
    print("i3_excluded: OPTIONS, PUT, DELETE, PATCH -> expect nothing")
    for _ in range(5):
        em.send(SOURCES["i3_excluded"], "OPTIONS", "/api/v1/items", 204, BROWSER_UA)
    em.send(SOURCES["i3_excluded"], "PUT", "/api/v1/items/1", 200, BROWSER_UA)
    em.send(SOURCES["i3_excluded"], "DELETE", "/api/v1/items/1", 204, BROWSER_UA)
    em.send(SOURCES["i3_excluded"], "PATCH", "/api/v1/items/2", 200, BROWSER_UA)


def case_webdav_app(em, cfg):
    """A vhost in radar_webdav_apps serves WebDAV natively, so 100821 must not
    fire on it. Uses the ownCloud shape observed on this deployment."""
    print("webdav_app: PROPFIND from an allowlisted WebDAV vhost -> expect nothing")
    em.send(SOURCES["webdav_app"], "PROPFIND", "/remote.php/dav/files/user/", 207,
            "Mozilla/5.0 (Windows) mirall/5.3.1.14018 (ownCloud)",
            host=cfg["webdav_host"])


def _failed_burst(em, srcip, cfg, prefix="/wp-admin"):
    for i in range(cfg["fail_threshold"]):
        em.send(srcip, "GET", f"{prefix}/{i}.php", 404, BROWSER_UA)


def case_confirm_1_2(em, cfg):
    ip = SOURCES["confirm_1_2"]
    print("confirm_1_2: scanner UA then failed-request rate -> expect 100830 at level 12")
    em.send(ip, "GET", "/", 200, SCANNER_UA)
    time.sleep(cfg["indicator_gap_seconds"])
    _failed_burst(em, ip, cfg)


def case_confirm_1_3(em, cfg):
    ip = SOURCES["confirm_1_3"]
    print("confirm_1_3: scanner UA then TRACE -> expect 100830 at level 12")
    em.send(ip, "GET", "/", 200, SCANNER_UA)
    time.sleep(cfg["indicator_gap_seconds"])
    em.send(ip, "TRACE", "/", 405, SCANNER_UA)


def case_confirm_2_3(em, cfg):
    ip = SOURCES["confirm_2_3"]
    print("confirm_2_3: failed-request rate then TRACE -> expect 100830 at level 12")
    for _ in range(2):
        _failed_burst(em, ip, cfg)
        time.sleep(cfg["indicator_gap_seconds"])
        em.send(ip, "TRACE", "/", 405, BROWSER_UA)


def case_confirm_split(em, cfg):
    a, b = SOURCES["confirm_split_a"], SOURCES["confirm_split_b"]
    print("confirm_split: two indicators from two sources -> expect no 100830")
    em.send(a, "GET", "/", 200, SCANNER_UA)
    time.sleep(cfg["indicator_gap_seconds"])
    em.send(b, "TRACE", "/", 405, BROWSER_UA)


def case_legit(em, cfg):
    print("legit: normal session, CORS preflight, crawler, uptime monitor, CI -> expect nothing above level 3")
    ip = SOURCES["legit"]
    for url in ("/", "/static/app.css", "/static/app.js", "/api/v1/profile", "/logout"):
        em.send(ip, "GET", url, 200, BROWSER_UA)
    for _ in range(10):
        em.send(ip, "OPTIONS", "/api/v1/items", 204, BROWSER_UA)
    for _ in range(5):
        em.send(SOURCES["monitor"], "GET", "/healthz", 200, MONITOR_UA)
    em.send(SOURCES["ci"], "GET", "/healthz", 200, CI_UA)
    em.send(SOURCES["ci"], "POST", "/api/v1/smoke", 201, CI_UA)


CASES = {
    "i1_only": case_i1_only,
    "i2_only": case_i2_only,
    "i2_below": case_i2_below,
    "i2_spread": case_i2_spread,
    "i3_only": case_i3_only,
    "i3_excluded": case_i3_excluded,
    "webdav_app": case_webdav_app,
    "confirm_1_2": case_confirm_1_2,
    "confirm_1_3": case_confirm_1_3,
    "confirm_2_3": case_confirm_2_3,
    "confirm_split": case_confirm_split,
    "legit": case_legit,
}

EXPECT = {
    "i1_only": {
        "src_ips": [SOURCES["i1_only"]],
        "present": [{"rule": "100810", "level": 3}],
        "absent": ["100815", "100820", "100821", "100825", "100826", "100827", "100828", "100830"],
    },
    "i2_only": {
        "src_ips": [SOURCES["i2_only"]],
        "present": [{"rule": "100825", "level": 10}],
        "absent": ["100810", "100820", "100821", "100826", "100827", "100828", "100830"],
    },
    "i2_below": {
        "src_ips": [SOURCES["i2_below"]],
        "present": [{"rule": "100815", "level": 2}],
        "absent": ["100825", "100830"],
    },
    "i2_spread": {
        "src_ips": [f"203.0.113.{40 + i}" for i in range(4)],
        "present": [{"rule": "100815", "level": 2}],
        "absent": ["100825", "100830"],
    },
    "i3_only": {
        "src_ips": [SOURCES["i3_only"]],
        "present": [{"rule": "100820", "level": 6}, {"rule": "100821", "level": 6}],
        "absent": ["100830"],
    },
    "i3_excluded": {
        "src_ips": [SOURCES["i3_excluded"]],
        "present": [],
        "absent": ["100810", "100815", "100820", "100821", "100825", "100830"],
    },
    "webdav_app": {
        "src_ips": [SOURCES["webdav_app"]],
        "present": [],
        "absent": ["100820", "100821", "100830"],
    },
    "confirm_1_2": {
        "src_ips": [SOURCES["confirm_1_2"]],
        "present": [{"rule": "100830", "level": 12}],
        "absent": [],
    },
    "confirm_1_3": {
        "src_ips": [SOURCES["confirm_1_3"]],
        "present": [{"rule": "100830", "level": 12}],
        "absent": [],
    },
    "confirm_2_3": {
        "src_ips": [SOURCES["confirm_2_3"]],
        "present": [{"rule": "100830", "level": 12}],
        "absent": [],
    },
    "confirm_split": {
        "src_ips": [SOURCES["confirm_split_a"], SOURCES["confirm_split_b"]],
        "present": [{"rule": "100810", "level": 3}, {"rule": "100820", "level": 6}],
        "absent": ["100830"],
    },
    "legit": {
        "src_ips": [SOURCES["legit"], SOURCES["crawler"], SOURCES["monitor"], SOURCES["ci"]],
        "present": [],
        "absent": ["100810", "100820", "100821", "100825", "100830"],
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

    print(f"Simulating scanning_detection: {log_path}")
    if interactive:
        print("Interactive mode: after each case, confirm you checked the dashboard before continuing.")
    _ensure_log_dir(log_path, sudo_tee)
    em = Emitter(log_path, sudo_tee, str(cfg["host"]))

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
            time.sleep(cfg["indicator_gap_seconds"])

    _print_summary(rows, interactive)
    print()
    if aborted:
        print("scanning_detection simulation stopped early (quit during verification)")
    else:
        print("scanning_detection simulation completed")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        if os.environ.get("RATF_DEBUG"):
            raise
        print(f"ERROR: scanning_detection simulation failed: {e}", file=sys.stderr)
        print("(set RATF_DEBUG=1 for the full traceback)", file=sys.stderr)
        sys.exit(1)