#!/usr/bin/env python3
"""Inject one anomaly-detector alert through the RADAR webhook, to test fusion.

The suspicious_login off-hour detector needs days of baseline and real off-hour
logins before it fires, so this posts the alert the detector's monitor would
send, for one user. Run it on the host that publishes the webhook port (the
manager host by default), then run a suspicious_login case for the same user
within the fusion window:

    1. python3 inject_ad_alert.py              (anomaly for test01, data window ending now)
    2. on the agent: python3 suspicious_login.py burst   (210013 for test01)

The 210013 decision should then report a fused anomaly counterpart. In the
other order (burst first, then this script), the 210040 decision is the one
that reports the signature counterpart.

The body has the same shape as the monitor's (see monitor.py
message_template), so it also exercises the webhook's multi-entity path.
Standard library only.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

CONFIG = {
    "webhook_url": "http://127.0.0.1:8080/notify",
    # WEBHOOK_SHARED_SECRET is read from the environment, else from this file.
    "env_file": str(Path(__file__).resolve().parents[3] / ".env"),
    "trigger": "SuspiciousLogin-OffHour-Detected",
    "entity": "test01",
    "anomaly_grade": 0.8,
    "anomaly_confidence": 0.9,
    # The anomaly's data window ends this many minutes ago and lasts window_minutes.
    "ends_minutes_ago": 0,
    "window_minutes": 5,
}


def _secret(env_file: str) -> str:
    value = os.environ.get("WEBHOOK_SHARED_SECRET", "").strip()
    if value:
        return value
    try:
        for line in Path(env_file).read_text().splitlines():
            line = line.strip()
            if line.startswith("export "):
                line = line[len("export "):]
            if line.startswith("WEBHOOK_SHARED_SECRET="):
                return line.split("=", 1)[1].strip().strip("'\"")
    except OSError:
        pass
    return ""


def _iso(epoch_s: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(epoch_s)) + "Z"


def build_body(cfg: dict, now: float) -> dict:
    end = now - cfg["ends_minutes_ago"] * 60
    start = end - cfg["window_minutes"] * 60
    anomaly = {
        "entity": cfg["entity"],
        "anomaly_grade": str(cfg["anomaly_grade"]),
        "anomaly_confidence": str(cfg["anomaly_confidence"]),
        "dataStart": str(int(start * 1000)),
        "dataEnd": str(int(end * 1000)),
    }
    return dict(anomaly, monitor={"name": "inject_ad_alert"}, trigger={"name": cfg["trigger"]},
                periodStart=_iso(end), periodEnd=_iso(now), anomalies=[anomaly, None])


def main() -> int:
    secret = _secret(CONFIG["env_file"])
    if not secret:
        print(f"WEBHOOK_SHARED_SECRET not set in the environment or {CONFIG['env_file']}", file=sys.stderr)
        return 1
    body = build_body(CONFIG, time.time())
    req = urllib.request.Request(CONFIG["webhook_url"], data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "X-RADAR-Webhook-Token": secret})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"webhook: {resp.status} {resp.read().decode(errors='replace')}")
    except urllib.error.HTTPError as e:
        print(f"webhook rejected the alert: {e.code} {e.read().decode(errors='replace')}", file=sys.stderr)
        return 1
    except urllib.error.URLError as e:
        print(f"webhook unreachable at {CONFIG['webhook_url']}: {e.reason}", file=sys.stderr)
        return 1
    print(f"injected {CONFIG['trigger']} for entity={CONFIG['entity']} "
          f"(grade={CONFIG['anomaly_grade']}, confidence={CONFIG['anomaly_confidence']})")
    if CONFIG["trigger"] == "SuspiciousLogin-OffHour-Detected":
        print("expect rule 210040 (suspicious_login, detection ad)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
