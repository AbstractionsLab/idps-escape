#!/usr/bin/env python3
import hmac
import json
import os
import re
import socket
import threading
from datetime import datetime

from flask import Flask, jsonify, request

LOG_FILE = os.environ.get("AD_ALERTS_LOG", "/var/log/ad_alerts.log")
TOKEN_HEADER = "X-RADAR-Webhook-Token"

_NAME_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_TS_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]{5,18}(?:Z|[+-][0-9]{2}:?[0-9]{2})?$")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
_write_lock = threading.Lock()


class Invalid(ValueError):
    pass


def _secret() -> str:
    return os.environ.get("WEBHOOK_SHARED_SECRET", "").strip()


def _authorized() -> bool:
    expected = _secret()
    supplied = request.headers.get(TOKEN_HEADER, "")
    return bool(expected) and hmac.compare_digest(supplied.encode(), expected.encode())


def _name(data: dict, key: str, default: str = None) -> str:
    value = data.get(key, default)
    if not isinstance(value, str) or not _NAME_RE.match(value):
        raise Invalid(f"{key} must match [A-Za-z0-9._:-]{{1,128}}")
    return value


def _unit_float(data: dict, key: str) -> str:
    value = data.get(key)
    try:
        f = float(value)
    except (TypeError, ValueError):
        raise Invalid(f"{key} must be a number")
    if not 0.0 <= f <= 1.0:
        raise Invalid(f"{key} must be between 0 and 1")
    return repr(f)


def _timestamp(data: dict, key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not _TS_RE.match(value):
        raise Invalid(f"{key} must be an ISO 8601 timestamp")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise Invalid(f"{key} must be an ISO 8601 timestamp")
    return value


def build_line(data: dict, host: str, now: datetime) -> str:
    trigger = _name(data.get("trigger") or {}, "name")
    entity = _name(data, "entity")
    start = _timestamp(data, "periodStart")
    end = _timestamp(data, "periodEnd")
    grade = _unit_float(data, "anomaly_grade")
    conf = _unit_float(data, "anomaly_confidence")
    body = (f'OpenSearchAD {trigger}: entity="{entity}", start="{start}", end="{end}", '
            f'anomaly_grade="{grade}", anomaly_confidence="{conf}" ')
    return f"{now.strftime('%b %d %H:%M:%S')} {host} ad_alert: {body}\n"


@app.route("/notify", methods=["POST"])
def receive_alert():
    if not _authorized():
        return jsonify({"status": "unauthorized"}), 401
    try:
        data = json.loads(request.get_data(cache=False) or b"null")
    except ValueError:
        return jsonify({"status": "invalid JSON"}), 400
    if not isinstance(data, dict):
        return jsonify({"status": "invalid JSON"}), 400
    if data == {"ping": True}:
        return jsonify({"status": "pong"}), 200
    try:
        line = build_line(data, socket.gethostname(), datetime.now())
    except Invalid as e:
        return jsonify({"status": "rejected", "error": str(e)}), 400
    with _write_lock, open(LOG_FILE, "a") as f:
        f.write(line)
    return jsonify({"status": "written"}), 200


@app.errorhandler(413)
def _too_large(_e):
    return jsonify({"status": "payload too large"}), 413


if __name__ == "__main__":
    port = int(os.environ.get("WEBHOOK_INTERNAL_PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
