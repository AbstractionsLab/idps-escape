#!/usr/bin/env python3
import hmac
import json
import os
import re
import socket
import threading
from datetime import datetime, timezone

from flask import Flask, jsonify, request

LOG_FILE = os.environ.get("AD_ALERTS_LOG", "/var/log/ad_alerts.log")
TOKEN_HEADER = "X-RADAR-Webhook-Token"

_NAME_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
MAX_ANOMALIES = 50
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


def _data_bound(value):
    """A bound of the anomaly's data window: epoch milliseconds (what the AD
    result index stores) or ISO 8601. Optional, so an absent or unusable value
    gives None rather than a rejection. Only the re-formatted value is written."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        if isinstance(value, (int, float)) or (isinstance(value, str) and value.strip().isdigit()):
            dt = datetime.fromtimestamp(int(value) / 1000, tz=timezone.utc)
        elif isinstance(value, str) and _TS_RE.match(value):
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        else:
            return None
    except (ValueError, OverflowError, OSError):
        return None
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _count(value):
    """Optional non-negative event count (off-hours rule mode). Unusable gives None."""
    if isinstance(value, bool):
        return None
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return n if 0 <= n <= 10**9 else None


def _optional_name(value):
    return value if isinstance(value, str) and _NAME_RE.match(value) else None


def build_line(data: dict, host: str, now: datetime) -> str:
    trigger = _name(data.get("trigger") or {}, "name")
    entity = _name(data, "entity")
    start = _timestamp(data, "periodStart")
    end = _timestamp(data, "periodEnd")
    grade = _unit_float(data, "anomaly_grade")
    conf = _unit_float(data, "anomaly_confidence")
    body = (f'OpenSearchAD {trigger}: entity="{entity}", start="{start}", end="{end}", '
            f'anomaly_grade="{grade}", anomaly_confidence="{conf}" ')
    data_start, data_end = _data_bound(data.get("dataStart")), _data_bound(data.get("dataEnd"))
    if data_start and data_end and data_start <= data_end:
        body += f'data_start="{data_start}", data_end="{data_end}" '
    count, group = _count(data.get("off_hours_count")), _optional_name(data.get("schedule_group"))
    if count is not None and group:
        body += f'off_hours_count="{count}", schedule_group="{group}" '
    return f"{now.strftime('%b %d %H:%M:%S')} {host} ad_alert: {body}\n"


def build_lines(data: dict, host: str, now: datetime) -> list:
    """One line per anomalous entity. A body without an `anomalies` list (older
    monitors) gives the single line of its top-level fields. Entries that fail
    validation are skipped; the request is rejected only when none is usable."""
    anomalies = data.get("anomalies")
    if not isinstance(anomalies, list):
        return [build_line(data, host, now)]
    lines, seen, errors = [], set(), []
    shared = {k: data.get(k) for k in ("trigger", "periodStart", "periodEnd")}
    for item in [a for a in anomalies if isinstance(a, dict)][:MAX_ANOMALIES]:
        merged = dict(shared, **{k: item.get(k) for k in ("entity", "anomaly_grade", "anomaly_confidence", "dataStart", "dataEnd", "off_hours_count", "schedule_group")})
        try:
            line = build_line(merged, host, now)
        except Invalid as e:
            errors.append(str(e))
            continue
        if merged["entity"] in seen:  # hits are sorted by grade: keep the highest per entity
            continue
        seen.add(merged["entity"])
        lines.append(line)
    if not lines:
        if errors:
            raise Invalid(errors[0])
        return [build_line(data, host, now)]
    return lines


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
        lines = build_lines(data, socket.gethostname(), datetime.now())
    except Invalid as e:
        return jsonify({"status": "rejected", "error": str(e)}), 400
    with _write_lock, open(LOG_FILE, "a") as f:
        f.writelines(lines)
    return jsonify({"status": "written", "lines": len(lines)}), 200


@app.errorhandler(413)
def _too_large(_e):
    return jsonify({"status": "payload too large"}), 413


if __name__ == "__main__":
    port = int(os.environ.get("WEBHOOK_INTERNAL_PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
