#!/usr/bin/env python3
import json
import socket, os
from datetime import datetime
from flask import Flask, request, abort

LOG_FILE = "/var/log/ad_alerts.log"

app = Flask(__name__)

@app.route("/notify", methods=["POST"])
def receive_alert():
    data = request.get_json(force=True)
    if not data:
        abort(400, "invalid JSON")

    mon = data.get("monitor", {}).get("name", "UnknownMonitor")
    trg = data.get("trigger", {}).get("name", "UnknownTrigger")
    ent = data.get("entity", "")
    start = data.get("periodStart", "")
    end   = data.get("periodEnd", "")

    ts = datetime.now().strftime("%b %d %H:%M:%S")
    host = socket.gethostname()


    # format exactly as you specified:
    body = f'OpenSearchAD {trg}: entity="{ent}", start="{start}", end="{end}"'
    line = f"{ts} {host} ad_alert: {body}\n"

    # append to your log
    with open(LOG_FILE, "a") as f:
        f.write(line)

    return {"status":"written"}, 200

if __name__ == "__main__":
    # for production, run under gunicorn or as systemd service
    app.run(host="0.0.0.0", port=8080)
