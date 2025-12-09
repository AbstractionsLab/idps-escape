#!/usr/bin/env python3

import sys
import json
import smtplib
import traceback
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import os
from pathlib import Path

def load_active_responses_env():
    candidates = [
        Path("/var/ossec/active-response/bin/active_responses.env"),
        Path(__file__).with_name("active_responses.env"),
    ]

    env_file = next((p for p in candidates if p.exists()), None)
    if not env_file:
        return

    with env_file.open() as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key:
                os.environ.setdefault(key, value)

load_active_responses_env()

LOGFILE = os.environ.get("AR_LOG_FILE", "/var/ossec/logs/active-responses.log")

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.office365.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
EMAIL_TO = os.environ.get("EMAIL_TO", "")
EMAIL_FROM = os.environ.get("EMAIL_FROM", SMTP_USER)
USE_STARTTLS = os.environ.get("SMTP_STARTTLS", "yes").lower() in ("1", "true", "yes")

def log(level, msg):
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"{ts} [{level}] {msg}\n"
    try:
        with open(LOGFILE, "a") as f:
            f.write(line)
    except Exception:
        sys.stderr.write("Failed to write to log file: " + traceback.format_exc() + "\n")
        sys.stderr.write(line)

def log_exc(prefix="Exception"):
    tb = traceback.format_exc()
    log("ERROR", f"{prefix}: {tb}")

def read_wrapper():
    raw = sys.stdin.read()
    if raw is None:
        return None
    raw = raw.strip()
    log("DEBUG", f"Raw STDIN length={len(raw)}. Raw head: {raw[:1000]!r}")
    if not raw:
        log("DEBUG", "No raw input from stdin")
        return None
    try:
        wrapper = json.loads(raw)
        log("DEBUG", f"Parsed JSON wrapper keys: {list(wrapper.keys())}")
    except Exception as e:
        log("ERROR", f"Cannot parse AR wrapper JSON: {e}. Raw (first 2000 chars): {raw[:2000]!r}")
        log_exc("JSON parse error")
        return None

    alert_obj = wrapper
    if isinstance(wrapper, dict):
        params = wrapper.get("parameters")
        if isinstance(params, dict):
            inner_alert = params.get("alert")
            if isinstance(inner_alert, dict):
                alert_obj = inner_alert
                log("DEBUG", f"Using parameters.alert as alert object, keys: {list(inner_alert.keys())}")

    return alert_obj

def send_email(subject, body):
    log("INFO", f"Preparing to send email: subject={subject!r} from={EMAIL_FROM} to={EMAIL_TO} via {SMTP_HOST}:{SMTP_PORT} starttls={USE_STARTTLS}")
    msg = MIMEMultipart()
    msg["From"] = EMAIL_FROM
    msg["To"] = EMAIL_TO
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30)
        log("DEBUG", f"SMTP connection opened to {SMTP_HOST}:{SMTP_PORT}")
    except Exception as e:
        log("ERROR", f"Failed to open SMTP connection: {e}")
        log_exc("SMTP connect error")
        return False

    try:
        server.ehlo()
        log("DEBUG", "Sent EHLO")
        if USE_STARTTLS:
            server.starttls()
            log("DEBUG", "Started STARTTLS")
            server.ehlo()
            log("DEBUG", "Sent EHLO after STARTTLS")

        if SMTP_USER and SMTP_PASS and SMTP_PASS != "CHANGE_ME":
            try:
                server.login(SMTP_USER, SMTP_PASS)
                log("INFO", f"SMTP login succeeded for user {SMTP_USER}")
            except Exception as e:
                log("ERROR", f"SMTP login failed for user {SMTP_USER}: {e}")
                log_exc("SMTP login failure")
                try:
                    server.quit()
                except Exception:
                    pass
                return False
        else:
            log("WARNING", "SMTP_USER or SMTP_PASS not provided or SMTP_PASS left as placeholder; trying to send without auth")

        try:
            server.send_message(msg)
            log("INFO", "Email send_message succeeded")
        except Exception as e:
            log("ERROR", f"Failed to send email: {e}")
            log_exc("SMTP send error")
            try:
                server.quit()
            except Exception:
                pass
            return False

        try:
            server.quit()
            log("DEBUG", "SMTP connection closed gracefully (QUIT)")
        except Exception as e:
            log("WARNING", f"Exception during SMTP quit: {e}")
            log_exc("SMTP quit warning")

        return True

    except Exception as e:
        log("ERROR", f"Unhandled SMTP exception: {e}")
        log_exc("Unhandled SMTP exception")
        try:
            server.quit()
        except Exception:
            pass
        return False

def build_message_from_alert(alert):
    try:
        rule = alert.get("rule", {}) if isinstance(alert, dict) else {}
        rule_id = rule.get("id", "unknown")
        rule_desc = rule.get("description", "")
        level = rule.get("level", "unknown")
    except Exception:
        rule_id = "unknown"
        rule_desc = ""
        level = "unknown"

    timestamp = alert.get("timestamp", "") if isinstance(alert, dict) else ""
    agent = alert.get("agent", {}).get("name", "") if isinstance(alert.get("agent", {}), dict) else ""
    data = alert.get("data", {})
    srcip = data.get("srcip", "") or alert.get("srcip_dst", "") or ""
    dstuser = data.get("dstuser", "") or alert.get("dstuser_dst", "") or ""
    srcuser = data.get("srcuser", "")
    radar_outcome = data.get("radar_outcome", "")
    radar_asn = data.get("radar_asn", "")
    radar_country = data.get("radar_country", "")
    radar_geo_velocity_kmh = data.get("radar_geo_velocity_kmh", "")

    subject = f"Wazuh Alert {rule_id} level={level} - {rule_desc[:80]}"
    body_lines = [
        f"Timestamp: {timestamp}",
        f"Agent: {agent}",
        f"Rule ID: {rule_id}",
        f"Rule description: {rule_desc}",
        f"Level: {level}",
        f"Source IP: {srcip}",
        f"Source user: {srcuser}",
        f"Destination user: {dstuser}",
        f"RADAR outcome: {radar_outcome}",
        f"RADAR ASN: {radar_asn}",
        f"RADAR country: {radar_country}",
        f"RADAR geo_velocity_kmh: {radar_geo_velocity_kmh}",
        "",
        "Full alert JSON:",
        json.dumps(alert, indent=2, sort_keys=True)
    ]
    body = "\n".join(body_lines)
    return subject, body

def main():
    log("INFO", "email_ar active-response started")

    alert = read_wrapper()
    if alert is None:
        log("WARNING", "No alert wrapper parsed - exiting")
        return

    log("INFO", "Building message from alert")
    try:
        subject, body = build_message_from_alert(alert)
        log("DEBUG", f"Email subject: {subject!r}")
        log("DEBUG", f"Email body head: {body[:800]!r}")
    except Exception as e:
        log("ERROR", f"Failed to build message: {e}")
        log_exc("build_message_from_alert error")
        return

    ok = send_email(subject, body)
    if ok:
        log("INFO", "Active response email_ar completed successfully")
    else:
        log("ERROR", "Active response email_ar failed - see earlier logs")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log("CRITICAL", f"Unhandled exception in main: {e}")
        log_exc("main crash")
        sys.exit(2)