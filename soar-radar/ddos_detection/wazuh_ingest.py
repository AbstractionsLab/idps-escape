#!/usr/bin/env python3
import csv
import json
import glob
from datetime import datetime, date, timedelta
import requests
from requests.auth import HTTPBasicAuth
import os


# Configuration
ES_URL = "https://wazuh.indexer:9200"
AUTH = HTTPBasicAuth("admin", "SecretPassword")
CA_CERT = "/etc/ssl/root-ca.pem"
CHUNK_SIZE = 200
REQUEST_TIMEOUT = 60
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Send bulk via HTTP
def send_bulk(lines):
    data = "\n".join(lines) + "\n"
    resp = requests.post(
        f"{ES_URL}/_bulk?refresh=true",
        auth=AUTH,
        headers={"Content-Type": "application/x-ndjson"},
        data=data,
        verify=CA_CERT,
        timeout=REQUEST_TIMEOUT
    )
    resp.raise_for_status()
    result = resp.json()
    if result.get("errors"):
        print("Bulk errors:", result["items"])
    else:
        print(f"Indexed chunk of {len(lines) // 2} docs")

def normalize_key(key):
    return key.strip().replace(".", "_").replace(" ", "_").replace("/", "_")

def to_float_safe(val):
    try:
        return float(val)
    except (ValueError, TypeError):
        return val

# Shift date & ingest
def shift_and_bulk(file_pattern, index_prefix, date_field, date_fmt, day_shift):
    target_date = date.today() + timedelta(days=day_shift)
    mode = "Simulation" if day_shift == 0 else "Shifted"

    for path in glob.glob(file_pattern):
        buffer = []
        print(f"{mode} load from {path}")
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            reader.fieldnames = [name.strip() for name in reader.fieldnames]
            for row in reader:
                row = {normalize_key(k.strip()): to_float_safe(v) for k, v in row.items()}
                # Skip placeholder column if exists
                if "Unnamed: 0" in row:
                    del row["Unnamed: 0"]

                # Parse and shift timestamp
                try:
                    orig = datetime.strptime(row[date_field], date_fmt)
                except ValueError:
                    print(f"Invalid date in row: {row[date_field]}")
                    continue

                new_ts = datetime.combine(target_date, orig.time())
                iso_ts = new_ts.isoformat()

                # Inject timestamp and hour
                row["@timestamp"] = iso_ts
                row["event_hour"] = new_ts.hour

                # Prepare bulk index payload
                idx = f"{index_prefix}-{new_ts.strftime('%Y.%m.%d')}"
                buffer.append(json.dumps({"index": {"_index": idx}}))
                buffer.append(json.dumps(row))

                # Send in chunks
                if len(buffer) >= CHUNK_SIZE * 2:
                    send_bulk(buffer)
                    buffer.clear()

        if buffer:
            send_bulk(buffer)
        print(f" → Completed {mode}, indexed into {idx}")


# Main Entry
if __name__ == "__main__":
    file_pattern = os.path.join(BASE_DIR, "dataset", "Syn.csv")
    shift_and_bulk(
        file_pattern,                # Adjust to your actual path
        "wazuh-ad-ddos-detection",
        "Timestamp",
        "%Y-%m-%d %H:%M:%S.%f",
        day_shift=0                            # 0 = simulate today
    )
