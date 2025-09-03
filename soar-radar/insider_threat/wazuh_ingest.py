#!/usr/bin/env python3
import csv
import glob
import json
import os
from datetime import datetime, date, timedelta, timezone
import requests
from requests.auth import HTTPBasicAuth

# ────────────────────────────
# Configuration
# ────────────────────────────
ES_URL = "https://wazuh.indexer:9200"
AUTH = HTTPBasicAuth("admin", "SecretPassword")
CA_CERT = "/etc/ssl/root-ca.pem"
CHUNK_SIZE = 200
REQUEST_TIMEOUT = 60
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ────────────────────────────
# Send bulk via HTTP
# ────────────────────────────
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


# ────────────────────────────
# Date shifting
# ────────────────────────────
def shift_and_bulk(file_pattern, index_prefix, date_field, date_fmt, day_shift):
    """
    day_shift:
      -1 => map events to yesterday (for training)
       0 => map events to today (simulate real-time)
    """
    target_date = date.today() + timedelta(days=day_shift)
    mode = "Training" if day_shift < 0 else "Simulation"

    for path in glob.glob(file_pattern):
        buffer = []
        print(f"{mode} load from {path}")
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # parse original timestamp
                orig = datetime.strptime(row[date_field], date_fmt)
                # new timestamp with shifted date
                new_ts = datetime.combine(target_date, orig.time())
                utc_ts = new_ts.astimezone(timezone.utc)
                iso_ts = utc_ts.isoformat()

                # enrich row
                row["@timestamp"] = iso_ts
                row["event_hour"] = utc_ts.hour
                # compute bytes of content if present
                if "content" in row:
                    row["content_bytes"] = len(row["content"].encode("utf-8"))

                # prepare NDJSON: meta + source
                idx = f"{index_prefix}-{new_ts.strftime('%Y.%m.%d')}"
                buffer.append(json.dumps({"index": {"_index": idx}}))
                buffer.append(json.dumps(row))

                # send in chunks
                if len(buffer) >= CHUNK_SIZE * 2:
                    send_bulk(buffer)
                    buffer.clear()

        # send leftovers
        if buffer:
            send_bulk(buffer)
        print(f" → Completed {mode}, indexed into {idx}")


if __name__ == "__main__":
    to_load = [
        ("file2-5.csv", -5),
        ("file2-4.csv", -4),
        ("file2-3.csv", -3),
        ("file2-2.csv", -2),
        ("file2-1.csv", -1),
        ("file2+0.csv", 0),
        ("file2+1.csv", 1),
        ("file2+2.csv", 2),
        ("file2+3.csv", 3),
        ("file2+4.csv", 4),
        ("file2+5.csv", 5)
    ]

    for filename, shift in to_load:
        file_pattern = os.path.join(BASE_DIR, "dataset", filename)
        shift_and_bulk(
            file_pattern,
            "wazuh-ad-insider-threat",
            "date",
            "%m/%d/%Y %H:%M:%S",
            day_shift=shift
        )
