#!/usr/bin/env python3
from __future__ import annotations
import csv, glob, json, os
from datetime import datetime, date, timedelta, timezone
from pathlib import Path
import requests
from requests.auth import HTTPBasicAuth

from convert import convert_row_to_wazuh_docs

# ────────────────────────────
# Configuration
# ────────────────────────────

def load_env(env_path: Path) -> None:
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line: 
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())

load_env(Path(".env"))
ES_URL = os.environ.get("OS_URL", "")
os_user = os.environ.get("OS_USER", "")
os_pass = os.environ.get("OS_PASS", "")
AUTH = HTTPBasicAuth(os_user, os_pass)
CA_CERT = os.environ.get("OS_VERIFY_SSL", "")
CHUNK_SIZE = 200
REQUEST_TIMEOUT = 60
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PIPELINE_NAME = None

# ────────────────────────────
# HTTP bulk
# ────────────────────────────
def send_bulk(lines):
    params = []
    if PIPELINE_NAME:
        params.append(f"pipeline={PIPELINE_NAME}")
    params.append("refresh=true")
    url = f"{ES_URL}/_bulk?{'&'.join(params)}"

    data = "\n".join(lines) + "\n"
    resp = requests.post(
        url,
        auth=AUTH,
        headers={"Content-Type": "application/x-ndjson"},
        data=data,
        verify=CA_CERT,
        timeout=REQUEST_TIMEOUT
    )
    resp.raise_for_status()
    result = resp.json()
    if result.get("errors"):
        failures = [it for it in result.get("items", []) if it.get("index", {}).get("error")]
        print(f"Bulk had {len(failures)} errors; first: {failures[:3]}")
    else:
        print(f"Indexed chunk of {len(lines)//2} docs")

# ────────────────────────────
# Date shifting + bulk
# ────────────────────────────
def shift_and_bulk(file_pattern: str, index_prefix: str, date_field: str, date_fmt: str, day_shift: int):
    """
    day_shift:
      < 0 => treat as training day   → index_prefix-YYYY.MM.DD
      >=0 => treat as prod/sim day   → index_prefix-YYYY.MM.DD
    """
    target_date = date.today() + timedelta(days=day_shift)
    mode = "Training" if day_shift < 0 else "Simulation"

    for path in glob.glob(file_pattern):
        buffer = []
        print(f"{mode} load from {path}")
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                orig = datetime.strptime(row[date_field], date_fmt)
                shifted_local = datetime.combine(target_date, orig.time())

                syscall_doc, path_doc = convert_row_to_wazuh_docs(row, shifted_local)

                idx = f"{index_prefix}-{shifted_local.strftime('%Y.%m.%d')}"
                buffer.append(json.dumps({"index": {"_index": idx}})); buffer.append(json.dumps(syscall_doc, separators=(",",":")))
                buffer.append(json.dumps({"index": {"_index": idx}})); buffer.append(json.dumps(path_doc,    separators=(",",":")))

                if len(buffer) >= CHUNK_SIZE * 2:
                    send_bulk(buffer); buffer.clear()

        if buffer:
            send_bulk(buffer)
        print(f" → Completed {mode}, indexed into {idx}")

# ────────────────────────────
# Main
# ────────────────────────────
if __name__ == "__main__":
    to_load = [
        ("file2-5.csv", -5),
        ("file2-4.csv", -4),
        ("file2-3.csv", -3),
        ("file2-2.csv", -2),
        ("file2-1.csv", -1),
        ("file2+0.csv",  0),
        ("file2+1.csv",  1),
        ("file2+2.csv",  2),
        ("file2+3.csv",  3),
        ("file2+4.csv",  4),
        ("file2+5.csv",  5)
    ]

    for filename, shift in to_load:
        file_pattern = os.path.join(BASE_DIR, "dataset", filename)
        shift_and_bulk(
            file_pattern=file_pattern,
            index_prefix="wazuh-ad-insider-threat",
            date_field="date",
            date_fmt="%m/%d/%Y %H:%M:%S",
            day_shift=shift
        )
