import os
import random
import string
import time
import json
import re
import requests
import subprocess
import csv
from pathlib import Path
from uuid import uuid4
from datetime import datetime, timezone
from setup.config_loader import AppConfig

class InsiderThreatSimulator:
    def __init__(self, user_id: str, pc_name: str, app_config: AppConfig):
        self.user_id = user_id
        self.pc_name = pc_name
        self.log_dir = app_config.log_dir
        self.opensearch_url = app_config.opensearch_url
        self.auth = (app_config.opensearch_user, app_config.opensearch_pass)
        self.verify_cert = app_config.opensearch_verify_ssl
        self.index_prefix = app_config.scenario_config["insider_threat"]["index_prefix"]
        self.container_name = app_config.scenario_config["insider_threat"]["container_name"]

    def simulate_and_ingest(self, normal_count=5, anomaly_count=5):
        self._create_user_in_container()
        self._simulate_with_strace(normal_count, anomaly_count)
        logs = self._parse_strace_log()
        self._save_to_csv(logs)

        for log in logs:
            self.send_to_opensearch(log)
            time.sleep(0.2)

        print(f"[✓] Simulated and ingested {len(logs)} insider threat logs.")

    def _save_to_csv(self, logs):
        if not logs:
            print("[!] No logs to save to CSV.")
            return

        # Assume you're running from within `soar-radar/radar_test_framework/...`
        project_root = Path(__file__).resolve().parents[2]  # go up 2 levels to soar-radar
        dataset_dir = project_root / "insider_threat" / "dataset"
        dataset_dir.mkdir(parents=True, exist_ok=True)

        # Random filename
        random_suffix = uuid4().hex[:6]
        csv_path = dataset_dir / f"answers-{random_suffix}.csv"

        with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["id", "date", "user", "pc", "filename", "content"])
            writer.writeheader()
            writer.writerows(logs)

        print(f"[✓] Saved {len(logs)} logs to {csv_path}")

    def _create_user_in_container(self):
        print(f"[→] Creating user {self.user_id} in container...")
        try:
            subprocess.run([
                "docker", "exec", self.container_name, "useradd", "-m", self.user_id
            ], check=True)
            print(f"[✓] User {self.user_id} created successfully.")
        except subprocess.CalledProcessError:
            print(f"[!] User {self.user_id} may already exist. Skipping creation.")

    def _simulate_with_strace(self, normal_count, anomaly_count):
        trace_commands = []

        for _ in range(normal_count):
            trace_commands.append(f"su - {self.user_id} -c 'cat /etc/passwd > /dev/null'")

        for _ in range(anomaly_count):
            filename = f"/tmp/{self._rand_block()}.txt"
            trace_commands.append(f"su - {self.user_id} -c 'dd if=/dev/urandom bs=1M count=5 | base64 > {filename}'")

        strace_cmd = (
            f"strace -ff -y -e trace=open,read -s 500 -o {self.log_dir} "
            f"bash -c \"{' && '.join(trace_commands)}\""
        )

        try:
            subprocess.run([
                "docker", "exec", self.container_name, "bash", "-c", strace_cmd
            ], check=True)
            print("[✓] Strace command executed.")
        except subprocess.CalledProcessError as e:
            print(f"[!] Strace simulation failed: {e}")

    def _parse_strace_log(self):
        try:
            log_files = subprocess.check_output([
                "docker", "exec", self.container_name, "bash", "-c", f"ls {self.log_dir}*"
            ]).decode().strip().splitlines()
        except subprocess.CalledProcessError:
            print(f"[!] No strace logs found at {self.log_dir}*")
            return []

        logs = []
        file_pattern = re.compile(r'read\(\d+<(/[^>]+)>')

        for path in log_files:
            try:
                output = subprocess.check_output([
                    "docker", "exec", self.container_name, "cat", path
                ]).decode()

                for line in output.splitlines():
                    match = file_pattern.search(line)
                    if match:
                        filename = match.group(0)
                        content_raw = match.group(1)
                        if filename.startswith("/proc") or filename.startswith("/dev"):
                            continue  # Skip system noise

                        timestamp = datetime.now()
                        log_entry = {
                            "id": f"{{{self._random_id()}}}",
                            "date": timestamp.strftime("%m/%d/%Y %H:%M:%S"),
                            "user": self.user_id,
                            "pc": self.pc_name,
                            "filename": filename,
                            "content": content_raw
                        }
                        logs.append(log_entry)

            except subprocess.CalledProcessError:
                print(f"[!] Could not read strace output from: {path}")

        return logs

    def send_to_opensearch(self, log_entry):
        try:
            dt_local = datetime.strptime(log_entry["date"], "%m/%d/%Y %H:%M:%S")
            dt_utc = dt_local.astimezone(timezone.utc)
            index_name = f"{self.index_prefix}-{dt_utc.strftime('%Y.%m.%d')}"

            payload = {
                **log_entry,
                "@timestamp": dt_utc.isoformat(),
                "event_hour": dt_utc.hour,
                "content_bytes": len(log_entry["content"].encode("utf-8"))
            }

            response = requests.post(
                f"{self.opensearch_url}/{index_name}/_doc",
                auth=self.auth,
                headers={"Content-Type": "application/json"},
                data=json.dumps(payload),
                verify=self.verify_cert,
                timeout=10
            )

            if response.status_code >= 300:
                print(f"[!] Failed to upload to OpenSearch: {response.status_code} {response.text}")
            else:
                print(f"[+] Log uploaded: {log_entry['filename']}")

        except Exception as e:
            print(f"[!] OpenSearch upload error: {e}")

    def _random_id(self):
        return "{}-{}-{}".format(
            self._rand_block(),
            self._rand_block(),
            self._rand_block()
        )

    def _rand_block(self):
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))


if __name__ == "__main__":
    sim = InsiderThreatSimulator(user_id="BAL0044", pc_name="agent.insider")
    sim.simulate_and_ingest(normal_count=3, anomaly_count=2)
