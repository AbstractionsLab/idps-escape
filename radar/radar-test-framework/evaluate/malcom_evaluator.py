from pathlib import Path
from datetime import datetime
from collections import defaultdict
import requests
import json
import csv
from requests.auth import HTTPBasicAuth


class MalwareC2Evaluator:
    def __init__(self, app_config):
        self.scenario_name = "malware_communication"
        self.es_url = app_config.opensearch_url.rstrip("/")
        self.auth = HTTPBasicAuth(app_config.opensearch_user, app_config.opensearch_pass)
        self.es_verify_ssl = app_config.opensearch_verify_ssl
        self.result_index = app_config.scenario_config["malware_communication"]["result_index"]
        self.source_log_index = app_config.scenario_config["malware_communication"]["index_prefix"] + "-*"
        self.output_dir = Path("evaluation_results")
        self.output_dir.mkdir(exist_ok=True)
        self.output_file = self.output_dir / f"{self.scenario_name}_detection_results.csv"

    def fetch_anomalies(self):
        query = {
            "size": 10000,
            "query": {"match_all": {}}
        }
        url = f"{self.es_url}/{self.result_index}/_search"
        response = requests.get(url, headers={"Content-Type": "application/json"}, auth=self.auth,
                                data=json.dumps(query), verify=self.es_verify_ssl)
        response.raise_for_status()
        results = response.json()["hits"]["hits"]

        anomalies = defaultdict(list)  # group by IP (entity)
        for hit in results:
            source = hit["_source"]
            ip = source.get("entity", [{}])[0].get("value")
            start = source.get("data", {}).get("period_start")
            end = source.get("data", {}).get("period_end")
            if ip and start and end:
                try:
                    start_dt = datetime.fromisoformat(start)
                    end_dt = datetime.fromisoformat(end)
                    anomalies[ip].append((start_dt, end_dt))
                except Exception:
                    continue
        return anomalies

    def fetch_all_events(self):
        query = {"size": 10000, "query": {"match_all": {}}}
        url = f"{self.es_url}/{self.source_log_index}/_search"
        response = requests.get(url, headers={"Content-Type": "application/json"}, auth=self.auth,
                                data=json.dumps(query), verify=self.es_verify_ssl)
        response.raise_for_status()
        return response.json()["hits"]["hits"]

    def write_detection_csv(self, anomalies_by_ip, all_events):
        with self.output_file.open("w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Source IP", "Timestamp", "Label", "Detected"])

            for event in all_events:
                src = event.get("_source", {})
                entity = src.get("id.orig_h")
                timestamp = src.get("@timestamp")
                label = src.get("label", "Unknown")
                try:
                    ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                except Exception:
                    continue

                windows = anomalies_by_ip.get(entity, [])
                detected = any(start <= ts <= end for start, end in windows)
                writer.writerow([entity, timestamp, label, "Yes" if detected else "No"])

        print(f"[✓] Malware Communication detection CSV written to: {self.output_file}")

    def run(self):
        print(f"[✓] Starting evaluation for scenario: {self.scenario_name}")
        anomalies_by_ip = self.fetch_anomalies()
        all_events = self.fetch_all_events()
        self.write_detection_csv(anomalies_by_ip, all_events)

        # Evaluation summary (optional)
        TP = FP = FN = TN = 0
        for event in all_events:
            src = event.get("_source", {})
            entity = src.get("id.orig_h")
            timestamp = src.get("@timestamp")
            label = src.get("label", "Unknown")
            try:
                ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except Exception:
                continue

            detected = any(start <= ts <= end for start, end in anomalies_by_ip.get(entity, []))

            if detected and label != "Benign":
                TP += 1
            elif detected and label == "Benign":
                FP += 1
            elif not detected and label != "Benign":
                FN += 1
            elif not detected and label == "Benign":
                TN += 1

        precision = TP / (TP + FP) if (TP + FP) else 0
        recall = TP / (TP + FN) if (TP + FN) else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

        print("\nEvaluation Summary:")
        print(f"• TP: {TP}")
        print(f"• FP: {FP}")
        print(f"• FN: {FN}")
        print(f"• TN: {TN}")
        print(f"\nPrecision: {precision:.4f}")
        print(f"Recall: {recall:.4f}")
        print(f"F1 Score: {f1:.4f}")
