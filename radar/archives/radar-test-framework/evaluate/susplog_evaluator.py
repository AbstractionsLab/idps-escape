import os
import csv
import json
from datetime import datetime, timezone
from dateutil.parser import parse
from typing import List, Dict
import requests
from pathlib import Path
from requests.auth import HTTPBasicAuth
from setup.config_loader import AppConfig


class SuspiciousLoginEvaluator:
    def __init__(self, app_config):
        self.scenario_name="suspicious_login"
        self.es_url=app_config.opensearch_url
        self.auth = HTTPBasicAuth(app_config.opensearch_user, app_config.opensearch_pass)
        self.result_index=app_config.scenario_config[self.scenario_name]["result_index"]
        self.source_log_index=app_config.scenario_config[self.scenario_name]["index_prefix"] + "-*"

    def get_anomalies(self) -> List[Dict]:
        query = {
            "size": 10000,
            "query": {
                "range": {
                    "anomaly_grade": {"gt": 0.0}
                }
            }
        }
        url = f"{self.es_url}/{self.result_index}/_search"
        r = requests.post(
            url,
            auth=self.auth,
            headers={"Content-Type": "application/json"},
            data=json.dumps(query),
            verify=False
        )
        r.raise_for_status()
        return r.json()["hits"]["hits"]

    def get_all_logs_scroll(self, query: dict, index: str) -> List[dict]:
        logs = []
        search_url = f"{self.es_url}/{index}/_search?scroll=2m"
        query["size"] = 10000

        r = requests.post(
            search_url,
            auth=self.auth,
            headers={"Content-Type": "application/json"},
            data=json.dumps(query),
            verify=False
        )
        r.raise_for_status()
        response = r.json()
        scroll_id = response.get("_scroll_id")
        hits = response["hits"]["hits"]
        logs.extend([hit["_source"] for hit in hits])

        while hits:
            scroll_url = f"{self.es_url}/_search/scroll"
            scroll_body = {
                "scroll": "2m",
                "scroll_id": scroll_id
            }
            r = requests.post(
                scroll_url,
                auth=self.auth,
                headers={"Content-Type": "application/json"},
                data=json.dumps(scroll_body),
                verify=False
            )
            r.raise_for_status()
            response = r.json()
            scroll_id = response.get("_scroll_id")
            hits = response["hits"]["hits"]
            logs.extend([hit["_source"] for hit in hits])

        return logs

    def run(self):
        print(f"Evaluating scenario: {self.scenario_name}")
        anomalies = self.get_anomalies()
        metrics = self.evaluate(anomalies)
        print(f"Evaluation complete: {json.dumps(metrics, indent=2)}")
        return metrics

    def evaluate(self, anomalies: list) -> dict:
        anomaly_windows = []



        tp, fp, fn, tn = 0, 0, 0, 0
        now = datetime.now(timezone.utc).isoformat()

        # Step 1: Fetch all source logs till now using scroll
        source_query = {
            "query": {
                "range": {
                    "@timestamp": {
                        "lte": now
                    }
                }
            }
        }
        all_source_logs = self.get_all_logs_scroll(source_query, self.source_log_index)
        print(f"Retrieved {len(all_source_logs)} source logs.")

        matched_logs_set = set()

        # Step 2: Match each anomaly to source logs
        for anomaly in anomalies:
            source = anomaly.get("_source", {})
            user = source.get("entity", [{}])[0].get("value")
            start_ms = source.get("data_start_time")
            end_ms = source.get("data_end_time")

            if not user or not start_ms or not end_ms:
                continue

            start_time = datetime.fromtimestamp(start_ms / 1000, tz=timezone.utc)
            end_time = datetime.fromtimestamp(end_ms / 1000, tz=timezone.utc)
            anomaly_windows.append((user, start_time, end_time))

            matched = [
                log for log in all_source_logs
                if log.get("User ID") == user and
                start_time <= parse(log["@timestamp"]) <= end_time
            ]
            matched_logs_set.update(id(log) for log in matched)

            is_tp = any(
                str(log.get("Is Attack IP", "")).lower() == "true" or
                str(log.get("Is Account Takeover", "")).lower() == "true"
                for log in matched
            )

            if is_tp:
                tp += 1
            else:
                fp += 1

        # Step 3: Remaining logs for FN/TN
        for log in all_source_logs:
            if id(log) in matched_logs_set:
                continue

            is_attack = str(log.get("Is Attack IP", "")).lower() == "true" or \
                        str(log.get("Is Account Takeover", "")).lower() == "true"

            if is_attack:
                fn += 1
            else:
                tn += 1

        self.write_evaluation_csv(self.scenario_name, all_source_logs, anomaly_windows)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        return {
            "Scenario": self.scenario_name,
            "TP": tp,
            "FP": fp,
            "FN": fn,
            "TN": tn,
            "Precision": round(precision, 3),
            "Recall (Detection Rate)": round(recall, 3),
            "F1-Score": round(f1, 3)
        }

    def write_evaluation_csv(self, scenario_name: str, logs: List[dict], anomaly_windows: List[tuple]):
        output_dir = Path("evaluation_results")
        output_dir.mkdir(exist_ok=True)
        output_file = output_dir / f"{scenario_name}_detection_results.csv"

        with output_file.open("w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["User ID", "Timestamp", "Attack Label", "Detected"])

            for log in logs:
                user = log.get("User ID")
                timestamp_str = log.get("@timestamp")
                is_attack = str(log.get("Is Attack IP", "")).lower() == "true" or \
                            str(log.get("Is Account Takeover", "")).lower() == "true"

                detected = False
                for anomaly_user, start, end in anomaly_windows:
                    if anomaly_user == user and start <= parse(timestamp_str) <= end:
                        detected = True
                        break

                writer.writerow([
                    user,
                    timestamp_str,
                    "Yes" if is_attack else "No",
                    "Yes" if detected else "No"
                ])

        print(f"[✓] Detection CSV written to {output_file}")

