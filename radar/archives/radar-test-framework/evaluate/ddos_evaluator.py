import json
import csv
import requests
from collections import defaultdict
from pathlib import Path
from datetime import datetime
from requests.auth import HTTPBasicAuth

class DDoSEvaluator:
    def __init__(self, app_config):
        self.scenario_name = "ddos_detection"
        self.es_url = app_config.opensearch_url.rstrip("/")
        self.auth = HTTPBasicAuth(app_config.opensearch_user, app_config.opensearch_pass)
        self.es_verify_ssl = app_config.opensearch_verify_ssl
        self.result_index = app_config.scenario_config["ddos_detection"]["result_index"]
        self.source_log_index = app_config.scenario_config["ddos_detection"]["index_prefix"] + "-*"
        relative_path = app_config.scenario_config["ddos_detection"]["label_csv_path"]
        self.label_csv_glob = Path(__file__).resolve().parents[2] / relative_path
        output_dir = Path("evaluation_results")
        output_dir.mkdir(exist_ok=True)
        self.output_file = output_dir / f"{self.scenario_name}_detection_results.csv"

    def _get_all_detections(self):
        query = {"query": {"match_all": {}}, "sort": [{"@timestamp": {"order": "asc"}}]}
        url = f"{self.es_url}/{self.result_index}/_search"
        headers = {"Content-Type": "application/json"}

        detections = defaultdict(list)
        size = 1000
        from_idx = 0
        while True:
            query["from"] = from_idx
            query["size"] = size
            resp = requests.post(url, auth=self.auth, headers=headers, json=query, verify=self.es_verify_ssl)
            resp.raise_for_status()
            hits = resp.json()["hits"]["hits"]
            if not hits:
                break
            for hit in hits:
                src = hit["_source"]
                entity = src.get("entity")
                start = src.get("period_start")
                end = src.get("period_end")
                if entity and start and end:
                    try:
                        detections[entity].append((
                            datetime.fromisoformat(start),
                            datetime.fromisoformat(end)
                        ))
                    except Exception:
                        continue
            from_idx += size
        return detections

    def _is_within_any_window(self, ip, timestamp, detection_windows):
        for (start, end) in detection_windows.get(ip, []):
            if start <= timestamp <= end:
                return True
        return False

    def _query_source_events(self, scroll_duration="2m", batch_size=1000):
        now_ts = datetime.utcnow().isoformat()

        search_url = f"{self.es_url}/{self.source_log_index}/_search?scroll={scroll_duration}"
        headers = {"Content-Type": "application/json"}

        query = {
            "size": batch_size,
            "_source": ["Destination_IP", "@timestamp", "Label"],
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {
                "range": {
                    "@timestamp": {
                        "lte": now_ts
                    }
                }
            }
        }

        # Initial search
        resp = requests.post(search_url, auth=self.auth, headers=headers, json=query, verify=self.es_verify_ssl)
        resp.raise_for_status()
        data = resp.json()
        scroll_id = data.get("_scroll_id")
        hits = data["hits"]["hits"]

        all_events = []
        for hit in hits:
            src = hit["_source"]
            try:
                event = {
                    "Destination_IP": src.get("Destination_IP", "").strip(),
                    "Timestamp": datetime.fromisoformat(src["@timestamp"].strip()),
                    "Label": src.get("Label", "").strip()
                }
                all_events.append(event)
            except Exception:
                continue

        # Continue scrolling until no more data
        while True:
            scroll_resp = requests.post(
                f"{self.es_url}/_search/scroll",
                auth=self.auth,
                headers=headers,
                json={"scroll": scroll_duration, "scroll_id": scroll_id},
                verify=self.es_verify_ssl
            )
            scroll_resp.raise_for_status()
            scroll_data = scroll_resp.json()
            scroll_id = scroll_data.get("_scroll_id")
            hits = scroll_data["hits"]["hits"]

            if not hits:
                break

            for hit in hits:
                src = hit["_source"]
                try:
                    event = {
                        "Destination_IP": src.get("Destination_IP", "").strip(),
                        "Timestamp": datetime.fromisoformat(src["@timestamp"].strip()),
                        "Label": src.get("Label", "").strip()
                    }
                    all_events.append(event)
                except Exception:
                    continue

        print(f"[✓] Retrieved {len(all_events)} events from source index")
        return all_events

    def run(self):
        print(f"[✓] Evaluating DDoS detection for scenario: {self.scenario_name}")
        detection_windows = self._get_all_detections()
        all_events = self._query_source_events()

        TP = FP = FN = TN = 0

        with self.output_file.open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Destination_IP", "Timestamp", "Label", "Detected"])

            for event in all_events:
                dest_ip = event["Destination_IP"]
                timestamp = event["Timestamp"]
                label = event["Label"]
                detected = self._is_within_any_window(dest_ip, timestamp, detection_windows)

                if detected:
                    if label != "BENIGN":
                        TP += 1
                    else:
                        FP += 1
                else:
                    if label != "BENIGN":
                        FN += 1
                    else:
                        TN += 1

                writer.writerow([
                    dest_ip,
                    timestamp.isoformat(),
                    label,
                    "Yes" if detected else "No"
                ])

        print("\n[✓] Evaluation Results:")
        print(f"• TP: {TP}")
        print(f"• FP: {FP}")
        print(f"• FN: {FN}")
        print(f"• TN: {TN}")

        precision = TP / (TP + FP) if (TP + FP) else 0
        recall = TP / (TP + FN) if (TP + FN) else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

        print(f"\nPrecision: {precision:.4f}")
        print(f"Recall: {recall:.4f}")
        print(f"F1 Score: {f1:.4f}")
        print(f"[✓] CSV written to: {self.output_file}")
