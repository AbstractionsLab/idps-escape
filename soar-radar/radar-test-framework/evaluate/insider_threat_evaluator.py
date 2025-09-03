import os
import csv
import json
from datetime import datetime
from typing import List, Dict, Tuple
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth
from dateutil import parser as dtp


class InsiderThreatEvaluator:

    def __init__(self, app_config):
        self.scenario_name = "insider_threat"
        self.es_url = app_config.opensearch_url.rstrip("/")
        self.auth = HTTPBasicAuth(app_config.opensearch_user, app_config.opensearch_pass)
        self.es_verify_ssl = app_config.opensearch_verify_ssl

        self.result_index = app_config.scenario_config["insider_threat"]["result_index"]
        self.source_log_index = app_config.scenario_config["insider_threat"]["index_prefix"] + "-*"

        # Labels path: can be a glob like ".../labels/*.csv"
        relative_path = app_config.scenario_config["insider_threat"]["label_csv_path"]
        self.label_csv_glob = Path(__file__).resolve().parents[2] / relative_path

        self.label_rows = self._load_labels()
        self.output_dir = Path("evaluation_results")
        self.output_dir.mkdir(exist_ok=True)
        self.output_file = self.output_dir / f"{self.scenario_name}_detection_results.csv"

    # Public entrypoint
    def run(self) -> Dict:
        print(f"[✓] Evaluating scenario: {self.scenario_name}")

        rows = self._build_all_rows()            # per-event rows with Label/Detected
        metrics = self._compute_metrics(rows)    # TP/FP/FN/TN & scores
        self._write_csv(rows)                    # write exactly what we evaluated

        print(f"[✓] Evaluation complete:\n{json.dumps(metrics, indent=2)}")
        return metrics

    # Labels
    def _load_labels(self) -> List[Dict]:
        rows: List[Dict] = []

        # Resolve glob(s)
        if "*" in str(self.label_csv_glob):
            csv_paths = list(self.label_csv_glob.parent.glob(self.label_csv_glob.name))
        else:
            csv_paths = [self.label_csv_glob]

        for csv_file in csv_paths:
            if not csv_file.exists():
                print(f"[!] Label CSV not found: {csv_file}")
                continue

            print(f"[✓] Loading labels from: {csv_file}")
            with csv_file.open(newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Accept both "%m/%d/%Y %H:%M:%S" and "%m/%d/%Y %H:%M"
                    date_raw = row["date"]
                    try:
                        timestamp = datetime.strptime(date_raw, "%m/%d/%Y %H:%M:%S")
                    except ValueError:
                        timestamp = datetime.strptime(date_raw, "%m/%d/%Y %H:%M")
                    rows.append(
                        {
                            "user": row["user"],
                            "timestamp": timestamp,
                            "date_str": date_raw,  # keep EXACT original string for keying
                        }
                    )
        return rows

    # Build a quick lookup set for (user, date_str)
    def _label_map(self) -> set[Tuple[str, str]]:
        return {(lbl["user"], lbl["date_str"]) for lbl in self.label_rows}

    # ES helpers (scroll)
    def _search(self, index: str, body: Dict, scroll: str = "2m") -> Dict:
        url = f"{self.es_url}/{index}/_search?scroll={scroll}"
        r = requests.post(
            url,
            auth=self.auth,
            headers={"Content-Type": "application/json"},
            data=json.dumps(body),
            verify=self.es_verify_ssl,
        )
        r.raise_for_status()
        return r.json()

    def _scroll(self, scroll_id: str, scroll: str = "2m") -> Dict:
        url = f"{self.es_url}/_search/scroll"
        r = requests.post(
            url,
            auth=self.auth,
            headers={"Content-Type": "application/json"},
            data=json.dumps({"scroll": scroll, "scroll_id": scroll_id}),
            verify=self.es_verify_ssl,
        )
        r.raise_for_status()
        return r.json()

    def _clear_scroll(self, scroll_id: str):
        try:
            url = f"{self.es_url}/_search/scroll"
            requests.delete(
                url,
                auth=self.auth,
                headers={"Content-Type": "application/json"},
                data=json.dumps({"scroll_id": [scroll_id]}),
                verify=self.es_verify_ssl,
                timeout=10,
            )
        except Exception:
            pass  # non-fatal

    def _scan_sources(self, index: str, query: Dict, page_size: int = 5000) -> List[Dict]:
        # Returns ALL _source docs for a given query using the scroll API.
        q = dict(query) if query else {}
        q.setdefault("size", page_size)
        q.setdefault("track_total_hits", True)

        first = self._search(index, q)
        scroll_id = first.get("_scroll_id")
        hits = first.get("hits", {}).get("hits", [])

        sources: List[Dict] = [h["_source"] for h in hits]

        while hits:
            nxt = self._scroll(scroll_id)
            scroll_id = nxt.get("_scroll_id")
            hits = nxt.get("hits", {}).get("hits", [])
            sources.extend(h["_source"] for h in hits)

        if scroll_id:
            self._clear_scroll(scroll_id)

        return sources

    # Data gathering
    def _get_all_source_logs(self) -> List[Dict]:
        print("[✓] Fetching ALL source logs via scroll...")
        return self._scan_sources(
            self.source_log_index,
            {"query": {"match_all": {}}},
            page_size=5000,
        )

    def _get_all_anomalies(self) -> List[Dict]:
        print("[✓] Fetching ALL anomalies via scroll...")
        return self._scan_sources(
            self.result_index,
            {"query": {"range": {"anomaly_grade": {"gt": 0.0}}}},
            page_size=5000,
        )

    # Row building & metrics
    @staticmethod
    def _parse_ts_ms(ts_raw: str) -> Tuple[int, str]:
        # Parse @timestamp (any ISO-ish format). Return (epoch_ms, pretty "YYYY-MM-DD HH:MM:SS").

        dt = dtp.parse(ts_raw)  # timezone-aware if present
        epoch_ms = int(dt.timestamp() * 1000)
        pretty = dt.replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")
        return epoch_ms, pretty

    def _build_detection_windows(self, anomalies: List[Dict]) -> List[Tuple[str, int, int]]:
        # Returns list of (user, start_ms, end_ms) windows.
        windows: List[Tuple[str, int, int]] = []
        missing = 0
        for a in anomalies:
            try:
                user = a["entity"][0]["value"]
                start_ms = int(a["data_start_time"])
                end_ms = int(a["data_end_time"])
                windows.append((user, start_ms, end_ms))
            except Exception:
                missing += 1
        if missing:
            print(f"[i] Skipped {missing} anomaly docs with missing fields.")
        return windows

    @staticmethod
    def _event_in_windows(user: str, ts_ms: int, windows: List[Tuple[str, int, int]]) -> bool:
        for u, start, end in windows:
            if u == user and start <= ts_ms <= end:
                return True
        return False

    def _derive_log_date_if_missing(self, log: Dict) -> str:
        # If source log doesn't have the 'date' field used by labels, derive it from @timestamp as '%m/%d/%Y %H:%M' (minute precision) to match typical label CSV format.
        date_str = log.get("date")
        if date_str:
            return date_str

        ts_raw = log.get("@timestamp")
        if not ts_raw:
            return ""  # no way to match labels

        try:
            dt = dtp.parse(ts_raw)
            return dt.strftime("%m/%d/%Y %H:%M")
        except Exception:
            return ""

    def _build_all_rows(self) -> List[Dict]:
        label_keys = self._label_map()
        all_logs = self._get_all_source_logs()
        anomalies = self._get_all_anomalies()
        windows = self._build_detection_windows(anomalies)

        print("[✓] Building per-event rows...")
        rows: List[Dict] = []

        for log in all_logs:
            user = log.get("user", "UNKNOWN")
            ts_raw = log.get("@timestamp", "")

            # parse timestamp to epoch ms and pretty output
            try:
                ts_ms, ts_pretty = self._parse_ts_ms(ts_raw)
            except Exception:
                # If parsing fails, write raw and consider "not detected"
                ts_ms, ts_pretty = (None, ts_raw[:19].replace("T", " "))

            # Label (ground truth) — match EXACT (user, date_str) as in labels
            date_str = self._derive_log_date_if_missing(log)
            label = "Anomaly" if (user, date_str) in label_keys else "Benign"

            # Detection status — within any anomaly window for this user?
            detected = "Yes" if (ts_ms is not None and self._event_in_windows(user, ts_ms, windows)) else "No"

            rows.append(
                {
                    "User": user,
                    "Timestamp": ts_pretty,
                    "Label": label,
                    "Detected": detected,
                }
            )

        return rows

    @staticmethod
    def _compute_metrics(rows: List[Dict]) -> Dict:
        tp = sum(1 for r in rows if r["Label"] == "Anomaly" and r["Detected"] == "Yes")
        fp = sum(1 for r in rows if r["Label"] == "Benign"  and r["Detected"] == "Yes")
        fn = sum(1 for r in rows if r["Label"] == "Anomaly" and r["Detected"] == "No")
        tn = sum(1 for r in rows if r["Label"] == "Benign"  and r["Detected"] == "No")

        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall    = tp / (tp + fn) if (tp + fn) else 0.0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

        return {
            "Scenario": "insider_threat",
            "TP": tp,
            "FP": fp,
            "FN": fn,
            "TN": tn,
            "Precision": round(precision, 3),
            "Recall (Detection Rate)": round(recall, 3),
            "F1-Score": round(f1, 3),
        }

    def _write_csv(self, rows: List[Dict]) -> None:
        print(f"[✓] Writing full evaluation CSV to: {self.output_file}")
        with self.output_file.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["User", "Timestamp", "Label", "Detected"])
            writer.writeheader()
            writer.writerows(rows)
