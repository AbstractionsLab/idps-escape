import requests
import json
import yaml
import os
from setup.opensearch_config import OpenSearchConfig

class DetectorManager:
    def __init__(self, config: OpenSearchConfig):
        self.config = config

    def get_detector_id_by_name(self, name):
        url = f"{self.config.opensearch_url}/_plugins/_anomaly_detection/detectors/_search"
        body = {
            "query": {
                "term": {
                    "name.keyword": name
                }
            }
        }
        try:
            response = requests.post(url, auth=self.config.opensearch_auth, headers=self.config.headers,
                                     data=json.dumps(body), verify=self.config.opensearch_verify_ssl)
            response.raise_for_status()
            hits = response.json().get("hits", {}).get("hits", [])
            if hits:
                detector_id = hits[0]["_id"]
                print(f"[✓] Detector '{name}' already exists with ID: {detector_id}")
                return detector_id
            else:
                return None
        except Exception as e:
            print(f"[!] Error searching for detector: {e}")
            return None

    def create_detector(self, index_name, time_field, feature_attributes, categorical_field,
                        detector_interval=5, detector_delay=1, result_index="opensearch-ad-plugin-result-scenario",
                        name="detector", description="AD Detector"):
        existing_id = self.get_detector_id_by_name(name)
        if existing_id:
            return existing_id

        url = f"{self.config.opensearch_url}/_plugins/_anomaly_detection/detectors"

        body = {
            "name": name,
            "description": description,
            "time_field": time_field,
            "indices": [index_name],
            "filter_query": {"bool": {"filter": [{"term": {"Login Successful.keyword": "True"}}]}},
            "feature_attributes": feature_attributes,
            "detection_interval": {
                "period": {"interval": detector_interval, "unit": "Minutes"}
            },
            "window_delay": {
                "period": {"interval": detector_delay, "unit": "Minutes"}
            },
            "category_field": [categorical_field],
            "result_index": f"{result_index}",
            "rules": []
        }

        response = requests.post(url, auth=self.config.opensearch_auth, headers=self.config.headers,
                                 data=json.dumps(body), verify=self.config.opensearch_verify_ssl)

        if response.status_code == 201:
            detector_id = response.json()['_id']
            print(f"[+] Created detector: {name} with ID: {detector_id}")
            return detector_id
        else:
            print("[-] Failed to create detector:", response.text)
            return None

    def start_detector(self, detector_id):
        url = f"{self.config.opensearch_url}/_plugins/_anomaly_detection/detectors/{detector_id}/_start"
        try:
            response = requests.post(url, auth=self.config.opensearch_auth, headers=self.config.headers,
                                     verify=self.config.opensearch_verify_ssl)
            response.raise_for_status()

            if response.status_code == 200:
                print(f"[✓] Detector started successfully (ID: {detector_id})")
                return True
            else:
                print(f"[!] Failed to start detector: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            print(f"[!] Exception while starting detector: {e}")
            return False