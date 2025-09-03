import requests
import json
import yaml
import os
from setup.opensearch_config import OpenSearchConfig
from setup.webhook import WebhookManager

class MonitorManager:
    def __init__(self, scenario_config, detector_id: str, config: OpenSearchConfig):
        self.config = config
        self.scenario_config = scenario_config
        self.detector_id = detector_id

    def get_monitor_id_by_name(self, monitor_name):
        url = f"{self.config.wazuh_url}/api/alerting/monitors/_search"
        body = {
            "query": {
                "term": {
                    "name.keyword": monitor_name
                }
            }
        }

        response = requests.post(
            url,
            auth=self.config.wazuh_auth,
            headers=self.config.headers,
            json=body,
            verify=self.config.wazuh_verify_ssl
        )

        if response.status_code == 200:
            hits = response.json().get("hits", {}).get("hits", [])
            for hit in hits:
                if hit["_source"]["name"] == monitor_name:
                    monitor_id = hit["_id"]
                    print(f"[✓] Monitor '{monitor_name}' already exists with ID: {monitor_id}")
                    return monitor_id
        else:
            print(f"[!] Failed to search for monitor '{monitor_name}': {response.status_code}")
            print(response.text)

        return None

    def create_monitor(self):
        monitor_name = self.scenario_config["monitor_name"]
        existing_id = self.get_monitor_id_by_name(monitor_name)
        if existing_id:
            return existing_id
        trigger_name = self.scenario_config["trigger_name"]
        anomaly_grade_threshold = self.scenario_config["anomaly_grade_threshold"]
        confidence_threshold = self.scenario_config["confidence_threshold"]
        webhook = WebhookManager(self.config)
        webhook_id = webhook.create_webhook()

        payload = {
            "name": monitor_name,
            "type": "monitor",
            "monitor_type": "query_level_monitor",
            "enabled": True,
            "schedule": {
                "period": {"interval": 2, "unit": "MINUTES"}
            },
            "inputs": [
                {
                    "search": {
                        "indices": [".opendistro-anomaly-results*"],
                        "query": {
                            "size": 1,
                            "sort": [
                                {"anomaly_grade": "desc"},
                                {"confidence": "desc"}
                            ],
                            "query": {
                                "bool": {
                                    "filter": [
                                        {"range": {
                                            "execution_end_time": {
                                                "from": "{{period_end}}||-2m",
                                                "to": "{{period_end}}",
                                                "include_lower": True,
                                                "include_upper": True
                                            }
                                        }},
                                        {"term": {"detector_id": {"value": self.detector_id}}}
                                    ]
                                }
                            },
                            "aggregations": {
                                "max_anomaly_grade": {
                                    "max": {"field": "anomaly_grade"}
                                }
                            }
                        }
                    }
                }
            ],
            "triggers": [
                {
                    "name": trigger_name,
                    "severity": "1",
                    "condition": {
                        "script": {
                            "lang": "painless",
                            "source": f"return ctx.results != null && ctx.results.length > 0 && ctx.results[0].aggregations != null && ctx.results[0].aggregations.max_anomaly_grade != null && ctx.results[0].hits.total.value > 0 && ctx.results[0].hits.hits[0]._source != null && ctx.results[0].hits.hits[0]._source.confidence != null && ctx.results[0].aggregations.max_anomaly_grade.value != null && ctx.results[0].aggregations.max_anomaly_grade.value > {anomaly_grade_threshold} && ctx.results[0].hits.hits[0]._source.confidence > {confidence_threshold}"
                        }
                    },
                    "actions": [
                        {
                            "name": self.config.webhook_name,
                            "destination_id": webhook_id,
                            "subject_template": {
                                "lang": "mustache",
                                "source": "Alerting Notification action"
                            },
                            "message_template": {
                                "lang": "mustache",
                                "source": json.dumps({
                                    "monitor": {"name": "{{ctx.monitor.name}}"},
                                    "trigger": {"name": "{{ctx.trigger.name}}"},
                                    "entity": "{{ctx.results.0.hits.hits.0._source.entity.0.value}}",
                                    "periodStart": "{{ctx.periodStart}}",
                                    "periodEnd": "{{ctx.periodEnd}}"
                                })
                            },
                            "throttle_enabled": False
                        }
                    ]
                }
            ]
        }

        print(f"[+] Creating monitor '{monitor_name}'")
        response = requests.post(
            f"{self.config.wazuh_url}/api/alerting/monitors",
            auth=self.config.wazuh_auth,
            headers=self.config.headers,
            json=payload,
            verify=self.config.wazuh_verify_ssl
        )

        if response.status_code == 200:
            print(f"[✓] Monitor created successfully: {monitor_name}")
            return response.json().get("_id")
        else:
            print(f"[!] Failed to create monitor: {response.status_code}\n{response.text}")
            return None
