import requests
import json
from setup.opensearch_config import (OpenSearchConfig)

class WebhookManager:
    def __init__(self, config: OpenSearchConfig):
        self.config = config

    def webhook_exists(self) -> str:
        """Check if webhook with the given name exists and return its config_id."""

        response = requests.get(
            f"{self.config.wazuh_url}/api/notifications",
            auth=self.config.wazuh_auth,
            headers=self.config.headers,
            verify=self.config.wazuh_verify_ssl
        )

        if response.status_code != 200:
            print(f"[!] Failed to list existing webhooks: {response.status_code}")
            print(response.text)
            return ""

        resp_configs = response.json().get("data", {}).get("items", [])
        for resp_config in resp_configs:
            if resp_config.get("name") == self.config.webhook_name:
                config_id = resp_config.get("id", "")
                print(f"[✓] Webhook '{self.config.webhook_name}' already exists with ID: {config_id}")
                return config_id

        return ""

    def create_webhook(self) -> str:
        existing_id = self.webhook_exists()
        if existing_id:
            return existing_id

        payload = {
            "config": {
                "name": self.config.webhook_name,
                "description": "",
                "config_type": "webhook",
                "is_enabled": True,
                "webhook": {
                    "url": self.config.webhook_url,
                    "header_params": {
                        "Content-Type": "application/json"
                    },
                    "method": "POST"
                }
            }
        }

        print(f"[+] Creating webhook '{self.config.webhook_name}'...")

        response = requests.post(
            f"{self.config.wazuh_url}/api/notifications/create_config",
            auth=self.config.wazuh_auth,
            headers=self.config.headers,
            data=json.dumps(payload),
            verify=self.config.wazuh_verify_ssl
        )

        if response.status_code == 200:
            print(f"[✓] Webhook '{self.config.webhook_name}' created successfully.")
            return response.json().get("config_id", "")
        else:
            print(f"[!] Failed to create webhook: {response.status_code}")
            print(response.text)
            return ""
