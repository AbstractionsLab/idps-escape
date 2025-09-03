# radar-test-framework/setup/config_loader.py
import os
import yaml
from dotenv import load_dotenv
from dataclasses import dataclass

load_dotenv()  # Load from .env

@dataclass
class AppConfig:
    opensearch_url: str
    opensearch_user: str
    opensearch_pass: str
    opensearch_verify_ssl: str
    keycloak_base_url: str
    keycloak_admin_user: str
    keycloak_admin_pass: str
    keycloak_username: str
    keycloak_password: str
    keycloak_realm: str
    geoip_db_path: str
    log_dir: str
    scenario_config: dict
    default_scenario: str
    wazuh_url: str
    wazuh_username: str
    wazuh_password: str
    wazuh_verify_ssl: str
    webhook_name: str
    webhook_url: str


def load_config(yaml_path: str = "config.yaml") -> AppConfig:
    with open(yaml_path, "r") as f:
        yaml_config = yaml.safe_load(f)

    return AppConfig(
        opensearch_url=os.getenv("OPENSEARCH_URL"),
        opensearch_user=os.getenv("OPENSEARCH_USER"),
        opensearch_pass=os.getenv("OPENSEARCH_PASS"),
        opensearch_verify_ssl=os.getenv("OPENSEARCH_VERIFY_SSL"),
        keycloak_base_url=os.getenv("KEYCLOAK_BASE_URL"),
        keycloak_admin_user=os.getenv("KEYCLOAK_ADMIN_USER"),
        keycloak_admin_pass=os.getenv("KEYCLOAK_ADMIN_PASS"),
        keycloak_username=os.getenv("KEYCLOAK_USERNAME"),
        keycloak_password=os.getenv("KEYCLOAK_PASSWORD"),
        keycloak_realm=os.getenv("KEYCLOAK_REALM"),
        geoip_db_path=os.getenv("GEOIP_DB_PATH"),
        log_dir=os.getenv("LOG_DIR"),
        wazuh_url=os.getenv("WAZUH_URL"),
        wazuh_username=os.getenv("WAZUH_USER"),
        wazuh_password=os.getenv("WAZUH_PASS"),
        wazuh_verify_ssl=os.getenv("WAZUH_VERIFY_SSL"),
        webhook_name=os.getenv("WEBHOOK"),
        webhook_url=os.getenv("WEBHOOK_URL"),
        scenario_config=yaml_config["scenarios"],
        default_scenario=yaml_config.get("default_scenario", "insider_threat"),
    )
