from setup.config_loader import AppConfig

class OpenSearchConfig:
    def __init__(self, app_config: AppConfig):
        self.opensearch_url = app_config.opensearch_url
        self.opensearch_auth = (app_config.opensearch_user, app_config.opensearch_pass)
        self.opensearch_verify_ssl = False if app_config.opensearch_verify_ssl=="False" else app_config.opensearch_verify_ssl
        self.wazuh_url = app_config.wazuh_url
        self.wazuh_auth = (app_config.wazuh_username, app_config.wazuh_password)
        self.wazuh_verify_ssl = False if app_config.wazuh_verify_ssl=="False" else app_config.wazuh_verify_ssl
        self.headers = {
            "Content-Type": "application/json",
            "osd-xsrf": "true"
        }
        self.webhook_name = "RADAR"
        self.webhook_url = app_config.webhook_url  # Can optionally come from YAML if needed

