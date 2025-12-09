FROM wazuh/wazuh-dashboard:4.12.0

USER root

RUN /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin install anomalyDetectionDashboards --allow-root

USER wazuh-dashboard
