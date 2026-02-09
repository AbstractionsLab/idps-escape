# OpenSearch AD plugin in Wazuh

> Note: starting from v0.6, our RADAR deployment solution automatically installs the AD plugin.

While you can follow the official instructions on the [Wazuh blog post](https://wazuh.com/blog/enhancing-it-security-with-anomaly-detection/) describing the integration of [the OpenSearch AD plugin](https://github.com/opensearch-project/anomaly-detection), if you wish to adopt a Docker-based model, you can follow the instructions below.

## Integration steps overview

1. **Docker Environment Setup**  
   Wazuh (indexer, manager, and dashboard) can be deployed using Docker (see our [manual](./wazuh/wazuh_installation.md)). This is a common practice for containerized environments.
2. **Accessing the Wazuh Dashboard container**  
   You need to access the Wazuh Dashboard container to install the Anomaly Detection plugin. This is done using the following commands:
   - List running containers:  
     ```bash
     sudo docker ps
     ```
   - Access the container:  
     ```bash
     sudo docker exec -it {container_id} bash
     ```
   - Inside the container, install the Anomaly Detection plugin:  
     ```bash
     /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin install anomalyDetectionDashboards
     ```
   - Exit the container and restart it:  
     ```bash
     exit
     sudo docker restart {container_id}
     ```
   - After restart, you can verify the plugin is installed:  
     ```bash
     sudo -u wazuh-dashboard /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin list
     ```
     The `anomalyDetectionDashboards` plugin should appear in the list.
3. **Using the Plugin in Wazuh**  
   Once installed and enabled, you can configure anomaly detection monitors and alerts within the Wazuh dashboard. The plugin uses the Random Cut Forest (RCF) algorithm to detect anomalies in near real-time, and you can pair it with the Alerting plugin for notifications.

### Summary table

| Step | Description |
|------|-------------|
| 1    | Deploy Wazuh (indexer, manager, dashboard) with Docker |
| 2    | Access the Wazuh Dashboard container |
| 3    | Install the OpenSearch Anomaly Detection plugin |
| 4    | Restart the container and verify plugin installation |
| 5    | Configure anomaly detection and alerting in the dashboard |

## Additional notes

- **Compatibility:** The steps above are confirmed to work with Wazuh versions based on OpenSearch (e.g., Wazuh 4.8.0 with OpenSearch 2.10.0).
- **Troubleshooting:** If you encounter connectivity issues (e.g., `getaddrinfo ENOTFOUND wazuh.indexer`), ensure that all required containers are running and properly networked.
- **Use cases:** Integrating the Anomaly Detection plugin allows you to detect suspicious activities, such as spikes in failed login attempts, and receive timely alerts; see our [RADAR](/radar/README.md) page for more details.