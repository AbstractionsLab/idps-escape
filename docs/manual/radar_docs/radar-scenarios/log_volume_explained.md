# Log volume growth detection

## Objectives

**Example scenario:** Each endpoint normally generates a relatively stable amount of log data under `/var/log/`. A sudden and unexplained spike in log volume can indicate malware activity, brute-force attempts, unauthorized processes, or system misuse. This scenario continuously monitors the raw size of the `/var/log` directory and identifies abnormal growth based on the endpoint’s own historical baseline.

Goal: Detect unusually high log volume on any endpoint, generate alerts, and enable automated responses such as email notifications or integration with SOAR workflows.

---

## Behavior-based approach

### Detection

The detection process is implemented using these components:

1. **Local metric collection** A systemd timer, installed once at agent onboarding time (automatically by `bootstrap-agent.sh --group log_volume`), runs `du -sb /var/log` every 30 seconds and appends a syslog-formatted line to a fixed local file (`/var/log/radar/log_volume_metric.log`). This deliberately avoids Wazuh's `full_command` mechanism in the group's `agent.conf`. 
2. **Agent config** (`scenarios/agent_configs/log_volume/radar-log-volume-agent-snippet.xml`, delivered via the `log_volume` group) — an ordinary `<localfile>` watching that fixed path.
3. **Custom decoders** (`scenarios/decoders/log_volume/0001-log-volume.xml`) extract `log_path`/`log_bytes` from the collected line.
4. An **OpenSearch Anomaly Detector** uses `log_bytes` over time to detect spikes.

---

### Active Response Analysis

Active responses handle detected suspicious events:

- **Email Notification (`/radar/scenarios/active_responses/radar_ar.py`)**
    - Sends alert emails when a scenario rule is triggered.

### Manual setup

We distinguish between:

- **Agent side**
- **Manager side** (Wazuh manager where decoders, rules, and active responses live)
- **Wazuh Dashboard / OpenSearch** configuration

#### Prerequisites

- A functioning Wazuh deployment (manager and agents). For deployment instructions, refer to the [SOAR RADAR README](/radar/README.md).

#### Agent-side configuration

If the agent was onboarded with `bootstrap-agent.sh --group log_volume` (recommended), this is done automatically — the script installs the systemd timer below, and the `log_volume` group's own `agent.conf` configures Wazuh to watch the resulting file. The steps below are only needed for a fully manual setup.

1. Install the local metric collector, once, as root:
```bash
mkdir -p /var/log/radar
chmod 0755 /var/log/radar

cat > /usr/local/bin/radar-log-volume-metric.sh << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
LOG_FILE="/var/log/radar/log_volume_metric.log"
BYTES=$(du -sb /var/log 2>/dev/null | awk '{print $1}')
printf '%s %s log_volume_metric: /var/log %s\n' \
  "$(date '+%b %d %H:%M:%S')" "$(hostname)" "${BYTES:-0}" >> "$LOG_FILE"
EOF
chown root:root /usr/local/bin/radar-log-volume-metric.sh
chmod 0750 /usr/local/bin/radar-log-volume-metric.sh
```

2. Install and start the systemd timer that runs it every 30 seconds:
```bash
cat > /etc/systemd/system/radar-log-volume.service << 'EOF'
[Unit]
Description=RADAR log_volume metric collector (one-shot)

[Service]
Type=oneshot
ExecStart=/usr/local/bin/radar-log-volume-metric.sh
EOF

cat > /etc/systemd/system/radar-log-volume.timer << 'EOF'
[Unit]
Description=Run the RADAR log_volume metric collector every 30 seconds

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
Unit=radar-log-volume.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now radar-log-volume.timer
```

3. Configure the Wazuh agent to watch the resulting file:
```
nano /var/ossec/etc/ossec.conf
```
And paste the content of `/radar/scenarios/agent_configs/log_volume/radar-log-volume-agent-snippet.xml` inside of `<ossec_config>` tag.

4. Restart the agent:
```
systemctl restart wazuh-agent
```

A logrotate config is recommended too, to keep `/var/log/radar/log_volume_metric.log` from growing unbounded.

#### Manager-side configuration

1. Copy the files in `/radar/scenarios/decoders/log_volume` into the `/var/ossec/etc/decoders/`
2. Copy the files in `/radar/scenarios/rules/log_volume` into the `/var/ossec/etc/rules/`
3. Configure active response scripts.
```
cp /radar/scenarios/active_responses/radar_ar.py /var/ossec/active-response/bin/radar_ar.py
chmod 750 /var/ossec/active-response/bin/radar_ar.py
chown root:wazuh /var/ossec/active-response/bin/radar_ar.py
```
4. Configure commands and active responses by copying the content of `/radar/scenarios/ossec/radar-log-volume-ossec-snippet.xml` into the end of `/var/ossec/etc/ossec.conf` under `<ossec_config>` tag.
5. Restart the manager:
```
/var/ossec/bin/wazuh-control restart
```

#### Wazuh Dashboard / Opensearch

##### Create the Anomaly Detector

1. Ensure that `data.log_bytes` in index `wazuh-ad-log-volume-*` is a numerical field in **Index Management** Menu.
2. **Navigate** in Wazuh Dashboards to **OpenSearch Plugins ➔ Anomaly Detection**.
3. Click **Create detector** and fill out:
    - **Name:** `log_volume-detector`
    - **Description:** “Monitor log volume per endpoint”
    - **Index:** `wazuh-ad-log-volume-*`
    - **Time field:** `@timestamp`
    - **Detection interval:** `5m` (with `1m` window delay)
    - **Detector type:** Real-time (continuous)
    - **Custom result index:** opensearch-ad-plugin-result-log-volume (!important)

---

##### Define Features

| Feature name | Method | Field | Notes |
| --- | --- | --- | --- |
| `max_log_bytes` | `max` | `data.log_bytes` | Maximum value of the log_bytes in the given detection interval |

---

##### Enable Categorical Field (per-endpoint modelling)

Under **Categorical field**, select the agent identifier `agent.name.keyword`.

This ensures each endpoint gets its own statistical model.

**Note:** The categorical field in the UI documentation shows `agent.name.keyword`, while `config.yaml` shows `agent.name` without the `.keyword` suffix. OpenSearch automatically uses the keyword field type for categorical fields when available, so both forms are functionally equivalent.

---

##### Saving & Validation

Click **Next** to **Review**.

- The UI will validate your feature expressions and show sample anomaly scores if enough history exists.
- Click **Create** to finalize.


### Monitor and Webhook

#### Create Webhook

This [webhook](/radar/webhook/README.md) is a simple Flask application that receives the monitor's payload and appends a single line to `/var/log/ad_alerts.log`. To deploy the webhook in the Wazuh manager:

1. Copy the [ad_alerts_webhook.py](/radar/webhook/ad_alerts_webhook.py) file from this repository into the Wazuh manager to a custom wazuh_webhook directory.
2. Ensure execution permissions: 
```bash
chmod +x ad_alerts_webhook.py
```
3. Run under a python3:
```bash
python3 ad_alerts_webhook.py
```
4. The resulted log file should be monitored by Wazuh, thus `/var/ossec/etc/ossec.conf` needs to be configured:
```xml
<localfile>
    <log_format>syslog</log_format>
    <location>/var/log/ad_alerts.log</location>
</localfile>
```

#### Create an OpenSearch Monitor

In `log_volume-detector` Anomaly overview, set up alert: 

1. This will create a monitor log_volume-detector-Monitor, which will create an alert when an anomaly is detected.
2. **Trigger Configuration: Add trigger**
    - **Trigger name:** `LogVolume-Growth-Detected`
    - **Severity:** High
    - **Condition:**
    
    When choosing thresholds for firing alerts, you must balance **sensitivity** (catching real threats) against **precision** (avoiding false positives). A balanced strategy is to require:
    
    - **anomaly_grade ≥ 0.5:** captures the upper quintile of deviations without triggering on mild fluctuations, and
    - **confidence ≥ 0.5:** ensures the model has seen enough data to trust its grade.
    
3. Before following with an action, create a Notification Channel in Wazuh. Go to Menu, navigate to Notifications under Explore. And create a Channel:
    - **Name**: RADAR
    - **Channel type:** Custom webhook
    - **Method:** POST
    - **Webhook URL:** [http://\<wazuh-manager\>:8080/notify]
4. **Action**
    - **Action name:** `RADAR`
    - **Channel**: RADAR
    - **Message (must be JSON)**
        
        ```
        {
          "monitor": {
            "name": "{{ctx.monitor.name}}"
          },
          "trigger": {
            "name": "{{ctx.trigger.name}}"
          },
          "entity": "{{ctx.results.0.hits.hits.0._source.entity.0.value}}",
          "periodStart": "{{ctx.periodStart}}",
          "periodEnd":   "{{ctx.periodEnd}}"
        }
        ```
        
When the condition is met, this monitor will send structured JSON to the webhook.
