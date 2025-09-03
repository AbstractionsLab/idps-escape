# DDoS Detection

## Part 1: Objectives

**Goal**: Detect distributed denial-of-service (DDoS) attacks by analyzing traffic flow anomalies using flow-level features (packet rate, SYN flags, etc.).

**Example Scenario**: A SYN flood attack begins targeting a public-facing web server. Suddenly, the number of incoming packets per second spikes, SYN flag counts increase dramatically, and the server is overwhelmed by half-open connections. This deviates from normal traffic patterns, which are stable and predictable during regular hours. For instance, a web server normally receives 200 requests/minute, but under attack, this reaches 10,000/minute, mostly SYNs without completing handshakes.

## Part 2: Data preparation and ingestion

### 2.1 Dataset ingestion

To simulate today's DDoS traffic data and feed it into Wazuh Anomaly Detection, we use a date-shifting ingestion script located in `ddos_detection/wazuh_ingest.py`. Run it from the `soar-radar` root:

```bash
python3 ./ddos_detection/wazuh_ingest.py
```

- **What it does:**
    - Reads the single-day SYN flood CSV
    - Shifts each event’s timestamp to today
    - Extracts `@timestamp` (ISO), and `event_hour`
    - Indexes the documents into `wazuh-ad-ddos-detection-YYYY.MM.DD`

### 2.2 Index pattern & Wazuh integration

1. In **Dashboards Management**, create an **Index Pattern** for `wazuh-ad-ddos-detection-*`
2. Confirm in **Discover** that events are ingested with:
    - `@timestamp` (datetime)
    - `Source_IP`, `Destination_IP`, and traffic features (e.g., `Flow_Packets_s`, `SYN_Flag_Count`)

## Part 3: Detector & feature configuration

### 3.1 Create the Anomaly Detector

1. Navigate to **OpenSearch Plugins ➔ Anomaly Detection** in Wazuh Dashboards
2. Click **Create detector**:
    - **Name:** `ddos-detector`
    - **Description:** "Detect abnormal traffic rates per host"
    - **Index:** `wazuh-ad-ddos-detection-*`
    - **Time field:** `@timestamp`
    - **Detection interval:** `5m` with `1m` window delay
    - **Detector type:** Real-time (continuous)
    - **Custom result index:** opensearch-ad-plugin-result-ddos_detection (!important)

### 3.2 Define numerical features

- `flow_packets_per_second` – average – field: `Flow_Packets_s`
    - Detects bursty request patterns
- `flow_bytes_per_second` – average – field: `Flow_Bytes_s`
    - Captures payload volume in high-load attacks
- `syn_flag_count` – sum – field: `SYN_Flag_Count`
    - High SYN without ACKs signals SYN flood
- `packet_length_average` – average – field: `Packet_Length_Mean`
    - Detects uniformity of packet sizes
- `total_bwd_packets` – average – field: `Total_Backward_Packets`
    - Low value signals unresponded traffic (in SYN floods)

### 3.3 Enable categorical field (per-host modelling)

Enable the **Categorical field** option and select `Destination_IP.keyword`.

This builds a separate anomaly model per destination IP (victim). Each host is monitored independently, allowing for better sensitivity to changes in its own traffic pattern.

### 3.4 Save and validate

Click **Next** and **Create**. The detector validates features and starts model training.

## Part 4: Monitor, Webhook & Wazuh rule integration

### 4.1 Create an OpenSearch monitor

1. In the `ddos-detector` page, click **Set up alert**
2. Add a **Trigger**:
    - **Name:** `DDoS-Detected`
    - **Severity:** High
    - **Condition:**

```
anomaly_grade >= 0.8 and confidence >= 0.85
```

1. Add a Notification Channel:
    - **Type:** Custom webhook
    - **URL:** `http://<wazuh-manager>:8888/opensearch-alert`
2. **Message (JSON):**

```json
{
  "monitor": {"name": "{{ctx.monitor.name}}"},
  "trigger": {"name": "{{ctx.trigger.name}}"},
  "entity": "{{ctx.results.0.hits.hits.0._source.entity.0.value}}",
  "periodStart": "{{ctx.periodStart}}",
  "periodEnd": "{{ctx.periodEnd}}"
}
```

### 4.2 Webhook logging

Deploy the `ad_alerts_webhook.py` listener from `webhook/` in the Wazuh manager:

```bash
python3 webhook/ad_alerts_webhook.py
```

Log file: `/var/log/ad_alerts.log`

Configure Wazuh to watch it:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/ad_alerts.log</location>
</localfile>
```

### 4.3 Decoder & rule

### **4.3.1 Local decoder**

Add the content of the file `local_decoder.xml` in this repository into the file `/var/ossec/etc/decoders/local_decoder.xml` in the Wazuh manager.

### **4.3.2 Local rules**

Add the content of the file `local_rules.xml` in this repository into the file `/var/ossec/etc/rules/local_rules.xml` in the Wazuh manager.

- **Restart** Wazuh manager (`var/ossec/bin/wazuh-control restart` in Docker or `systemctl restart wazuh-manager`).
- This ensures rule 100303 fires whenever our webhook writes a matching line to `/var/log/ad_alerts.log`.

### 4.4 Manager-side active response

1. Register the script in `ossec.conf`:

```xml
<command>
  <name>ad_enrich</name>
  <executable>ad_context_ddos_active_response.py</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <disabled>no</disabled>
  <command>ad_enrich</command>
  <location>server</location>
  <rules_id>100303</rules_id>
  <timeout>120</timeout>
</active-response>
```

1. Copy `ad_context_ddos_active_response.py` to `/var/ossec/active-response/bin` and make executable.
2. Install `requests` module.

```bash
pip3 install requests
```

3. Give permissions for execution:

```bash
chmod 750 /var/ossec/active-response/bin/ad_context_ddos_active_response.py
chown root:wazuh /var/ossec/active-response/bin/ad_context_ddos_active_response.py
```

4. Restart Wazuh Manager.

```bash
/var/ossec/bin/wazuh-control restart
```

### 4.5 Agent-side active response

To prepare Wazuh agents to handle contextual logging and active defense during DDoS detection:

1. **Enable remote commands**

Edit (or create if missing) the file:

```
/var/ossec/etc/local_internal_options.conf
```

Add the following line:

```
wazuh_command.remote_commands=1
```

2. **Create log files for agent enrichment**

```bash
sudo touch /var/ossec/logs/ad_pc_enriched.log
sudo chown root:wazuh /var/ossec/logs/ad_pc_enriched.log
sudo chmod 664 /var/ossec/logs/ad_pc_enriched.log
```

3. **Deploy agent-side scripts**

Copy the scripts to the agent's AR directory:

```bash
sudo cp write_contextual_logs_ddos_active_response.sh /var/ossec/active-response/bin/
sudo cp rate_limit.sh /var/ossec/active-response/bin/
```

4. **Set correct permissions**

```bash
sudo chown root:wazuh /var/ossec/active-response/bin/write_contextual_logs_ddos_active_response.sh
sudo chmod 750 /var/ossec/active-response/bin/write_contextual_logs_ddos_active_response.sh

sudo chown root:wazuh /var/ossec/active-response/bin/rate_limit.sh
sudo chmod 750 /var/ossec/active-response/bin/rate_limit.sh
```

5. **Register commands in `ossec.conf`**

Edit the agent’s `/var/ossec/etc/ossec.conf` and ensure the following is added inside `<ossec_config>`:

```xml
<command>
  <name>write_contextual_logs_ddos_active_response.sh</name>
  <executable>write_contextual_logs_ddos_active_response.sh</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<command>
  <name>rate_limit.sh</name>
  <executable>rate_limit.sh</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>
```

6. **Restart the Agent**

```bash
sudo systemctl restart wazuh-agent
```

This completes the setup for executing rate limiting, firewall dropping, and logging actions on agents when a DDoS anomaly is detected.

## Part 5: Active response analysis

To minimize the operational risk while still responding decisively to confirmed threats, this setup implements a **two-tier active response strategy** for DDoS:

### Tier 1 – Contextual logging & rate limiting
**Trigger condition:**
- anomaly_grade ≥ 0.8
- confidence ≥ 0.85

**Response actions:**
- Execute `write_contextual_logs_ddos_active_response.sh` to store detailed traffic data from each source IP into `ad_pc_enriched.log` for later analysis.
- Execute `rate_limit.sh` to apply `iptables`-based rate limiting for the source IPs that participated in the anomaly window.

This tier prioritizes observation and mitigation without outright denial of traffic, helping analysts assess intent before escalation.

### Tier 2 – Traffic blocking
**Trigger Condition:**
- anomaly_grade ≥ 0.95
- confidence ≥ 0.95

**Response actions:**
- Execute `firewall_drop.sh` to block offending IPs at the `iptables` level via a DROP rule.

This level is reserved for confirmed, high-confidence DDoS attacks.

### 5.1 Active response flow breakdown

- **Receive trigger parameters:**
  - Destination IP (victim IP): `ip_keyword`
  - Anomaly window start: `period_start`
  - Anomaly window end: `period_end`

- **Query events:**
  The server-side script queries OpenSearch for all flow logs matching the anomaly window and destination IP.

- **Resolve agent:**
  From the destination IP, the system maps to a Wazuh agent using the API. This becomes the enforcement point.

- **Identify source IPs:**
  The script extracts all unique `Source_IP` fields from the matched flows — these are potential attackers.

- **Send Tiered Commands:**
  For each `Source_IP`:
    - Tier 1 → `rate_limit.sh`
    - Tier 2 (if configured) → `firewall_drop.sh`

- **Log Enrichment:**
  Additionally, one contextual log is sent to the agent via `write_contextual_logs_ddos_active_response.sh` for the entire event set.

- **Result Logging:**
  Each action’s outcome is logged in the manager for auditing.

### 5.2 Rate Limiting on WSL

Since `hashlimit` is unsupported on WSL, the script falls back to `limit` with per-IP filtering. Example inserted rule:

```
ACCEPT tcp -- 172.16.0.9 0.0.0.0/0 tcp dpt:80 limit: avg 20/min burst 10
```

### 5.3 Cleanup & Reversion

Rules can be removed via:

```bash
sudo iptables -D INPUT <rule-number>
```

## Part 6.Risk Analysis

In a scenario where a public-facing web server is subjected to a SYN‑flood or volumetric DDoS attack, we model the risk using the classical risk formulation:

```
R = C × I
```

Here, `C` is the anomaly detection model's confidence score, used as a direct proxy for the likelihood of a genuine attack, and `I` is the impact severity, determined via the Common Vulnerability Scoring System (CVSS). Although CVSS traditionally applies to software vulnerabilities, its framework for quantifying impact via the Confidentiality‑Integrity‑Availability (CIA) triad has been adapted in research to assess the severity of denial‑of‑service incidents based on availability impact .

In the DDoS scenario, the characteristics are:

- **Availability loss**: Complete, due to overwhelming traffic and half‑open TCP connections.
- **Confidentiality / Integrity**: Minimal direct impact since there is no data compromise or modification.

This aligns with a high‑severity profile under CVSS, reflected in documented examples where a full denial of service yields a **Base Score ≈ 9.0** . Accordingly, we assign:

```
I = 9.0
```

Thus, the risk score computes as:

```
R = C × 9.0
```

Under this tiering scheme, high-confidence detections of traffic anomalies that suggest a volumetric flood generate elevated risk scores (close to 9.0) and should typically fall into **Tier 3**, prompting immediate mitigation. This methodology ensures that alert prioritization remains statistically grounded, transparent, and aligned with the classical risk principle *Likelihood × Impact*, applying detection certainty and standardized severity consistently across distinct threat types.


## Part 7: Dataset

The dataset used is the **CIC-DDoS2019** dataset, specifically the **SYN flood** CSVs. These are publicly available from [https://www.unb.ca/cic/datasets/ddos-2019.html](https://www.unb.ca/cic/datasets/ddos-2019.html). The data was shifted and ingested to simulate modern traffic patterns for anomaly-based detection.