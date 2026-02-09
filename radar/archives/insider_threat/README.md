# Insider threat

## Part 1: Objectives

**Example Scenario:** A privileged employee starts accessing an abnormal number of confidential files outside business hours and copying data to an external drive. This deviates from their normal behavior and may signal malicious intent or account compromise. For instance, a database administrator who typically queries customer records during the day is now running massive exports at midnight, or an engineer is downloading an unusual volume of sensitive documents not related to their project.

**Categorical features:** To enhance detection, categorize anomalies by user or user attributes. Enabling a **category field** for the username (or user ID) ensures the anomaly model learns a separate baseline for each user. This way, one user’s normal activity does not mask another’s outliers. Additional categorical dimensions could include user department or role (if such metadata can be appended to log events), as insider threats often stand out when compared to peers. Essentially, we want to “slice” the data per user for UEBA, so that anomalies are detected relative to each user’s own typical behavior.

## Part 2: Data preparation and ingestion

### 2.1 Dataset ingestion

To simulate today's data and feed it to the Wazuh AD plugin, we shift each file’s dates into the last five days. The script is located in `insider-threat/wazuh_ingest.py`. Run it from the `soar-radar` folder:

```bash
python3 ./insider-threat/wazuh_ingest.py
```

- **What it does:**
    - Iterates offsets **–5…+5**
    - Shifts each event’s date to `today + offset`
    - Enriches with `@timestamp` (ISO), `event_hour`, `content_bytes`
    - Bulk‐indexes into daily indices like `wazuh-ad-insider-threat-2025.06.07`

### 2.3 Index Pattern & Wazuh Integration

1. In **Dashboards Management**, create an **Index Pattern** for `wazuh-ad-insider-threat-*`.
2. Confirm that documents appear in **Discover** with fields:
    - `@timestamp` (date)
    - `user` (string)
    - `pc`, `filename`, `content_bytes`, etc.

## Part 3: Detector & Feature Configuration

### 3.1 Create the Anomaly Detector

1. **Navigate** in Wazuh Dashboards to **OpenSearch Plugins ➔ Anomaly Detection**.
2. Click **Create detector** and update the fields as follows:
    - **Name:** `insider-threat-detector`
    - **Description:** “Monitor per-user file access & data volume”
    - **Index:** `wazuh-ad-insider-threat-*`
    - **Time field:** `@timestamp`
    - **Detection interval:** `5m` (with `1m` window delay)
    - **Detector type:** Real-time (continuous)
    - **Custom result index:** opensearch-ad-plugin-result-insider_threat (!important)

### 3.2 Define Numeric Features

| Feature name | Method | Field | Notes |
| --- | --- | --- | --- |
| `user_file_access_count` | `count()` | `user.keyword` | Counts file events per user |
| `user_data_volume_bytes` | `sum()` | `content_bytes` | Total bytes read or written |
| `user_distinct_files_touched` | Custom expression | - | Workaround via ingest pipeline (see below) |

### 3.2.1 Workaround for Cardinality

The OpenSearch UI does not support `cardinality()` directly, which is why we use a custom expression:

```json
{
    "distinct_files_cardinality": {
        "cardinality": {
            "field": "filename.keyword"
        }
    }
}
```

### 3.3 Enable Categorical Field (Per-User Modelling)

Under **Categorical field**, select the user identifier `user.keyword`.

This ensures each user gets its own statistical model, preventing Alice’s behavior from obscuring Bob’s anomalies.

### 3.4 Saving & Validation

Click **Next** to **Review**.

- The UI will validate your feature expressions and show sample anomaly scores if enough history exists.
- Click **Create** to finalize.

## Part 4: Monitor, Webhook & Wazuh Rule Integration

### 4.1 Create an OpenSearch Monitor

In the `insider-threat-detector` anomaly overview, set up an alert: 

1. This will create a `insider-threat-detector` monitor, which will create an alert when an anomaly is detected.
2. **Trigger Configuration**: Add trigger
    - **Trigger name:** `Insider-Threat-Detected`
    - **Severity:** High
    - **Condition:**
    
    When choosing thresholds for firing alerts, you must balance **sensitivity** (catching real threats) against **precision** (avoiding false positives). A balanced strategy is to require:
    
    - **anomaly_grade ≥ 0.8:** captures the upper quintile of deviations without triggering on mild fluctuations, and
    - **confidence ≥ 0.85:** ensures the model has seen enough data to trust its grade.
    
    Starting here helps minimize alerts on spikes. Particularly important in high-cardinality, per-user detectors where data volume per user can vary widely. Tuning can then adjust these up or down based on observed false-positive rates during the analysis.
    
3. Before following with an action, create a Notification Channel in Wazuh. Go to Menu, navigate to Notifications under Explore. And create a Channel:
    - **Name**: RADAR
    - **Channel type:** Custom webhook
    - **Method:** POST
    - **Webhook URL:** [http://<wazuh-manager>:8888/opensearch-alert](http://192.168.0.28:8888/opensearch-alert)
4. **Action**
    - **Action name:** `RADAR`
    - **Channel**: RADAR
    - **Message (must be JSON)**:
        
        ```json
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

### 4.2 Webhook script

This [AD alerts webhook](/soar-radar/webhook/ad_alerts_webhook.py) is a simple Flask application that receives the monitor's payload and appends a single line to `/var/log/ad_alerts.log`. To deploy the webhook in the Wazuh manager:

1. Copy the [file](/soar-radar/webhook/ad_alerts_webhook.py) from this repository into the Wazuh manager to a custom `wazuh_webhook` directory.

2. Ensure execution permissions: `chmod +x`

3. Run under a python3:

```bash
python3 ad_alerts_webhook.py
```

4. The resulting log file should be monitored by Wazuh, thus `/var/ossec/etc/ossec.conf` needs to be configured:

```xml
<localfile>
    <log_format>syslog</log_format>
    <location>/var/log/ad_alerts.log</location>
</localfile>
```

### 4.3 Wazuh Decoder & Rule

### 4.3.1 Local Decoder

Add the content of the file `local_decoder.xml` in this repository into the file `/var/ossec/etc/decoders/local_decoder.xml` in the Wazuh manager.

### 4.3.2 Local Rules 

Add the content of the file `local_rules.xml` in this repository into the file `/var/ossec/etc/rules/local_rules.xml` in the Wazuh manager.

- **Restart** Wazuh manager (`var/ossec/bin/wazuh-control restart` in Docker or `systemctl restart wazuh-manager`).
- This ensures rule 100301 fires whenever our webhook writes a matching line to `/var/log/ad_alerts.log`.

### 4.4 Binding the Manager-Side Active Response

1. In **`ossec.conf`** on the manager, register and bind only the `ad_context_insider_active_response.py` script. Script can be found in [Active Response directory](/soar-radar/active_responses/).

```xml
<ossec_config>
  <!-- 1) Command declaration -->
  <command>
    <name>ad_enrich</name>
    <executable>ad_context_insider_active_response.py</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <!-- 2) Active-response binding -->
  <active-response>
    <disabled>no</disabled>
    <command>ad_enrich</command>
    <location>server</location>
    <rules_id>100301</rules_id>
    <timeout>120</timeout>
  </active-response>
</ossec_config>
```

- When Wazuh rule 100301 fires, it will run `ad_context_insider_active_response.py user_keyword period_start period_end`.

2. Place a copy of the script from the `active_responses` directory to `/var/ossec/active-response/bin` in the Wazuh manager. **Note**: remember to update the Wazuh access credentials (username, password) in the script based on your setup.
3. Give permissions for execution:
```sh
chmod 750 /var/ossec/active-response/bin/ad_context_insider_active_response.py
chown root:wazuh /var/ossec/active-response/bin/ad_context_insider_active_response.py
```
4. Install dependencies in the Wazuh manager

```shell
python3 -m pip install requests
```

### 4.5. Binding the Agent-side Active Responses

1. **Install `jq`** (used by the scripts for JSON parsing):
    
    ```bash
    sudo apt update
    sudo apt install -y jq
    ```
    
2. **Create your log files** (for enrichment):
    
    ```bash
    sudo touch /var/ossec/logs/ad_pc_enriched.log
    sudo chown root:wazuh /var/ossec/logs/ad_pc_enriched.log
    sudo chmod 664    /var/ossec/logs/ad_pc_enriched.log
    ```
    
3. **Create your blocked-users log** (for lock/unlock):
    
    ```bash
    sudo touch /var/ossec/logs/blocked_users.log
    sudo chown root:wazuh /var/ossec/logs/blocked_users.log
    sudo chmod 664    /var/ossec/logs/blocked_users.log
    ```
    

4. Deploy the Scripts

Copy your two scripts into the agent’s AR directory. Scripts can be found in [Active Response directory](/soar-radar/active_responses/).

```bash
sudo cp write_contextual_logs_insider_active_response.sh \
        /var/ossec/active-response/bin/
sudo cp lock_user_linux_active_response.sh \
        /var/ossec/active-response/bin/
```

Set ownership and permissions so Wazuh can execute them:

```bash
sudo chown root:wazuh /var/ossec/active-response/bin/write_contextual_logs_insider_active_response.sh
sudo chmod 750      /var/ossec/active-response/bin/write_contextual_logs_insider_active_response.sh

sudo chown root:wazuh /var/ossec/active-response/bin/lock_user_linux_active_response.sh
sudo chmod 750      /var/ossec/active-response/bin/lock_user_linux_active_response.sh
```

5. Enable Remote Commands

In order for the manager to invoke these scripts via the API or `<active-response>` blocks, the agent must accept remote commands.

Create or update:

```sh
/var/ossec/etc/local_internal_options.con
```

and include:

```sh
wazuh_command.remote_commands=1
```

6. Register Commands in the Agent’s `ossec.conf`

Edit:

```sh
/var/ossec/etc/ossec.conf
```

Under the top-level `<ossec_config>` element, add **both** `<command>` entries:

```xml
<ossec_config>
  …
  <command>
    <name>write_contextual_logs_insider_active_response.sh</name>
    <executable>write_contextual_logs_insider_active_response.sh</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>lock_user_linux_active_response.sh</name>
    <executable>lock_user_linux_active_response.sh</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>
  …
</ossec_config>
```

7. Restart the Agent

```bash
sudo systemctl restart wazuh-agent
```

## Part 5: Active Response Analysis

For most environments, it is prudent to implement a **two-tier response**:

1. **Tier 1 (Alert Only):** anomaly_grade ≥ 0.8 **AND** confidence ≥ 0.85 generates a security alert for analyst review.
2. **Tier 2 (Automated Lockout):** anomaly_grade ≥ 0.95 **AND** confidence ≥ 0.95 initiates a high-impact Active Response (e.g., account lockout).

By reserving lockouts for only the most extreme, high-confidence events, you mitigate the risk of inadvertently locking legitimate users during benign but unusual patterns (such as quarterly bulk exports).

### 5.1 Context extraction Active response flow

- **Receive Trigger Parameters**
    
    The script is called with three pieces of information are extracted by the Wazuh decoder and rule:
    
    - **User identifier** (the account that generated the anomaly)
    - **Anomaly window start** (when the detector began flagging unusual behavior)
    - **Anomaly window end** (when it stopped)
- **Authenticate to the Wazuh API**
    
    It requests a JWT token from the manager’s security endpoint, using the configured API credentials. This token is needed for all subsequent calls to query agents or dispatch further Active Responses.
    
- **Query Anomaly Events**
    
    Using the OpenSearch client, the script fetches every logged event for that user within the anomaly window from the test index. This returns raw details: timestamps, file names, bytes processed, host names, etc.
    
- **Group Events by Host (Agent)**
    
    The returned events are regrouped in memory by their `pc` field. Each group corresponds to one Wazuh agent where the suspicious activity occurred.
    
- **Enrichment Log Dispatch**
    
    For each agent:
    
    - It instructs Wazuh to run the custom **write_log** command on that agent, passing in the user name and the JSON‐array of events.
    - The agent appends those details to its local enrichment file (`ad_pc_enriched.log`), giving analysts full context of what happened on each machine.
- **Optional Account Lockout**
    
    Immediately after logging, the script can invoke the **lock_user** command on the same agent to disable the account locally. By default this step is **commented out** to prevent accidental lockouts during testing (simply uncomment it once you are satisfied with the detection quality).
    
- **Result Handling and Logging**
    
    Each Active Response call is made with a “wait for completion” flag. The script parses the API response to confirm which agents successfully received the command, which (if any) failed, and logs that outcome back on the manager for audit and troubleshooting.
    
- **False-Positive Safeguards & Threshold Justification**
    - **Alerts (no automatic lock):** only when **anomaly_grade ≥ 0.8** and **confidence ≥ 0.85**, to catch significant but not necessarily catastrophic deviations.
    - **Automated lockouts:** reserved for the most extreme cases—**anomaly_grade ≥ 0.95** and **confidence ≥ 0.95**—to minimize risk of locking out legitimate users.
    - The two-tier approach, combined with the enrichment log, ensures analysts see all context before any high-impact action.
- **Roll-Back Mechanism**
    
    If lockouts are enabled, you can configure a timeout (in Wazuh `<active-response>` settings) so that accounts are automatically re-enabled after a safe period.

## Part 6. Risk Analysis

In the scenario of a privileged user anomalously exporting sensitive data outside of business hours, the risk associated with this behavior is computed using the classical formulation:

```
R = C × I
```

where `C` is the model’s confidence that the behavior is malicious, and `I` is the impact severity derived from the Common Vulnerability Scoring System (CVSS). Although CVSS was originally designed for assessing external software vulnerabilities, we adopt it as a measure in cyber risk modeling and UEBA (User and Entity Behavior Analytics) to handle insider threat scenarios by mapping observed behavior to Confidentiality, Integrity, and Availability (CIA) impacts.

In this particular case, the user is accessing and exfiltrating large amounts of sensitive data, implying a **complete loss of confidentiality** and **partial compromise of data integrity**, but with **minimal availability impact**. These characteristics align with the "High" impact range in CVSS v3 scoring (7.0–8.9). Therefore, we conservatively assign an impact score of:

```
I = 7.5
```

This score represents a mid-point within the high-severity band and reflects the severity of potential data loss and misuse of privilege. The resulting risk score becomes:

```
R = C × 7.5
```

Depending on the thresholding technique used, e.g., empirically obtained values, the tiered system can be used to take different types of automated response actions:

- **Tier 2** → investigate
- **Tier 3** → urgent response

This thresholding strategy ensures a data-driven, explainable escalation path where only sufficiently confident and impactful insider threats are prioritized, while low-confidence anomalies are deprioritized. The formulation remains transparent, consistent, and interpretable across operational environments.


## Part 7. OpenCTI Enrichment

For Contextual Enrichment and Threat Intelligence, corresponding Active Response can be triggered on every Anomaly detection. The instructions can be found in the [Automated OpenCTI enrichment README](/integrations/opencti-wazuh-connector/automated_trigger/README.md).

## Part 8. Dataset

The dataset stored in the `dataset` subfolder of this RADAR scenario was obtained from the [kilthub](https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247) repository of Carnegie Mellon University.