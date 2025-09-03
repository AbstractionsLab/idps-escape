# Suspicious login

## Part 1: Objectives

**Example Scenario:** A user logs in at 03:00 from a foreign IP address, deviating from their normal location and login schedule. Another user who typically logs in from Luxembourg starts showing login activity from multiple countries within a short time frame. These behaviors deviate from the user’s normal pattern and may indicate account compromise, credential theft, or malicious automation.

The objective is to detect such deviations in login behavior by modeling typical login patterns (time, location, frequency) per user and identifying outliers indicative of suspicious or unauthorized access.

**Categorical Features:** To improve detection accuracy, categorize anomalies by username or user ID. This ensures the model builds a separate baseline per user. Optional dimensions include user department, user role, or device ID if such metadata exists in the log source. Data should be sliced per user to model unique behavioral patterns.


## Part 2: Data Preparation & Ingestion

### 2.1 Dataset Ingestion

To simulate “today” data and feed Wazuh’s AD plugin, we shift each file’s dates into the last three days. The script is located in suspicious_login/wazuh_ingest.py. Run it from suspicious_login:

```bash
python3 wazuh_ingest.py
```

- **What it does:**
    - Iterates offsets **–3…+3**
    - Shifts each event’s date to `today + offset`
    - Enriches with `@timestamp` (ISO), `event_hour`
    - Bulk‐indexes into daily indices like `wazuh-ad-suspicious-login-2025.06.07`

---

### 2.2 Index Pattern & Wazuh Integration

1. **In Dashboards Management**, create an **Index Pattern** for `wazuh-ad-suspicious-login-*`.
2. Confirm documents appear in **Discover** with fields:
    - `@timestamp` (date)
    - `User ID` (string)
    - `Country`, `IP Address`, `event_hour`, etc.

---

### 2.3. SSO system configuration

1. In agent endpoint, run Keycloak:

```bash
docker run -d --name keycloak -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=secret \
  quay.io/keycloak/keycloak:24.0.1 start-dev
```

1. In Keycloak Admin Console (http://localhost:8080):
    - Create Realm: `demo`
    - Create Confidential Client: `wazuh` (enable Service Accounts)
    - Assign roles from `realm-management`: `view-users`, `manage-users`
2. In agent endpoint, run script for adding users from dataset. For this, first set environment variables:

```bash
export KC_BASE_URL=http://127.0.0.1:8080
export KC_REALM=demo
export KC_ADMIN_USER=admin
export KC_ADMIN_PASSWORD=secret
```
Run the script to bulk create users:

```bash
python3 bulk_create_keycloak_users.py dataset/rba-dataset+0.csv
```



## Part 3: Detector & Feature Configuration

### 3.1 Create the Anomaly Detector

1. **Navigate** in Wazuh Dashboards to **OpenSearch Plugins ➔ Anomaly Detection**.
2. Click **Create detector** and fill out:
    - **Name:** `suspicious-login-detector`
    - **Description:** “Monitor per-user login”
    - **Index:** `wazuh-ad-suspicious-login-*`
    - **Time field:** `@timestamp`
    - **Detection interval:** `5m` (with `1m` window delay)
    - **Detector type:** Real-time (continuous)
    - **Custom result index:** opensearch-ad-plugin-result-suspicious_login (!important)

---

### 3.2 Define Features

| Feature name | Method | Field | Notes |
| --- | --- | --- | --- |
| `login_count` | `value_count` | `User ID.keyword` | Counts total login events per user |
| `distinct_geo_country` | Custom expression | — | See “Workaround for Cardinality” below |
| `login_hour_cardinality` | Custom expression | — | See “Workaround for Cardinality” below |

---

### 3.2.1 Workaround for Cardinality

OpenSearch’s anomaly-detection UI doesn’t directly expose a `cardinality()` aggregation in the simple “Field value” mode, so we inject our two cardinality features via custom JSON expressions:

```json
{
  "distinct_geo_country": {
    "cardinality": {
      "field": "Country.keyword"
    }
  }
}
```

```json
{
  "login_hour_cardinality": {
    "cardinality": {
      "field": "event_hour"
    }
  }
}
```

Each of these goes into the “Custom expression” section when you add a feature.

### 3.3 Enable Categorical Field (per-user modelling)

Under **Categorical field**, select the user identifier `User ID.keyword`.

This ensures each user gets its own statistical model, preventing Alice’s behavior from obscuring Bob’s anomalies.

---

### 3.4 Saving & Validation

Click **Next** to **Review**.

- The UI will validate your feature expressions and show sample anomaly scores if enough history exists.
- Click **Create** to finalize.

## Part 4: Monitor, Webhook & Wazuh Rule Integration

### 4.1 Create an OpenSearch Monitor

In suspicious-login-detector Anomaly overview, set up alert: 

1. This will create a monitor suspicious-login-detector-Monitor, which will create an alert when an anomaly is detected.
2. **Trigger Configuration: Add trigger**
    - **Trigger name:** `Suspicious-Login-Detected`
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
    - **Webhook URL:** [http://\<wazuh-manager\>:8888/opensearch-alert](http://192.168.0.28:8888/opensearch-alert)
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

---

### 4.2 Webhook Script (`ad_alerts_webhook.py`)

This [webhook](/soar-radar/webhook/README.md) is a simple Flask application that receives the monitor's payload and appends a single line to `/var/log/ad_alerts.log`. To deploy the webhook in the Wazuh manager:

1. Copy the [ad_alerts_webhook.py](/soar-radar/webhook/ad_alerts_webhook.py) file from this repository into the Wazuh manager to a custom wazuh_webhook directory.

2. Ensure execution permissions: chmod +x

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

---

### 4.3 Wazuh Decoder & Rule

### 4.3.1 Local Decoder

Add the content of the file local_decoder.xml in this repository into the file `/var/ossec/etc/decoders/local_decoder.xml` at the Wazuh manager.

### 4.3.2 Local Rules 

Add the content of the file local_rules.xml in this repository into the file `/var/ossec/etc/rules/local_rules.xml` at the Wazuh manager.

- **Restart** Wazuh manager (`var/ossec/bin/wazuh-control restart` in Docker or `systemctl restart wazuh-manager`).
- This ensures rule 100302 fires whenever our webhook writes a matching line to `/var/log/ad_alerts.log`.

---

### 4.4 Binding the Manager-Side Active Response

1. In **`ossec.conf`** on the manager, register and bind only the `ad_context_susplog_active_response.py` script. Script can be found in [Active Response directory](/soar-radar/suspicious_login/active_responses).

```xml
<ossec_config>
  <!-- 1) Command declaration -->
  <command>                                                                                                             
    <name>ad_enrich_suspicious_login</name>                                                                             
    <executable>ad_context_susplog_active_response.py</executable>                                                        
    <timeout_allowed>yes</timeout_allowed>                                                                              
  </command>

  <!-- 2) Active-response binding -->
  <active-response>
    <disabled>no</disabled>
    <command>ad_enrich_suspicious_login</command>
    <location>server</location>
    <rules_id>100302</rules_id>
  </active-response>
</ossec_config>
```

- When Wazuh rule `100302` fires, it will run `ad_context_susplog_active_response.py`.

2. Place the script itself in active-response directory to /var/ossec/active-response/bin in wazuh manager.
3. Give permissions for execution:
```bash
chmod 750 /var/ossec/active-response/bin/ad_context_susplog_active_response.py
chown root:wazuh /var/ossec/active-response/bin/ad_context_susplog_active_response.py
```
4. Install dependencies into Wazuh manager

```bash
python3 -m pip install requests
```

### 4.5. Binding the Agent-side Active Responses

1. **Install `jq` for JSON parsing:**

```bash
sudo apt update
sudo apt install -y jq
```

2. **Prepare enrichment log file:**

```bash
sudo touch /var/ossec/logs/ad_pc_enriched.log
sudo chown root:wazuh /var/ossec/logs/ad_pc_enriched.log
sudo chmod 664 /var/ossec/logs/ad_pc_enriched.log
```

3. **Deploy contextual logging script:**

```bash
sudo cp write_contextual_logs_susplog_active_response.sh /var/ossec/active-response/bin/
sudo chown root:wazuh /var/ossec/active-response/bin/write_contextual_logs_susplog_active_response.sh
sudo chmod 750 /var/ossec/active-response/bin/write_contextual_logs_susplog_active_response.sh
```

4. **Register command in `ossec.conf`:**

```xml
<command>
  <name>write_contextual_logs_susplog_active_response.sh</name>
  <executable>write_contextual_logs_susplog_active_response.sh</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>
```

5. **Deploy Keycloak AR script:**

```bash
sudo cp disable_sso_user.py /var/ossec/active-response/bin/
sudo chmod 750 /var/ossec/active-response/bin/disable_sso_user.py
sudo chown root:wazuh /var/ossec/active-response/bin/disable_sso_user.py
```

6. **Set environment variables:**

```bash
export KC_BASE_URL=http://127.0.0.1:8080
export KC_REALM=demo
export KC_CLIENT_ID=wazuh
export KC_CLIENT_SECRET=REPLACE_ME
```

7. **Register `disable-sso-user` command in `ossec.conf`:**

```xml
<command>
  <name>disable_sso_user.py</name>
  <executable>disable_sso_user.py</executable>
  <timeout_allowed>no</timeout_allowed>
</command>
```

8. **Enable remote command execution.** 

Edit /var/ossec/etc/local_internal_options.conf:

```
wazuh_command.remote_commands=1
```

9. **Restart the Wazuh agent:**

```bash
sudo systemctl restart wazuh-agent
```

## Part 5: Active Response Analysis (Suspicious Login)

In a production environment, we recommend a **two-tier response** strategy for login anomalies:

### Tier 1: Alert Only (For Early Anomalies)

- **Condition:** `anomaly_grade ≥ 0.7` and `confidence ≥ 0.8`
- **Action:**
    - Trigger alert in Wazuh
    - Run `write_contextual_logs_susplog_active_response.sh` to store user behavior snapshots in `/var/ossec/logs/ad_pc_enriched.log`

This tier gives visibility to analysts while avoiding premature blocking.

### Tier 2A: Disable SSO Account (User-Based Threats)

- **Condition:** `anomaly_grade ≥ 0.9` and `confidence ≥ 0.9`
- **Action:**
    - Run `disable-sso-user` to lock the user in Keycloak

**Use case:**

- Credential theft or malicious automation
- Suspicious access patterns per user (geo-jumping, midnight logins)
- Internal compromise or insider misuse

**Impact:** Prevents any future login attempts using the user’s SSO identity across all systems federated with Keycloak.

**Recovery:** Admins can re-enable accounts manually after validation.

### Tier 2B: IP Firewall Block (Network-Based Threats)

- **Condition:** `anomaly_grade ≥ 0.9` and `confidence ≥ 0.9`
- **Action:**
    - Run `firewall-drop` via Wazuh Active Response

**Use case:**

- Malicious IPs scanning or brute-forcing multiple users
- Botnets with rotating credentials

**Impact:** Temporarily drops packets from the attacker’s IP using IPTables (default expiration ~10 mins).

**Recovery:** IP block expires automatically unless re-enforced.

### Considerations

- Combine both actions in **multi-agent setups**, where IP block runs on proxies and SSO disable runs on user-specific agents.
- Use `whitelist` logic in scripts to skip known corporate VPN IPs or admin users.
- Ensure all AR scripts log to `/var/ossec/logs/active-responses.log` for auditability.

This two-tier model balances visibility with rapid containment, reserving automated blocks for the highest-confidence scenarios and minimizing collateral disruption.

---

### 5.1 Context Extraction & Active Response Flow

Below is the end-to-end sequence when a suspicious login anomaly triggers Tier 2 containment:

- **Trigger Parameters Passed**
    - A Wazuh rule matched by the anomaly detector emits an alert.
    - The alert includes key parameters extracted by the decoder:
        - **`detector_name`**: `"Suspicious-Login-Detected"`
        - **`user_keyword`**: (e.g., `"test_openbas"`)
        - **`User ID`**: the SSO identity to be disabled (e.g., `4324475583306591935`)
        - **`period_start`** / **`period_end`**: ISO timestamps bounding the anomaly window
- **Script Invocation by `execd`**
    - The Wazuh agent’s `execd` daemon triggers the relevant Active Response scripts using the wrapper JSON.
    - Both `write_contextual_logs_susplog_active_response.sh` and `disable-sso-user` receive the alert data via `stdin` with `"command":"add"`.
- **Contextual Enrichment (write_contextual_logs_susplog_active_response.sh)**
    - The first script authenticates with the Wazuh API.
    - It queries OpenSearch for **all login events** for the suspicious user within the given time window.
    - Events are enriched and saved to `/var/log/suspicious_login_enriched.log` for forensic and audit purposes.
- **Automated Containment**
    - **Firewall IP Blocking**:
        - Extracted events are grouped by `IP Address`.
        - For each distinct source IP, the script triggers Wazuh’s `firewall-drop` Active Response:
            
            ```json
            {
              "command": "firewall-drop",
              "arguments": ["1.2.3.4"],
              "alert": { "data": { "srcip": "1.2.3.4" } }
            }
            ```
            
        - Wazuh immediately issues an IPTables DROP rule on the agent to block the offending IP.
    - **SSO User Disabling**:
        - The `disable-sso-user` script loads environment variables from `/var/ossec/.kc_env`.
        - It authenticates with Keycloak using client credentials.
        - Searches the realm for the provided `User ID`.
        - If the user exists, the account is disabled by setting `enabled=false` to halt further SSO authentication.
- **Audit & Logging**
    - Each firewall block API call is logged in `/var/ossec/logs/active-responses.log` on the manager, capturing success or failure per IP.
    - The `disable-sso-user` script logs user disablement actions to `/var/ossec/logs/active-responses/disable_sso_user.log`.
    - These logs allow security analysts to verify that both containment actions (IP block and SSO lockout) executed successfully.

---

### 5.2 False-Positive Safeguards

- **Tier 1 thresholds** are set lower to catch suspicious but not definitive anomalies—analysts receive full context logs before any automated action.
- **Tier 2 thresholds** are high enough to trigger blocking only on the most egregious outliers, reducing the risk of collateral denial-of-service for legitimate users.
- **Whitelist handling**: The script can be extended to skip blocking on known safe IP ranges (e.g., corporate VPN egress points).
- **Short rollback window** (e.g. 15–30 minutes) limits disruption if a benign IP is inadvertently blocked.

## Part 6. OpenCTI Enrichment

For Contextual Enrichment and Threat Intelligence, corresponding Active Response can be triggered on every Anomaly detection. The instruction is in [Automated OpenCTI Enrichment](/integrations/opencti-wazuh-connector/automated_trigger/).

## Part 7. Dataset

The dataset originates from [Kaggle - RBA-dataset](https://www.kaggle.com/datasets/dasgroup/rba-dataset).

## Part 8: Generalizing Suspicious Login Detection Beyond Keycloak

While this setup uses **Keycloak** as the default SSO provider for demonstration purposes, the detection logic is **fully generalizable** to other authentication systems such as:

- **SSH login events** (e.g., `/var/log/auth.log`)
- **Azure Active Directory sign-ins**
- **Google Workspace / Okta / SAML-based SSO providers**

The anomaly detection system is designed to be **identity provider–agnostic**, relying only on normalized login event data.

---

### 7.1 Key Concepts for Generalization

| Component          | Adaptation Notes                                                                 |
|-------------------|-----------------------------------------------------------------------------------|
| **Log Source**     | Replace or augment Keycloak logs with logs from SSH, Azure AD, Okta, etc.        |
| **Ingest Format**  | Normalize logs to include fields like `User ID`, `timestamp`, `Country`, `IP`.   |
| **Anomaly Features** | Maintain behavior-based indicators (geo changes, login hours, frequency).       |
| **Categorical Field** | Always slice data per user (e.g., `User ID.keyword`, `username.keyword`).     |

---

### 7.2 Feature Mapping for Other Authentication Systems

| Common Field   | SSH                    | Azure AD / Okta         |
|----------------|------------------------|--------------------------|
| **User ID**     | `username`             | `userPrincipalName`      |
| **Timestamp**   | `timestamp`            | `createdDateTime`        |
| **IP Address**  | `src_ip`               | `ipAddress`              |
| **Country**     | Derived from `src_ip`  | Derived from `ipAddress` |
| **Login Time**  | Derived from timestamp | Derived from timestamp   |

Use Logstash, Filebeat modules, or ingestion scripts to transform and map fields before indexing to OpenSearch.

## Part 8. Risk Analysis
 In the case of suspicious login activity,such as a user accessing the system at 03:00 from a foreign IP or from multiple countries in a short timeframe, the associated risk is again modelled using:

```
R = C × I
```

Here, `C` represents the confidence score output by the anomaly detection system, reflecting the likelihood that the login behavior deviates from established user-specific baselines. This use of model confidence as a proxy for likelihood is standard in behavior-based intrusion detection systems. The impact score `I` is derived from CVSS, adapted to represent behavioral anomalies such as unauthorized or suspicious access events.

In this context, potential consequences include **moderate confidentiality loss** (e.g., exposure of personal or customer data), but typically **no direct integrity or availability compromise**, assuming the attacker has not escalated privileges or performed destructive actions.

According to our tiered thresholding automated response mechanism, we set:

- **Tier 2** → investigate suspicious login
- **Tier 3** → contain or lock account

This framework ensures that anomalous login behavior is escalated only when both the confidence is high and the potential business impact is non-trivial. It also allows for consistent application of response policies across users and login patterns, making the model robust for account compromise detection.