# Linux resource utilization detection

## Objectives

**Example scenario:** Each Linux endpoint normally runs at a fairly stable CPU
and memory load. A sustained, unexplained spike — from cryptomining, a
runaway or looping process, a resource-exhaustion attack, or unauthorized
compute-heavy jobs — can go unnoticed by threshold-based monitoring tuned for
"normal" peaks. This scenario samples CPU and memory utilization on each
endpoint and identifies abnormal utilization based on the endpoint's own
historical baseline.

Goal: Detect unusually high CPU/memory utilization on any Linux endpoint,
generate alerts, and enable automated responses such as email notifications,
service termination, or integration with SOAR workflows.

---

## Behavior-based approach

### Detection

The detection process is implemented using three components:

1. Local metric collection (`radar-linux-resource-utilization.timer`, a
   systemd timer installed by `bootstrap-agent.sh` when an agent is enrolled
   in the `linux_resource_utilization` group). Every 30 seconds it samples
   `/proc/stat` (CPU) and `/proc/meminfo` (memory) and appends a line to
   `/var/log/radar/resource_usage_metric.log`:
   ```
   Jan 01 00:00:00 edge.vm resource_usage_metric: cpu=12.34 mem=56.78
   ```
2. Custom decoders (`decoders/linux_resource_utilization/0001-linux-resource-utilization.xml`)
   parse the `cpu=<pct> mem=<pct>` pairs into `data.cpu_usage_pct` and
   `data.mem_usage_pct` fields.
3. An OpenSearch Anomaly Detector builds a per-endpoint RCF baseline over the
   average and peak of both fields and flags deviations.

---

### Active response analysis

Active responses handle detected anomalies:

- **Email Notification / mitigation (`/radar/scenarios/active_responses/radar_ar.py`)**
    - Sends alert emails when the scenario's rule is triggered.
    - `ar.yaml`'s `linux_resource_utilization` entry allows `terminate_service.sh`
      as a Tier 3 mitigation. As shipped it has no `terminable_services` list, so
      no service is stopped, and anomaly alerts carry no source IP, so no
      connection is killed either: tier 3 only notifies. To stop a service, add
      `terminable_services: [<name>]` to this entry and allow the same service on
      the agent (`bootstrap-agent.sh --allow-service <name>`). See
      [Mitigations](../radar-tuning.md#mitigations).

### Manual setup

We distinguish between:

- **Agent side**
- **Manager side** (Wazuh manager where decoders, rules, and active responses live)
- **Wazuh Dashboard / OpenSearch** configuration

#### Prerequisites

- A functioning Wazuh deployment (manager and agents). For deployment instructions, refer to the [SOAR RADAR README](/radar/README.md).

#### Agent-side configuration

1. Enable the CPU/memory metric collector:
```bash
nano /var/ossec/etc/ossec.conf
```
And paste the content of `/radar/scenarios/agent_configs/linux_resource_utilization/radar-linux-resource-utilization-agent-snippet.xml` inside the `<ossec_config>` tag.

2. Re-run `bootstrap-agent.sh --group linux_resource_utilization` from inside the `radar-agent` folder so the systemd timer described above is installed (assigning the group alone does not install it).

3. Restart the agent:
```
systemctl restart wazuh-agent
```

#### Manager-side configuration

1. Copy the files in `/radar/scenarios/decoders/linux_resource_utilization` into `/var/ossec/etc/decoders/`
2. Copy the files in `/radar/scenarios/rules/linux_resource_utilization` into `/var/ossec/etc/rules/`
3. Configure active response scripts: the dispatcher, its scenario configuration `ar.yaml`, and the settings file it reads (`active_responses.env`). Write the settings file with `wazuh_api.ar_env`, which keeps only the keys the active response needs, rather than copying the whole `.env`. `--os-url` is the indexer address as the manager reaches it, and `--manager-address` the manager's own address(es), which are never blocked. Keep `AR_RISK_CONFIG=/var/ossec/active-response/bin/ar.yaml` in `.env`, as in `env.example`.
```
cd /radar
PYTHONPATH=/radar python3 -m wazuh_api.ar_env write /var/ossec/active-response/bin/active_responses.env \
  --env-file /radar/.env --os-url https://<indexer-host>:9200 --manager-address <manager-ip>
cp /radar/scenarios/active_responses/ar.yaml /var/ossec/active-response/bin/ar.yaml
cp /radar/scenarios/active_responses/radar_ar.py /var/ossec/active-response/bin/radar_ar.py
chown root:wazuh /var/ossec/active-response/bin/active_responses.env /var/ossec/active-response/bin/radar_ar.py /var/ossec/active-response/bin/ar.yaml
chmod 0440 /var/ossec/active-response/bin/active_responses.env
chmod 0750 /var/ossec/active-response/bin/radar_ar.py
chmod 0640 /var/ossec/active-response/bin/ar.yaml
```
4. Configure commands and active responses by copying the content of `/radar/scenarios/ossec/radar-linux-resource-utilization-ossec-snippet.xml` into the end of `/var/ossec/etc/ossec.conf` under the `<ossec_config>` tag.
5. Restart the manager:
```
/var/ossec/bin/wazuh-control restart
```

#### Wazuh dashboard / OpenSearch

##### Create the anomaly detector

1. Ensure `data.cpu_usage_pct` and `data.mem_usage_pct` are indexed (as `keyword`, per `config.yaml`'s feature scripts, which parse them with `Double.parseDouble`) in **Index Management**.
2. **Navigate** in Wazuh Dashboards to **OpenSearch Plugins ➔ Anomaly Detection**.
3. Click **Create detector** and fill out:
    - **Name:** `LINUX_RESOURCE_UTILIZATION_DETECTOR` (the name the automated setup uses)
    - **Description:** "Monitor CPU/memory utilization per endpoint"
    - **Index:** `wazuh-archives-*` (raw archives — this scenario has no dedicated custom index, unlike `log_volume`)
    - **Time field:** `@timestamp`
    - **Detection interval:** `1m` (with `1m` window delay), per `config.yaml`
    - **Shingle size:** `8`
    - **Detector type:** Real-time (continuous)
    - **Custom result index:** `opensearch-ad-plugin-result-linux-resource-utilization` (!important)

---

##### Define features

| Feature name | Method | Field | Notes |
| --- | --- | --- | --- |
| `cpu_usage_avg` | `avg` (painless) | `data.cpu_usage_pct` | Parsed to double; average CPU utilization in the detection interval |
| `cpu_usage_max` | `max` (painless) | `data.cpu_usage_pct` | Peak CPU utilization in the detection interval |
| `memory_usage_avg` | `avg` (painless) | `data.mem_usage_pct` | Parsed to double; average memory utilization in the detection interval |
| `memory_usage_max` | `max` (painless) | `data.mem_usage_pct` | Peak memory utilization in the detection interval |

All four scripts return `0.0` when the field is absent, matching `imputation_option: { method: ZERO }` in `config.yaml`.

---

##### Enable categorical field (per-endpoint modelling)

Under **Categorical field**, select the agent identifier `agent.name` (matches `config.yaml`'s `categorical_field`).

This ensures each endpoint gets its own statistical model.

---

##### Filter query

Set the detector's filter to only score documents carrying `data.mem_usage_pct` (`config.yaml`'s `filter_query`).

---

##### Saving & validation

Click **Next** to **Review**.

- The UI will validate your feature expressions and show sample anomaly scores if enough history exists.
- Click **Create** to finalize.

### Monitor and webhook

#### Create webhook

The [webhook](/radar/webhook/README.md) receives the monitor's payload and appends one line per anomalous agent to `/var/log/ad_alerts.log`. See [Log volume growth — Monitor and webhook](./log_volume_explained.md#monitor-and-webhook) for the deployment steps; they are identical for this scenario.

#### Create an OpenSearch monitor

In `LINUX_RESOURCE_UTILIZATION_DETECTOR` Anomaly overview, set up an alert:

1. This creates a monitor `LinuxResourceUtilization-Monitor` (per `config.yaml`), which raises an alert when an anomaly is detected.
2. **Trigger Configuration: Add trigger**
    - **Trigger name:** `LinuxResourceUtilization-Anomaly-Detected`
    - **Severity:** High
    - **Condition:** `anomaly_grade ≥ 0.01` and `confidence ≥ 0.01` (the shipped `anomaly_grade_threshold`/`confidence_threshold` in `config.yaml`)
3. Point the trigger's **Action** at the same `RADAR` notification channel used by `log_volume`, with the same JSON message template (`monitor.name`, `trigger.name`, `entity`, `periodStart`, `periodEnd`, `anomaly_grade`, `anomaly_confidence`, `dataStart`, `dataEnd`) — see [Log volume growth — Create an OpenSearch monitor](./log_volume_explained.md#create-an-opensearch-monitor) for the exact payload.

---

## Rule flow and active response

Once the webhook writes an `OpenSearchAD LinuxResourceUtilization-Anomaly-Detected: ...` line, it flows through Wazuh the same way `log_volume`'s alerts do:

```
1. OpenSearch AD detects a CPU/memory anomaly for an endpoint
2. Wazuh receives the AD alert via the webhook (opensearch_ad decoder)
3. An AD catch-all rule matches (level 5): the first-loaded of 100300 (log_volume), 210039 (suspicious_login), 100320
4. Rule 100321 escalates on "LinuxResourceUtilization-Anomaly-Detected" (level 12)
5. Rule 100321 is the sole active-response trigger (ar.yaml + ossec snippet)
```

See the [Rules reference](../radar-rules.md#5-linux-resource-utilization-detection) for the full rule table, and [Tuning](../radar-tuning.md#how-the-risk-score-is-built) for how the risk engine scores this scenario.