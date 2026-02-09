# Run RADAR manual

## Overview

`run-radar.sh` is an orchestration script that automates the deployment of anomaly detection scenarios in a Wazuh environment. It executes a three-stage pipeline: data ingestion, detector creation/configuration, and monitoring setup.

### Execution Flow

```
run-radar.sh <scenario>
     ↓
[1] Data Ingestion → wazuh_ingest.py
     ↓
[2] Detector Setup → detector.py → returns DETECTOR_ID
     ↓
[3] Monitor Setup → monitor.py → returns MONITOR_ID
```

### Required Environment Variables

- `OS_URL`: Wazuh Indexer endpoint
- `OS_USER`: Wazuh Indexer authentication username
- `OS_PASS`: Wazuh Indexer authentication password
- `OS_VERIFY_SSL`: Wazuh Indexer TLS certificate verification
- `DASHBOARD_URL`: Wazuh Dashboard endpoint
- `DASHBOARD_USER`: Wazuh Dashboard authentication username
- `DASHBOARD_PASS`: Wazuh Dashboard authentication password
- `DASHBOARD_VERIFY_SSL`: Wazuh Dashboard TLS certificate verification
- `WEBHOOK_URL`: Webhook endpoint (usually located in Wazuh Manager)
- `WEBHOOK_NAME`: Webhook name

### Supported scenarios

The script accepts these scenario names:

- `suspicious_login`
- `log_volume`

**Note on archived scenarios:** The scenarios `insider_threat`, `ddos_detection`, and `malware_communication` are archived demo scenarios located in `/radar/archives/`. They require adaptation of indices, field mappings, and datasets to match your environment and are not production-ready. See the [main RADAR README](../../../radar/README.md) for scenario status details.

**Note on GeoIP detection:** The `geoip_detection` scenario is not listed here because it uses signature-based detection only (Wazuh rules and decoders, no OpenSearch AD pipeline). It is deployed via Ansible during `build-radar.sh` and does not require the `run-radar.sh` data ingestion/detector/monitor setup. See [GeoIP Detection Guide](./radar-scenarios/geoip_detection_explained.md) for manual setup instructions.

Each supported scenario has its own:

- Ingestion logic (`wazuh_ingest.py` in `/radar/scenarios/ingest_scripts/<scenario>/`)
- Feature definitions in `config.yaml`
- Monitor setup configurations in `config.yaml`

### Container execution

- Data injection, detector and monitor setup are run in the image `radar-cli:latest` , the image is built during `build-radar.sh`
- Python scripts executed in isolated containers
- Output IDs captured via stdout for pipeline chaining

## Stage 1: Data ingestion (`wazuh_ingest.py`)

### Purpose

Generates and ingests synthetic time-series log data into OpenSearch indices for anomaly detection training.

### 1. Log volume growth detection scenario

**Configuration:**

- Target agent: `edge.vm` (ID: 001)
- Metric: Log volume in bytes at `/var/log`
- Time window: 240 minutes historical data
- Sampling interval: 20 seconds
- Index pattern: `wazuh-ad-log-volume-*`

**Data Generation Algorithm:**

1. Baseline calculation
    - Queries last 10 minutes of existing data
    - Retrieves 2 first documents
    - Calculates delta between values, if insufficient data fallbacks to 20,000 bytes
2. Time series construction
    - Total points: `(240 minutes × 60) / 20 seconds = 720 points`
    - Linear progression: `start_value + (delta × point_index)`
    - Ensures realistic monotonically increasing log volume
3. Bulk ingestion
    - Uses OpenSearch `_bulk` API
    - NDJSON format (newline-delimited JSON)
    - Creates documents with structure:
        
    ```json
    {  
        "@timestamp": "ISO8601_timestamp",  
        "agent": {
        	"name": "edge.vm", 
        	"id": "001"
        },  
        "data": {
        	"log_path": "/var/log", 
        	"log_bytes": <value>
        },  
        "predecoder": {
        	"program_name": "log_volume_metric"
        }
    }
    ```
        

## Stage 2: Detector creation (`detector.py`)

### Purpose

Creates or retrieves ID of an OpenSearch Anomaly Detection detector configured for the specified scenario.

### Process

1. Configuration loading
    - Reads `config.yaml` for scenario definitions
    - Loads environment variables from `.env`
    - Validates scenario exists
2. Detector existence check
    - Searches for existing detector by name pattern: `{SCENARIO}_DETECTOR`
    - Uses query: `{"term": {"name.keyword": "<detector_name>"}}`
    - Returns ID of Detector if found
3. Creates detector with:
    - Timestamp field for analysis
    - Index pattern to monitor
    - Features
    - Detection interval
    - Window delay
    - Category field
    - Result index
4. Starts detector (begins analysis)
5. Returns detector ID to stdout

### Configuration example:

```yaml
log_volume:
    index_prefix: wazuh-ad-log-volume-*
    result_index: opensearch-ad-plugin-result-log-volume
    log_index_pattern: wazuh-ad-log-volume-*
    time_field: "@timestamp"
    categorical_field: "agent.name"
    detector_interval: 5
    delay_minutes: 1
    monitor_name: "LogVolume-Monitor"
    trigger_name: "LogVolume-Growth-Detected"
    anomaly_grade_threshold: 0.3
    confidence_threshold: 0.3
    features:
      - feature_name: log_volume_max
        feature_enabled: true
        aggregation_query:
          log_volume_max:
            max:
              field: data.log_bytes

```

## Stage 3: Monitor creation (`monitor.py`)

### Purpose

Creates alerting monitors that trigger notifications when anomalies exceed defined thresholds.

### Process

1. Webhook setup
    - Calls `ensure_webhook()` from `webhook.py`
    - Retrieves or creates notification channel with destination types: Custom webhook (HTTP POST)
2. Checks for existing monitor by name
3. If it does not exist, creates monitor with trigger conditions:

```
ctx.results[0].aggregations.max_anomaly_grade.value > {anomaly_grade_threshold} &&
ctx.results[0].hits.hits[0]._source.confidence > {confidence_threshold}
```

4. Returns monitor ID to stdout