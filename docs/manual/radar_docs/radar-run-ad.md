# Anomaly detector reference (`run-radar.sh`)

Reference for `run-radar.sh`, the script that creates and configures the OpenSearch anomaly detector and its alerting monitor for a scenario. For the day-to-day command, see [Operations](./radar-operations.md#run-the-anomaly-detector); this page covers what each of its three stages actually does and how to configure them.

`run-radar.sh` executes a three-stage pipeline: data ingestion (optional), detector creation, and monitor creation.

### Execution Flow

```
run-radar.sh <scenario> [--ingest true|false]
     ↓
[1] (Optional) Data Ingestion → wazuh_ingest.py
     ↓
[2] Detector Setup → detector.py → returns DETECTOR_ID
     ↓
[3] Monitor Setup → monitor.py → returns MONITOR_ID
```

### Usage

**Basic usage (without ingestion):**
```bash
./run-radar.sh <scenario>
```

**With optional data ingestion:**
```bash
./run-radar.sh <scenario> --ingest true
```

**Parameters:**
- `<scenario>`: name of the scenario to deploy — in practice only `log_volume` (see [Supported scenarios](#supported-scenarios) below)
- `--ingest true|false`: whether to ingest synthetic training data

> **The script's own `--help` text says the default is `true`; the code's actual default is `false`.** Pass `--ingest` explicitly rather than relying on either.

### Required environment variables

- `OS_URL`: OpenSearch/Wazuh Indexer endpoint — read directly by `detector.py`, `monitor.py`, `webhook.py`, and `wazuh_ingest.py`
- `OS_USER` / `OS_PASS`: OpenSearch authentication
- `OS_VERIFY_SSL`: TLS certificate verification for OpenSearch (`DASHBOARD_VERIFY_SSL` is accepted as a fallback if `OS_VERIFY_SSL` is unset, for historical reasons — set `OS_VERIFY_SSL` directly)
- `WEBHOOK_URL`: webhook endpoint the monitor posts to (the `ad-webhook` container `build-radar.sh` brings up)
- `WEBHOOK_NAME`: webhook destination name registered with OpenSearch (default: `RADAR Webhook`)

> `DASHBOARD_URL`, `DASHBOARD_USER`, and `DASHBOARD_PASS` are not read by this pipeline — they configure the separate Dashboards connector tested on the GUI's Connectors page, unrelated to `run-radar.sh`.

Note `radar_ar.py` (the active-response script) reads the same OpenSearch endpoint through a differently named variable, `WAZUH_INDEXER_HOST`, not `OS_URL` — both must point at the same instance. See SWD-032.

### Supported scenarios

`log_volume` is the only scenario with a working detector/monitor pipeline in the current codebase.

Each supported scenario has its own:

- Ingestion logic (`wazuh_ingest.py` in `/radar/scenarios/ingest_scripts/<scenario>/`)
- Feature definitions in `radar/config.yaml`
- Monitor setup configurations in `radar/config.yaml`
- Data ingestion configuration in `radar/config.yaml` (optional `ingest:` section)
- Simulation parameters in `radar/config.yaml` (optional `simulate:` section)

**Key change:** As of the unified configuration update, all scenario parameters (features, detector/monitor settings, ingestion config, and simulation config) are co-located in a single `radar/config.yaml` file under each scenario definition.
Before, ingestion and simulation parameters were in separate configuration files; now they're integrated into the main scenario definition block.

### Container execution

- The image `radar-cli:latest` is built (or rebuilt) on every run from `Dockerfile.radar-cli`, which bakes in `detector.py`, `monitor.py`, `webhook.py`, and the ingest script for the scenarios it knows about
- Each stage runs as a separate, short-lived container; output IDs are captured from stdout to chain into the next stage

## About Data Ingestion

Data ingestion is **optional** and controlled by the `--ingest` flag. 

**When to use ingestion (`--ingest true`):**
- Starting with a fresh scenario and no historical data
- Training the anomaly detector with synthetic baseline behavior
- Testing scenarios before deploying with real production data
- Generating a warm-start for faster anomaly detection

**When to skip ingestion (`--ingest false`, default):**
- Detector operates on existing live data in OpenSearch
- Real production logs are already flowing into the index
- Using historical data already present in the environment
- Fine-tuning detectors after initial deployment

**Example scenarios:**

1. **Fresh deployment with synthetic data:**
```bash
./run-radar.sh log_volume --ingest true
```
Creates and trains detector with synthetic log volume progression data.

2. **Production deployment with live data:**
```bash
./run-radar.sh log_volume
```
Detector immediately starts analyzing existing OpenSearch data without synthetic ingestion.

## Stage 1: Data ingestion (`wazuh_ingest.py`)

### Configuration source

Data ingestion parameters are defined in `radar/config.yaml` under each scenario's optional `ingest:` section. The ingestion script (`wazuh_ingest.py`) reads this configuration to control how synthetic training data is generated and injected into OpenSearch.

**Scenarios with `ingest:` configuration:**
- `log_volume` — parameters like `agent_id`, `agent_name`, `log_path`, `history_minutes`, baseline calculation

> **Important:** `agent_name`/`agent_id` here are placeholders (`"edge.vm"`/`"001"`) and must be customized to match the real, currently-enrolled agent that will actually be sending `log_volume` production data. Since the anomaly detector's `categorical_field` is `agent.name`, OpenSearch maintains a separate model per distinct agent name. If this placeholder doesn't match the real agent, the synthetic baseline gets seeded under a category that agent never reports under, and the ingest step provides no benefit at all for that agent's detection.

Examples:

```yaml
log_volume:
  ingest:
    agent_id: "001"
    agent_name: "edge.vm"
    program: "log_volume_metric"
    log_path: "/var/log"
    index_prefix: "wazuh-ad-log-volume"
    history_minutes: 240        # How much historical data to generate
    step_seconds: 20            # Sampling interval
    delta_query_window: "now-10m"
    delta_min_docs: 2
    fallback_delta: 20000
    baseline_bytes: 228654752   # Starting baseline for progression
```

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
    - Result index and its TTL
    - Rules (suppression below and over certain values)
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
    rules:
      - action: "IGNORE_ANOMALY"
        conditions:
          - feature_name: "log_volume_max"
            threshold_type: "ACTUAL_OVER_EXPECTED_RATIO"
            operator: "LTE"
            value: 0.0001
      - action: "IGNORE_ANOMALY"
        conditions:
          - feature_name: "log_volume_max"
            threshold_type: "EXPECTED_OVER_ACTUAL_RATIO"
            operator: "LTE"
            value: 0.0001

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