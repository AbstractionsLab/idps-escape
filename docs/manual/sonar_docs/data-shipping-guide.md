# SONAR data shipping guide

This guide explains how to use SONAR's data shipping feature to send anomaly detection results to dedicated Wazuh data streams for real-time monitoring and integration with RADAR automated responses.

## Table of contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Quick start](#quick-start)
4. [CLI usage](#cli-usage)
5. [Data stream structure](#data-stream-structure)
6. [Integration with RADAR](#integration-with-radar)
7. [Troubleshooting](#troubleshooting)

---

## Overview

### What is data shipping?

Data shipping is an **add-on feature** that enables SONAR to:

1. **Create dedicated data streams** in Wazuh Indexer (OpenSearch) during training
2. **Ship anomaly results** to these streams during detection instead of the default anomaly index
3. **Enable real-time monitoring** of anomaly events with scenario-specific indexing
4. **Integrate with RADAR** for automated incident response

### When to use shipping

| Scenario | Use Shipping? | Reason |
|----------|---------------|--------|
| Real-time detection with automated response | ✅ Yes | RADAR can monitor specific data streams for high-confidence anomalies |
| Historical analysis | ❌ No | Standard anomaly index sufficient for post-mortem investigation |
| Testing/development | ❌ No | Debug mode with local test data is more appropriate |
| Production deployment | ✅ Yes | Enables integration with SIEM dashboards and alerting |

---

## Architecture

### Data flow with shipping enabled

```
┌─────────────────┐
│  SONAR Training │  --ship flag
│   (cmd_train)   │
└────────┬────────┘
         │
         │ Creates data stream template
         ↓
┌─────────────────────────────────────┐
│    Wazuh Indexer (OpenSearch)       │
│                                     │
│  ┌───────────────────────────────┐ │
│  │ Index Template:               │ │
│  │ sonar_stream_template_mvad    │ │
│  │                               │ │
│  │ Components:                   │ │
│  │  - component_template_sonar_  │ │
│  │    mvad (algorithm fields)    │ │
│  │  - component_template_sonar_  │ │
│  │    {scenario_id} (features)   │ │
│  └───────────────────────────────┘ │
│                                     │
│  ┌───────────────────────────────┐ │
│  │ Data Stream:                  │ │
│  │ sonar_anomalies_mvad_{id}     │ │
│  │                               │ │
│  │ Documents:                    │ │
│  │  - timestamp                  │ │
│  │  - is_anomaly: true           │ │
│  │  - anomaly_score: 0.95        │ │
│  │  - threshold: 0.85            │ │
│  │  - scenario_name              │ │
│  │  - feature_values             │ │
│  └───────────────────────────────┘ │
└─────────────────────────────────────┘
         ↑
         │ Ships anomaly documents
         │
┌────────┴────────┐
│ SONAR Detection │  --ship flag
│   (cmd_detect)  │
└─────────────────┘
```

### Template hierarchy

```
Base Template (sonar_stream_template)
│
├── Priority: 1
├── Index Pattern: sonar_anomalies_*
└── Fields:
    ├── is_anomaly (boolean)
    ├── anomaly_score (float)
    ├── threshold (float)
    ├── scenario_name (keyword)
    └── detection_timestamp (date)

MVAD Algorithm Template (sonar_stream_template_mvad)
│
├── Priority: 2
├── Index Pattern: sonar_anomalies_mvad_*
├── Components:
│   └── component_template_sonar_mvad
└── Additional Fields:
    ├── mvad_score (float)
    ├── mvad_threshold (float)
    ├── sliding_window (integer)
    ├── bucket_minutes (integer)
    └── context (object)

Scenario-Specific Template (sonar_detector_mvad_{scenario_id})
│
├── Priority: 3
├── Index Pattern: sonar_anomalies_mvad_{scenario_id}
├── Components:
│   ├── component_template_sonar_mvad
│   └── component_template_sonar_{scenario_id}
└── Additional Fields:
    └── scenario_features (object)
        ├── feature_rule_level (float)
        ├── feature_srcip_count (float)
        └── ... (scenario-specific features)
```

---

## Quick start

### Configuration methods

SONAR supports two ways to enable data shipping:

1. **CLI flag** (quick one-off usage):
   ```bash
   poetry run sonar train --scenario my_scenario.yaml --ship
   ```

2. **YAML configuration** (persistent setting for scenario):
   ```yaml
   # In your scenario YAML file
   shipping:
     enabled: true  # Enable data shipping
     install_templates: true  # Install templates on first run
     scenario_id: "my_custom_id"  # Optional: custom scenario ID
   ```

### Configuration precedence

Shipping is enabled when **both** conditions are met:

1. **Shipping requested** via:
   - CLI `--ship` flag is set **OR**
   - YAML `shipping.enabled: true` is set
   - **Precedence**: CLI flag overrides YAML setting

2. **Debug mode is NOT active**:
   - `--debug` flag **disables shipping** automatically (safety measure)
   - Prevents accidental indexing of test data to production streams

**Decision matrix**:

| CLI `--ship` | YAML `shipping.enabled` | CLI `--debug` | Shipping Active? |
|--------------|-------------------------|---------------|------------------|
| ✅ True      | ❌ False                | ❌ False      | ✅ Yes           |
| ❌ False     | ✅ True                 | ❌ False      | ✅ Yes           |
| ✅ True      | ✅ True                 | ❌ False      | ✅ Yes           |
| ✅ True      | ✅ True                 | ✅ **True**   | ❌ **No** (debug mode) |
| ❌ False     | ❌ False                | ❌ False      | ❌ No            |

**Best practices**:
- **Development/Testing**: Use `--debug` (shipping auto-disabled)
- **Production scenarios**: Set `shipping.enabled: true` in YAML
- **Ad-hoc shipping**: Use `--ship` flag without modifying YAML
- **Never**: Combine `--debug` and `--ship` (debug mode wins)

### 1. Enable shipping during training

Create a data stream for your scenario:

```bash
poetry run sonar train \
    --config configs/my_config.yaml \
    --lookback-hours 168 \
    --ship
```

**Output:**
```
[INFO] Training on 2400 time points...
[INFO] Saving model to ./sonar/models/sonar_scenario_a1b2c3d4.pkl...
[INFO] Initializing data shipper for stream creation...
[INFO] Creating data stream for scenario: sonar_scenario_a1b2c3d4
[INFO] ✓ Data stream ready: sonar_anomalies_mvad_a1b2c3d4
[INFO]   Future detection runs with --ship will index anomalies to this stream
[INFO] ✓ Training complete.
```

### 2. Run detection with shipping

Ship anomalies to the created stream:

```bash
# Batch mode (single detection run)
poetry run sonar detect \
    --config configs/my_config.yaml \
    --lookback-minutes 60 \
    --ship

# Real-time mode (continuous monitoring) - from project root
poetry run sonar scenario \
    --use-case sonar/scenarios/brute_force_detection.yaml \
    --mode realtime \
    --ship
```

**Output:**
```
[INFO] Running detection on 240 time points...
[INFO] Found 3 anomalies.
[INFO] Shipping anomalies to Wazuh data stream...
[INFO]   Shipped anomaly to sonar_anomalies_mvad_a1b2c3d4: abc123
[INFO]   Shipped anomaly to sonar_anomalies_mvad_a1b2c3d4: def456
[INFO]   Shipped anomaly to sonar_anomalies_mvad_a1b2c3d4: ghi789
[INFO] ✓ Shipped 3 anomalies to data stream
```

---

## CLI usage

### Training with shipping

```bash
sonar train [OPTIONS] --ship
```

**What happens:**
1. Model is trained normally
2. Data shipper connects to Wazuh Indexer
3. Base templates are installed (if first time)
4. Scenario-specific data stream template is created
5. Data stream is ready for future anomaly indexing

**Important:** Shipping during training **only creates the infrastructure**. No anomalies are shipped during training.

### Detection with shipping

```bash
sonar detect [OPTIONS] --ship
sonar scenario --use-case YAML --ship
```

**What happens:**
1. Detection runs normally
2. Anomalies are detected and post-processed
3. Instead of indexing to `wazuh-anomalies-mvad`, anomalies are shipped to scenario-specific data stream
4. Each document is indexed with full feature context

---

## YAML configuration

### Configuring shipping in scenario files

Add a `shipping` section to your scenario YAML file for persistent configuration:

```yaml
# Example: sonar/scenarios/brute_force_detection.yaml

name: "Brute Force Attack Detection"
description: "Detect SSH brute force attempts"

# ... wazuh, training, detection sections ...

shipping:
  enabled: true  # Enable data shipping for this scenario
  install_templates: true  # Install base templates on first run
  scenario_id: "brute_force"  # Custom scenario ID (optional)
```

### Configuration options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable/disable data shipping for this scenario |
| `install_templates` | boolean | `true` | Whether to install base index templates on first run |
| `scenario_id` | string | `null` | Custom scenario ID (defaults to hash of model path if not specified) |

### Example: Production scenario with shipping

```yaml
name: "Lateral Movement Detection"
description: "Detect lateral movement patterns using PSExec, WMI, RDP connections"

wazuh:
  base_url: "https://wazuh.production.local:9200"
  alerts_index_pattern: "wazuh-alerts-*"
  username: "admin"
  password: "changeme"
  verify_ssl: true

training:
  lookback_hours: 336  # 14 days
  bucket_minutes: 10
  sliding_window: 144
  categorical_top_k: 20

shipping:
  enabled: true  # Always ship in production
  install_templates: true
  scenario_id: "lateral_movement"  # Consistent ID for RADAR

detection:
  mode: "realtime"
  lookback_minutes: 60
  threshold: 0.75
  min_consecutive: 2
```

**Result**: Every training run creates `sonar_anomalies_mvad_lateral_movement` stream, and all detected anomalies are shipped to it.

---

## Data stream structure

### Scenario ID generation

Each trained model gets a unique scenario ID based on its model path:

```python
import hashlib
scenario_id = hashlib.md5(model_path.encode()).hexdigest()[:8]
# Example: "a1b2c3d4"
```

**Stream name format:** `sonar_anomalies_mvad_{scenario_id}`

**Example:** `sonar_anomalies_mvad_a1b2c3d4`

### Document structure

Each anomaly document contains:

```json
{
  "timestamp": "2026-01-06T15:30:00.000Z",
  "is_anomaly": true,
  "anomaly_score": 0.95,
  "threshold": 0.85,
  "mvad_score": 0.95,
  "mvad_threshold": 0.85,
  "scenario_name": "sonar_scenario_a1b2c3d4",
  "detection_timestamp": "2026-01-06T15:35:00.000Z",
  "alert_count": 450,
  "feature_count": 3,
  "sliding_window": 200,
  "bucket_minutes": 5,
  "context": {
    "model_path": "./models/brute_force_model.pkl",
    "feature_names": ["rule.level", "srcip_count", "dstip_count"],
    "training_samples": 2400
  },
  "scenario_features": {
    "feature_rule_level": 8.5,
    "feature_srcip_count": 15.0,
    "feature_dstip_count": 3.0
  }
}
```

### Field descriptions

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | date | Timestamp of the detection window |
| `is_anomaly` | boolean | Always `true` for shipped documents |
| `anomaly_score` | float | Anomaly severity score (0-1) |
| `threshold` | float | Detection threshold used |
| `mvad_score` | float | MVAD algorithm-specific score |
| `scenario_name` | keyword | Unique scenario identifier |
| `detection_timestamp` | date | When detection was performed |
| `alert_count` | integer | Number of alerts in detection window |
| `feature_count` | integer | Number of features analyzed |
| `sliding_window` | integer | MVAD sliding window size |
| `bucket_minutes` | integer | Time bucket size in minutes |
| `context` | object | Model metadata (path, features, training info) |
| `scenario_features` | object | Feature values that triggered anomaly |

---

## Integration with RADAR

### RADAR monitoring setup

RADAR can monitor SONAR data streams for high-confidence anomalies:

```yaml
# RADAR playbook configuration
- name: Monitor SONAR brute force anomalies
  monitor:
    index: "sonar_anomalies_mvad_a1b2c3d4"
    query:
      bool:
        must:
          - match: { is_anomaly: true }
          - range: { anomaly_score: { gte: 0.9 } }
    polling_interval: 60
  actions:
    - block_srcip
    - notify_soc
    - create_ticket
```

### High-confidence anomaly filtering

```json
GET /sonar_anomalies_mvad_*/_search
{
  "query": {
    "bool": {
      "must": [
        { "term": { "is_anomaly": true } },
        { "range": { "anomaly_score": { "gte": 0.85 } } }
      ]
    }
  },
  "sort": [
    { "detection_timestamp": "desc" }
  ]
}
```

### Scenario-specific monitoring

Monitor specific attack types:

```bash
# Monitor only brute force scenario
GET /sonar_anomalies_mvad_a1b2c3d4/_search

# Monitor all SONAR anomalies
GET /sonar_anomalies_mvad_*/_search

# Monitor recent anomalies (last hour)
GET /sonar_anomalies_mvad_*/_search
{
  "query": {
    "range": {
      "detection_timestamp": {
        "gte": "now-1h"
      }
    }
  }
}
```

---

## Data lifecycle management

### Rollover policy

SONAR automatically installs a rollover policy for data streams:

**Policy: `sonar_rollover_policy`**

```json
{
  "policy": {
    "description": "SONAR anomaly data stream rollover policy",
    "states": [
      {
        "name": "active",
        "transitions": [
          {
            "state_name": "rollover",
            "conditions": {
              "min_index_age": "7d",
              "min_doc_count": 100000
            }
          }
        ]
      },
      {
        "name": "rollover",
        "actions": [{ "rollover": {} }],
        "transitions": [
          {
            "state_name": "delete",
            "conditions": { "min_index_age": "30d" }
          }
        ]
      },
      {
        "name": "delete",
        "actions": [{ "delete": {} }]
      }
    ]
  }
}
```

**Behavior:**
- Rollover after **7 days** or **100,000 documents**
- Delete old indices after **30 days**

### Installing rollover policy

Policy is automatically installed during first training with `--ship`. To manually install:

```python
from sonar.shipper.wazuh_data_shipper import WazuhDataShipper
from sonar.config import WazuhIndexerConfig

config = WazuhIndexerConfig(
    base_url="https://localhost:9200",
    username="admin",
    password="admin"
)

shipper = WazuhDataShipper(config, install=True)
shipper.add_rollover_policy()
```

---

## Troubleshooting

### Issue: "Connection to Wazuh Indexer not available"

**Cause:** Cannot connect to OpenSearch/Wazuh Indexer.

**Solution:**
```bash
# Check Wazuh Indexer status
curl -k -u admin:admin https://localhost:9200/_cluster/health

# Verify credentials in config
cat configs/my_config.yaml
```

### Issue: "SONAR shipper not installed"

**Cause:** Base templates not installed.

**Solution:**
```bash
# Re-run training with --ship to install templates
poetry run sonar train --config configs/my_config.yaml --ship
```

### Issue: Anomalies not appearing in data stream

**Symptoms:**
- Detection completes successfully
- No documents in `sonar_anomalies_mvad_*`

**Diagnosis:**
```bash
# Check if data stream exists
GET /_data_stream/sonar_anomalies_mvad_*

# Check template exists
GET /_index_template/sonar_stream_template_mvad_*

# Check recent documents
GET /sonar_anomalies_mvad_*/_search?size=1&sort=detection_timestamp:desc
```

**Solution:**
- Ensure training was run with `--ship` before detection
- Verify scenario ID matches between training and detection
- Check Wazuh Indexer logs for indexing errors

### Issue: "Failed to ship anomaly"

**Symptoms:** Error during `shipper.ship_single()`

**Common causes:**
1. **Data stream doesn't exist:** Run training with `--ship` first
2. **Permission denied:** Check OpenSearch user permissions
3. **Document validation failed:** Check document structure against template

**Fallback behavior:**
If shipping fails, SONAR automatically falls back to standard anomaly indexing:
```
[ERROR] Failed to ship anomalies: ...
[INFO] Falling back to standard anomaly indexing...
[INFO]   Indexed anomaly: abc123
```

### Issue: Debug mode with shipping

**Behavior:** Shipping is automatically disabled in debug mode.

```bash
# This will skip shipping (no Wazuh connection)
poetry run sonar train --debug --ship

# Output:
[INFO] 🔧 DEBUG MODE ENABLED - Using local test data
[INFO] ✓ Training complete.
# (No shipping messages)
```

**Why:** Debug mode uses local test data and doesn't connect to Wazuh Indexer, so shipping is not applicable.

---

## Advanced usage

### Custom scenario naming

By default, scenario ID is derived from model path. To use custom naming:

```python
from sonar.shipper.wazuh_data_shipper import WazuhDataShipper

shipper = WazuhDataShipper(config, install=False)

# Custom scenario ID
scenario_id = "brute_force_v1"
scenario_name = "Brute Force Detection v1.0"

# Define feature types
features = {
    "rule.level": "float",
    "srcip_count": "integer",
    "failed_login_rate": "float"
}

stream_name = shipper.create_scenario_stream(
    scenario_id=scenario_id,
    scenario_name=scenario_name,
    features=features
)

print(f"Stream created: {stream_name}")
# Output: sonar_anomalies_mvad_brute_force_v1
```

### Bulk shipping

For high-throughput scenarios:

```python
from sonar.shipper.wazuh_data_shipper import WazuhDataShipper

shipper = WazuhDataShipper(config)

# Prepare bulk request
actions = ["index"] * len(anomaly_docs)
bulk_body = shipper.get_bulk_request(
    data=anomaly_docs,
    stream_name="sonar_anomalies_mvad_a1b2c3d4",
    actions=actions
)

# Ship in bulk
response = shipper.ship_bulk(bulk_body)
print(f"Indexed {len(anomaly_docs)} documents")
```

### Deleting data streams

```python
# Delete a specific data stream
shipper.delete_data_stream("sonar_anomalies_mvad_a1b2c3d4")

# Via OpenSearch API
DELETE /sonar_anomalies_mvad_a1b2c3d4
```

**Warning:** This deletes all anomaly records in the stream.

---

## Best practices

### 1. Always train with --ship before detection

```bash
# Wrong: Detection without prior training
poetry run sonar detect --ship  # Stream doesn't exist!

# Correct: Train first, then detect
poetry run sonar train --ship
poetry run sonar detect --ship
```

### 2. Use scenario workflows for production

```bash
# Best: Use scenarios for reproducible workflows (from project root)
poetry run sonar scenario \
    --use-case sonar/scenarios/brute_force_detection.yaml \
    --mode realtime \
    --ship
```

### 3. Monitor data stream health

Set up monitoring for:
- Stream size growth rate
- Document indexing rate
- Rollover status
- Anomaly detection rate

### 4. Use descriptive model paths

```yaml
# Config: my_config.yaml
model_path: "./models/brute_force_ssh_v1.0.pkl"  # Clear naming
```

This creates identifiable scenario IDs and makes debugging easier.

### 5. Test without --ship first

```bash
# 1. Test with standard indexing
poetry run sonar train
poetry run sonar detect

# 2. Verify anomalies in wazuh-anomalies-mvad

# 3. Enable shipping for production
poetry run sonar train --ship
poetry run sonar detect --ship
```

---

## Summary

| Command | With --ship | Without --ship |
|---------|-------------|----------------|
| `sonar train` | Creates data stream template | Trains model only |
| `sonar detect` | Ships to data stream | Indexes to wazuh-anomalies-mvad |
| `sonar scenario` | Full workflow with streaming | Standard workflow |

**Key takeaway:** Shipping is a **production add-on** for real-time monitoring and RADAR integration. Use standard indexing for testing and development.
