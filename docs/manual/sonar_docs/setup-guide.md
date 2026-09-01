# SONAR setup and usage guide

Complete guide for installing, configuring, and using SONAR (SIEM-Oriented Neural Anomaly Recognition).

## Quick start

```bash
# 1. Install dependencies
cd /home/alab/soar
poetry install --with sonar

# 2. Verify installation
poetry run sonar check

# 3. Run a scenario (from project root)
poetry run sonar scenario --use-case sonar/scenarios/brute_force_detection.yaml
```

## Installation

### Prerequisites

- Python 3.10.12 (exact version required)
- Poetry for dependency management
- Wazuh/OpenSearch instance (for production) or debug mode (for development)

### Setup steps

```bash
# Install with all dependencies
poetry install --with sonar,test

# Or production only (faster)
poetry install --with sonar
```

### Verify installation

```bash
# Check Wazuh connection
poetry run sonar check

# Or with custom config
poetry run sonar check --config my_config.yaml
```

## Configuration

### Default configuration

SONAR uses `default_config.yaml` when no `--config` flag is provided.

```yaml
# Wazuh connection settings
wazuh:
  base_url: "https://localhost:9200"
  username: "admin"
  password: "admin"
  verify_ssl: false
  alerts_index_pattern: "wazuh-alerts-*"
  anomalies_index: "wazuh-anomalies-mvad"

# MVAD model settings
mvad:
  sliding_window: 200
  device: "cpu"
  extra_params: {}

# Feature extraction defaults
features:
  numeric_fields: ["rule.level"]
  bucket_minutes: 5
  categorical_fields: []
  categorical_top_k: 10
  derived_features: true

# Debug mode settings
debug:
  enabled: false
  data_dir: "./test_data/synthetic_alerts"
  training_data_file: "normal_baseline.json"
  detection_data_file: "with_anomalies.json"

# Model storage
model_path: "./model/mvad_model.pkl"
```

### Environment-specific configurations

Create custom configs for different environments:

```bash
# Development
poetry run sonar scenario --use-case scenario.yaml --config dev_config.yaml

# Production
poetry run sonar scenario --use-case scenario.yaml --config prod_config.yaml
```

## CLI commands

### Check connection

Verify Wazuh connectivity:

```bash
poetry run sonar check
poetry run sonar check --config custom.yaml
```

### Train model

Train MVAD model on historical data:

```bash
# Train on last 24 hours
poetry run sonar train --lookback-hours 24

# With custom config
poetry run sonar train --lookback-hours 168 --config prod.yaml

# With custom model name
poetry run sonar train --model-name "baseline_v2" --lookback-hours 168

# Enable data shipping (creates data stream)
poetry run sonar train --lookback-hours 168 --ship

# Debug mode (local data)
poetry run sonar train --lookback-hours 24 --debug
```

**All train options:**

| Option | Description | Default |
|--------|-------------|------|
| `--config PATH` | Path to config YAML | `default_config.yaml` |
| `--scenario PATH` | Path to scenario YAML (alternative to --config) | - |
| `--model-name NAME` | Custom model name for saving | Auto-generated |
| `--lookback-hours N` | Hours of historical data for training | 24 |
| `--fill-with-synthetic` | Generate synthetic alerts if data insufficient | False |
| `--synthetic-count N` | Number of synthetic alerts to create | Auto |
| `--synthetic-mode MODE` | Synthetic content mode: constant, random, copy | constant |
| `--synthetic-level N` | Rule level for constant mode | 5 |
| `--synthetic-srcip IP` | Source IP for constant mode | 192.0.2.0 |
| `--print-payloads` | Print JSON payloads before sending | False |
| `--dry-run` | Simulate without sending to Wazuh | False |
| `--payload-dir DIR` | Directory for saved payloads | ./payloads |
| `--debug` | Use local test data instead of Wazuh | False |
| `--ship` | Enable data shipping (create data stream) | False |

### Run detection

Detect anomalies in recent data:

```bash
# Detect in last 10 minutes
poetry run sonar detect --lookback-minutes 10

# Detect on longer lookback period
poetry run sonar detect --lookback-minutes 30

# Enable data shipping (ship to data stream)
poetry run sonar detect --lookback-minutes 10 --ship

# Debug mode
poetry run sonar detect --lookback-minutes 10 --debug
```

**Note:** Detection threshold and min_consecutive parameters are configured in scenario YAML files, not as CLI flags.

**All detect options:**

| Option | Description | Default |
|--------|-------------|------|
| `--config PATH` | Path to config YAML | `default_config.yaml` |
| `--scenario PATH` | Path to scenario YAML (alternative to --config) | - |
| `--lookback-minutes N` | Minutes of recent data to detect on | 10 |
| `--fill-with-synthetic` | Generate synthetic alerts if data insufficient | False |
| `--synthetic-count N` | Number of synthetic alerts to create | Auto |
| `--synthetic-mode MODE` | Synthetic content mode: constant, random, copy | constant |
| `--synthetic-level N` | Rule level for constant mode | 5 |
| `--synthetic-srcip IP` | Source IP for constant mode | 192.0.2.0 |
| `--print-payloads` | Print JSON payloads before sending | False |
| `--dry-run` | Simulate without sending to Wazuh | False |
| `--payload-dir DIR` | Directory for saved payloads | ./payloads |
| `--debug` | Use local test data instead of Wazuh | False |
| `--ship` | Enable data shipping (ship to data stream) | False |

### Scenario execution

Execute complete workflows defined in YAML:

```bash
# Run scenario with training and detection (from project root)
poetry run sonar scenario --use-case sonar/scenarios/brute_force_detection.yaml

# Training only (build baseline)
poetry run sonar scenario --use-case sonar/scenarios/training_only.yaml

# Detection only (use existing model)
poetry run sonar scenario --use-case sonar/scenarios/detection_only.yaml

# Debug mode
poetry run sonar scenario --use-case sonar/scenarios/example_scenario.yaml --debug
```

**Note:** All paths are relative to project root (`/home/alab/soar/`).

## Debug mode

Run SONAR without Wazuh infrastructure using local JSON test data.

### Enable debug mode

**Option 1: Command-line flag**
```bash
poetry run sonar train --debug
poetry run sonar detect --debug
poetry run sonar scenario --use-case scenario.yaml --debug
```

**Option 2: Configuration file**
```yaml
debug:
  enabled: true
  data_dir: "sonar/test_data/resource_monitoring"  # Relative to project root
  training_data_file: "resource_monitoring_training.json"
  detection_data_file: "resource_monitoring_detection.json"
```

### Test data structure

Test data should be JSON files containing Wazuh alert arrays:

```json
[
  {
    "timestamp": "2025-12-29T10:00:00.000Z",
    "rule": {
      "id": "5406",
      "level": 3,
      "groups": ["authentication", "sudo"]
    },
    "agent": {
      "id": "001",
      "name": "web-server-01"
    },
    "data": {
      "cpu_usage_%": 45.2,
      "memory_usage_%": 62.1
    }
  }
]
```

### Available test datasets

**Path resolution:** All paths in debug configuration are relative to the `sonar/` module directory.

| Dataset | Location | Description |
|---------|----------|-------------|
| Normal baseline | `test_data/synthetic_alerts/normal_baseline.json` | 12,000 normal alerts |
| With anomalies | `test_data/synthetic_alerts/with_anomalies.json` | 6,000 alerts with anomalies |
| Normal training | `test_data/generated_scenarios/normal_training.json` | 12,000 alerts with realistic patterns |
| Attack scenarios | `test_data/generated_scenarios/attack_scenarios.json` | 2,000 alerts with known attacks |
| Resource monitoring (train) | `test_data/resource_monitoring/resource_monitoring_training.json` | 24h normal system activity |
| Resource monitoring (detect) | `test_data/resource_monitoring/resource_monitoring_detection.json` | 6h with CPU/memory attacks |

### Generate custom test data

Use the provided generators:

```bash
# Resource monitoring data
poetry run python sonar/test_data/generate_resource_data.py

# Attack scenarios
poetry run python sonar/test_data/generate_attack_data.py
```

## Integration with Wazuh

### Alert ingestion

SONAR reads from Wazuh alert indices:
- Pattern: `wazuh-alerts-*` (configurable)
- Time-based queries using `timestamp` field
- Supports OpenSearch query DSL for filtering

### Anomaly indexing

Detected anomalies are written to:
- Index: `wazuh-anomalies-mvad` (configurable)
- Document structure matches Wazuh alert format with added fields:
  - `anomaly_score`: Confidence score (0-1)
  - `detection_timestamp`: When anomaly was detected
  - `model_version`: Model identifier

### RADAR integration

SONAR anomalies can trigger RADAR responses:

1. RADAR monitors `wazuh-anomalies-mvad` index
2. High-score anomalies (≥ threshold) trigger automated responses
3. Response playbooks defined in RADAR configuration

## Production deployment

### Recommended workflow

```bash
# 1. Initial baseline (weekly) - from project root
poetry run sonar scenario --use-case sonar/scenarios/brute_force_detection.yaml

# 2. Continuous monitoring (cron/systemd)
*/10 * * * * poetry run sonar detect --lookback-minutes 10

# 3. Weekly retraining (cron)
0 2 * * 0 poetry run sonar train --lookback-hours 168
```

### Docker deployment

SONAR is included in the main IDPS-ESCAPE stack:

```bash
# Build container
docker build -f sonar/Dockerfile.sonar -t sonar:latest .

# Run in docker-compose stack
docker-compose up -d sonar
```

### Monitoring and logging

SONAR uses Python logging:

```python
import logging
logging.basicConfig(level=logging.INFO)
```

Logs include:
- Data ingestion statistics
- Feature extraction details
- Model training progress
- Detected anomalies with scores

## Performance considerations

### Resource requirements

- **CPU**: 2+ cores recommended for MVAD training
- **Memory**: 2-4 GB depending on alert volume
- **Disk**: Minimal (model ~10 MB, logs rotated)

### Optimization tips

1. **Bucket size**: Larger buckets (10-15 min) reduce feature count
2. **Sliding window**: Keep 100-300 for most use cases
3. **Categorical encoding**: Limit with `categorical_top_k` parameter
4. **Historical lookback**: Balance between baseline quality and performance

## Common use cases

### Brute force detection

```yaml
name: "Brute Force Detection"
training:
  lookback_hours: 168  # 1 week baseline
  numeric_fields: ["rule.level"]
  categorical_fields: ["agent.id", "rule.groups"]
  bucket_minutes: 5
detection:
  mode: "historical"
  lookback_minutes: 60
  threshold: 0.7
```

### Resource monitoring

```yaml
name: "Linux Resource Monitoring"
training:
  lookback_hours: 24
  numeric_fields: ["data.cpu_usage_%", "data.memory_usage_%", "rule.level"]
  categorical_fields: ["agent.name", "rule.groups"]
  bucket_minutes: 1
detection:
  mode: "batch"
  lookback_minutes: 10
  threshold: 0.85
```

### Lateral movement detection

```yaml
name: "Lateral Movement Detection"
training:
  lookback_hours: 336  # 2 weeks
  numeric_fields: ["rule.level"]
  categorical_fields: ["agent.id", "data.srcip", "data.dstip"]
  bucket_minutes: 10
detection:
  mode: "realtime"
  polling_interval_seconds: 60
  threshold: 0.8
```

## Testing

### Unit tests

```bash
# All tests
poetry run pytest tests/sonartests/

# Specific test file
poetry run pytest tests/sonartests/test_engine_and_features.py

# With coverage
poetry run pytest --cov=sonar --cov-report=html tests/sonartests/
```

### Integration tests

```bash
# Test with debug mode
poetry run sonar scenario --use-case scenarios/example_scenario.yaml --debug

# Verify outputs
ls model/mvad_model.pkl
```

## Troubleshooting

See [troubleshooting.md](./troubleshooting.md) for detailed error diagnosis and solutions.

### Quick fixes

**Connection errors:**
```bash
# Check Wazuh is running
curl -u admin:admin https://localhost:9200/_cluster/health

# Use debug mode for development
poetry run sonar train --debug
```

**Feature mismatch errors:**
- Ensure consistent categorical values between training and detection
- Column alignment is automatic in SONAR
- Check logs for feature count details

**Model not found:**
```bash
# Train before detection
poetry run sonar train --lookback-hours 24

# Or specify model path
poetry run sonar detect --model-path ./custom_model.pkl
```