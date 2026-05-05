# SONAR: Developer API Reference and Quickstart

SONAR (SIEM-Oriented Neural Anomaly Recognition) is a multivariate time-series anomaly detection subsystem for IDPS-ESCAPE that leverages Microsoft's [time-series-anomaly-detector](https://pypi.org/project/time-series-anomaly-detector/) library. It replaces the MTAD-GAT deep learning approach with a redesigned and more performant solution optimized for Wazuh integration.

> ⚠️ **All commands should be run from project root** (`/home/alab/soar`)

> **Quick demo**: `poetry run sonar scenario --use-case sonar/scenarios/brute_force_detection.yaml --debug`

> **For comprehensive documentation**: See [docs/manual/sonar_docs/](../docs/manual/sonar_docs/) for setup guides, scenario tutorials, troubleshooting, and architecture documentation.

## Architecture

**Technical data flow** (API-level view):

```
WazuhIndexerClient (OpenSearch REST API)
    ↓ [search_alerts()]
WazuhFeatureBuilder (pandas aggregation)
    ↓ [build_timeseries()]
MVADModelEngine (Microsoft MVAD)
    ↓ [train() / predict()]
MVADPostProcessor (result → Wazuh docs)
    ↓ [build_wazuh_anomaly_docs()]
WazuhIndexerClient [index_anomaly()]
```

## Installation

### Via Poetry (recommended)

```bash
# Install the entire project with SONAR
poetry install --with sonar

# Or with test dependencies for development
poetry install --with sonar --with test
```

### Direct pip (if needed)

```bash
pip install time-series-anomaly-detector opensearch-py pandas requests pyyaml
```

## Usage

### Configuration

Create a `config.yaml` file with your Wazuh environment details (minimal example):

```yaml
wazuh:
  base_url: "https://your-opensearch-host:9200"
  username: "admin"
  password: "your-password"
  alerts_index_pattern: "wazuh-alerts-*"

mvad:
  sliding_window: 200

features:
  numeric_fields: ["rule.level"]
  bucket_minutes: 5

model_path: "./mvad_model.pkl"
```

See [default_config.yaml](./default_config.yaml) for complete configuration options including SSL, categorical features, and debug mode.

### CLI commands

#### 1. Define a use-case scenario (YAML)

Create a file `my_scenario.yaml` to define training and detection parameters:

```yaml
name: "My AD Scenario"
description: "Detect anomalies in authentication logs"
enabled: true
model_name: "my_model"  # Optional: auto-generated from scenario name if omitted

training:
  lookback_hours: 48
  numeric_fields:
    - "rule.level"
  categorical_fields: []       # Optional: fields to one-hot encode
  categorical_top_k: 10
  bucket_minutes: 5
  sliding_window: 200
  device: "cpu"
  derived_features: true       # Compute security/resource derived features
  fill_with_synthetic: false   # Auto-fill sparse history with synthetic alerts
  synthetic_count: 100
  synthetic_mode: "random"     # constant, random, or copy

detection:
  mode: "realtime"  # historical, batch, or realtime
  lookback_minutes: 10
  polling_interval_seconds: 300
  threshold: 0.85              # Anomaly score threshold (0.0–1.0)
  min_consecutive: 1           # Min consecutive anomalous buckets required

shipping:                      # Optional: enable for RADAR integration
  enabled: false
  scenario_id: null            # Auto-generated from model path if null

debug:                         # Optional: offline testing without Wazuh
  enabled: false
  data_dir: "./sonar/test_data/synthetic_alerts"
  training_data_file: "normal_baseline.json"
  detection_data_file: "with_anomalies.json"
```

See [example_scenario.yaml](./scenarios/example_scenario.yaml) for a complete template.

#### 2. Execute a use-case scenario

```bash
# Historical detection (assumes model pre-trained)
poetry run sonar scenario --use-case my_scenario.yaml

# Train + detect in batch mode
poetry run sonar scenario --use-case my_scenario.yaml --mode batch

# Real-time continuous detection (ctrl+c to stop)
poetry run sonar scenario --use-case my_scenario.yaml --mode realtime
```

#### 3. Check Wazuh connection

```bash
poetry run sonar check [--config CONFIG_YAML]
```

#### 4. Train model

```bash
poetry run sonar train [--config CONFIG_YAML] [--lookback-hours HOURS] [--ship]
```

Train the MVAD model on historical Wazuh alerts. Defaults to 24 hours of history.

#### 5. Run detection

```bash
poetry run sonar detect [--config CONFIG_YAML] [--lookback-minutes MINUTES] [--ship]
```

Execute anomaly detection on recent Wazuh alerts and index results back into Wazuh.

#### 6. CLI flags reference

Comprehensive list of available flags:

| Command | Flag | Description |
|---------|------|-------------|
| All | `--config YAML` | Path to configuration file (default: `sonar/default_config.yaml`) |
| All | `--debug` | Enable debug mode (uses local JSON test data instead of Wazuh) |
| All | `--print-payloads` | Print all API request/response payloads for debugging |
| All | `--dry-run` | Preview operations without executing (safe for testing) |
| All | `--payload-dir DIR` | Directory to save payload inspection files |
| `train` | `--lookback-hours HOURS` | Hours of historical data for training (default: 24) |
| `train` | `--scenario YAML` | Use scenario file for training configuration |
| `train` | `--model-name NAME` | Model name for saving trained model (auto-generated if omitted) |
| `train` | `--ship` | Create data stream for anomaly shipping (production feature) |
| `train` | `--fill-with-synthetic` | Auto-fill sparse training data with synthetic alerts |
| `train` | `--synthetic-count N` | Number of synthetic alerts to generate (default: minimal required) |
| `train` | `--synthetic-mode MODE` | Synthetic data mode: `constant`, `random`, or `copy` |
| `train` | `--synthetic-level LEVEL` | Alert severity level for `constant` mode (default: 5) |
| `train` | `--synthetic-srcip IP` | Source IP for synthetic alerts in `constant` mode |
| `detect` | `--lookback-minutes MIN` | Minutes of recent data for detection (default: 10) |
| `detect` | `--scenario YAML` | Use scenario file for detection configuration |
| `detect` | `--ship` | Ship anomalies to data stream instead of standard index |
| `detect` | `--fill-with-synthetic` | Auto-fill sparse detection data with synthetic alerts |
| `detect` | `--synthetic-*` | Same synthetic data flags as `train` command |
| `scenario` | `--use-case YAML` | Path to scenario YAML file (required) |
| `scenario` | `--mode MODE` | Override scenario mode: `historical`, `batch`, or `realtime` |
| `scenario` | `--ship` | Enable data shipping for this scenario run |
| `check` | (none) | Connection check command has no additional flags |

**Example usage:**

```bash
# Debug mode with synthetic data
poetry run sonar train --debug --synthetic-count 1000

# Inspect API payloads without execution
poetry run sonar detect --dry-run --print-payloads --payload-dir ./debug

# Production scenario with data shipping
poetry run sonar scenario --use-case sonar/scenarios/brute_force_detection.yaml --ship
```

For complete data shipping setup, see [data-shipping-guide.md](./docs/data-shipping-guide.md).

## Python API

### Quick start

```python
from datetime import datetime, timedelta, timezone
from sonar.config import PipelineConfig
from sonar.engine import MVADModelEngine
from sonar.features import WazuhFeatureBuilder
from sonar.wazuh_client import WazuhIndexerClient

# Load configuration
cfg = PipelineConfig()

# Connect to Wazuh
client = WazuhIndexerClient(cfg.wazuh)

# Fetch 24 hours of alerts
end = datetime.now(timezone.utc)
start = end - timedelta(hours=24)
alerts = client.search_alerts(start, end)

# Build time series features
fb = WazuhFeatureBuilder(cfg.features)
ts_data = fb.build_timeseries(alerts)

# Train model
engine = MVADModelEngine(cfg)
engine.train(ts_data)
engine.save()

# Later: load model and detect
engine2 = MVADModelEngine(cfg)
engine2.load()
recent_alerts = client.search_alerts(
    end - timedelta(minutes=10), end
)
recent_ts = fb.build_timeseries(recent_alerts)
results = engine2.predict(recent_ts)
```

### Component details

#### WazuhIndexerClient

```python
from sonar.wazuh_client import WazuhIndexerClient
from sonar.config import WazuhIndexerConfig

cfg = WazuhIndexerConfig(
    base_url="https://localhost:9200",
    username="admin",
    password="admin"
)
# You can enable payload inspection/dry-run when instantiating the client:
# client = WazuhIndexerClient(cfg, print_payloads=True, dry_run=True, payload_dir="./payloads")
client = WazuhIndexerClient(cfg)

# Check connection
if not client.check_connection():
    print("Connection failed!")

# Fetch alerts
alerts = client.search_alerts(start_dt, end_dt)

# Index anomaly (safe JSON serialization + index resolution)
anomaly_doc = {...}
doc_id = client.index_anomaly(anomaly_doc)
```

#### WazuhFeatureBuilder

```python
from sonar.features import WazuhFeatureBuilder
from sonar.config import FeatureConfig

cfg = FeatureConfig(
    numeric_fields=["rule.level", "data.custom_metric"],
    bucket_minutes=5
)
builder = WazuhFeatureBuilder(cfg)

# Convert alerts to time series
ts_df = builder.build_timeseries(alerts)
# DataFrame: time index, columns = numeric_fields
```

#### MVADModelEngine

```python
from sonar.engine import MVADModelEngine
from sonar.config import PipelineConfig

cfg = PipelineConfig(model_path="./my_model.pkl")
engine = MVADModelEngine(cfg)

# Train
engine.train(ts_df)
engine.save()

# Predict
engine.load()
results = engine.predict(new_ts_df)
```

#### MVADPostProcessor

```python
from sonar.pipeline import MVADPostProcessor
from sonar.config import FeatureConfig

pp = MVADPostProcessor(FeatureConfig())
anomaly_docs = pp.build_wazuh_anomaly_docs(
    timestamps=ts_df.index.to_list(),
    results=model_results,
    context={"lookback_minutes": 10}
)
```

## Testing

Run the comprehensive test suite:

```bash
# Install test dependencies
poetry install --with test

# Run all tests
poetry run pytest tests/sonartests/ -v

# Run with coverage
poetry run pytest tests/sonartests/ --cov=sonar --cov-report=html
```

### Test coverage

Test files in `tests/sonartests/`:

- `test_wazuh_and_pipeline.py`: OpenSearch API mocking, connection checks, anomaly document generation
- `test_engine_and_features.py`: Feature extraction, time-series aggregation, model training, prediction
- `test_config.py`: Configuration initialization and validation
- `test_scenario.py`: Scenario loading, execution modes, CLI integration
- `test_local_data_provider.py`: Debug mode data provider functionality

## Configuration parameters

### WazuhIndexerConfig

| Parameter | Default | Description |
|-----------|---------|-------------|
| `base_url` | `https://localhost:9200` | OpenSearch API endpoint |
| `username` | `admin` | OpenSearch username |
| `password` | `admin` | OpenSearch password |
| `verify_ssl` | `False` | SSL verification (boolean or path to CA) |
| `alerts_index_pattern` | `wazuh-alerts-*` | Wazuh alerts index pattern |
| `anomalies_index` | `wazuh-anomalies-mvad` | Destination anomalies index |

### MVADConfig

| Parameter | Default | Description |
|-----------|---------|-------------|
| `sliding_window` | `200` | Time points in detection window |
| `device` | `cpu` | Computation device (`cpu` or `cuda`) |
| `extra_params` | `{}` | Additional parameters for MVAD library |

### FeatureConfig

| Parameter | Default | Description |
|-----------|---------|-------------|
| `numeric_fields` | `["rule.level"]` | Wazuh fields to extract as features |
| `bucket_minutes` | `5` | Time-series aggregation bucket size |
| `categorical_fields` | `[]` | Wazuh fields to one-hot encode (dot-notation paths) |
| `categorical_top_k` | `10` | Keep top-k categories; group rest into `__other` |
| `derived_features` | `true` | Compute derived security/resource features (auth failures, severity flags, etc.) |
| `alert_filter` | `null` | Optional OpenSearch query fragment to filter alerts on ingestion |
| `max_numeric_fields` | `[]` | Numeric fields for which a per-bucket `<field>__max` column is also computed |

## Troubleshooting

### Connection error to Wazuh indexer
```bash
sonar check --config config.yaml
```
Verify credentials and endpoint URL.

### Empty time series
- Check that alerts exist in the time window
- Verify `numeric_fields` in config exist in your Wazuh alerts
- Increase `--lookback-hours` or `--lookback-minutes` for more data
- If history is sparse, consider `--fill-with-synthetic` to populate synthetic alerts (use `--dry-run` or `--print-payloads` to preview)

### Timestamp parsing
We accept ISO 8601 formats including `Z` (UTC) and fractional seconds. Malformed timestamps are skipped and logged; check logs for warnings about skipped alerts.

### Sliding window / training errors
If training fails with "sliding window is too large" ensure you have at least `sliding_window + 1` time points after aggregation. For development/test scenarios where the configured sliding window equals the library default and the data are tiny, the engine will temporarily use an effective smaller window for the fit (warning is logged); however, setting an explicitly large `sliding_window` still raises a `ValueError`.

### Model file not found
```bash
sonar train --config config.yaml
```
Ensure model is trained before running detection.

### GPU support
Set `device: "cuda"` in `MVADConfig` if you have a compatible GPU. Ensure `torch` with CUDA support is installed.

## Architecture differences from legacy MTAD-GAT implementation

| Aspect | v1 (ADBox) | v2 (SONAR) |
|--------|---------------|----------|
| Algorithm | Research-oriented implementation of slightly modified MTAD-GAT | MTAD-GAT |
| GPU Required | Yes | Optional (works on CPU) |
| Dependencies | PyTorch, TensorBoard | Microsoft MVAD library only |
| Production Readiness | Research | TRL 6 |

## Contributing

To extend SONAR:

1. **Add new features**: Modify `WazuhFeatureBuilder._extract_single_alert_features()`
2. **Custom post-processing**: Subclass or extend `MVADPostProcessor`
3. **Model configuration**: Add parameters to `MVADConfig.extra_params`

## References

- [Microsoft Anomaly Detector](https://pypi.org/project/time-series-anomaly-detector/)
- [IDPS-ESCAPE README](../README.md)
