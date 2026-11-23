# SONAR: Developer API Reference and Quickstart

SONAR (SIEM-Oriented Neural Anomaly Recognition) is a multivariate time-series anomaly detection subsystem for IDPS-ESCAPE that leverages Microsoft's [time-series-anomaly-detector](https://pypi.org/project/time-series-anomaly-detector/) library. It replaces the MTAD-GAT deep learning approach with a redesigned and more performant solution optimized for Wazuh integration.

> **Quick demo**: `poetry run sonar scenario --use-case linux_resource_monitoring --debug`
>
> Works from any directory: `--use-case` accepts the name of a packaged example scenario, paths inside configuration and scenario files are relative to those files, and models go to `sonar/models/<model_name>/` (see the [model guide](../docs/manual/sonar_docs/model-naming-guide.md)). The examples below name files relative to the project root (`/home/alab/soar`).

> **For comprehensive documentation**: See [docs/manual/sonar_docs/](../docs/manual/sonar_docs/) for setup guides, scenario tutorials, troubleshooting, and architecture documentation.

## Architecture

**Technical data flow** (API-level view):

```
WazuhIndexerClient (opensearch-py, client from sonar/indexer.py)
    ↓ [search_alerts()]
WazuhFeatureBuilder (pandas aggregation)
    ↓ [build_timeseries()]
ModelEngine (feature contract, model directory)
    ↓ [train() / predict()] → DetectorBackend: mvad (Microsoft MVAD), pca (linear multivariate) or ewma (baseline)
MVADPostProcessor (PointResult → anomaly docs)
    ↓ [build_wazuh_anomaly_docs()]
sinks.deliver() → WazuhSink (Wazuh manager: file or POST /events), DataStreamSink, IndexSink, JsonlSink, StdoutSink
```

By default anomalies go to the Wazuh manager, which raises them as alerts with SONAR's rules (`sonar/wazuh/rules/sonar_rules.xml`, IDs 100500–100519). See [Wazuh integration](../docs/manual/sonar_docs/setup-guide.md#wazuh-integration) and the [anomaly output guide](../docs/manual/sonar_docs/data-shipping-guide.md).

## Installation

### Via Poetry (recommended)

```bash
# The project with SONAR
poetry install --with sonar

# Or with test dependencies for development
poetry install --with sonar --with test

# Or only what SONAR needs (as the Docker image does)
poetry install --only main,sonar
```

The `sonar` group declares everything SONAR imports: `time-series-anomaly-detector`, `torch`, `numpy`, `pandas`, `opensearch-py`, `pyyaml` and `requests`. `python -m sonar` works like the `sonar` command.

### Wheel

The wheel built by `poetry build -f wheel` ships the example scenarios, the debug datasets they use, `default_config.yaml` and `sonar/wazuh/`. Its `sonar` extra installs SONAR's dependencies (Python 3.10.12):

```bash
pip install "idps_escape-2.2.0-py3-none-any.whl[sonar]"
sonar scenario --use-case linux_resource_monitoring --debug   # models in ~/.sonar, or $SONAR_HOME
```

See [Installing the wheel](../docs/manual/sonar_docs/setup-guide.md#installing-the-wheel).

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

model_name: my_model          # the model is <models_dir>/my_model/
# models_dir: /var/lib/sonar/models   # default: sonar/models/ in a checkout; relative = relative to this file
```

`sonar train --config config.yaml` and `sonar detect --config config.yaml` both use `<models_dir>/my_model/`. Without `model_name`, the name is `sonar`. The old `model_path` key is still read, with a deprecation warning. A `--config` file replaces `default_config.yaml` rather than adding to it.

A `--config` file is loaded by `load_config`, which reads `features.numeric_fields`, `categorical_fields`, `categorical_top_k`, `bucket_minutes`, `derived_features`, `alert_filter` and `max_numeric_fields`.

See [default_config.yaml](./default_config.yaml) for complete configuration options including SSL, categorical features, and debug mode.

### CLI commands

#### 1. Define a use-case scenario (YAML)

Create a file `my_scenario.yaml` to define training and detection parameters:

```yaml
name: "My AD Scenario"
description: "Detect anomalies in authentication logs"
enabled: true
model_name: "my_model"  # Optional; default: the name above in lower case (my_ad_scenario)

training:
  backend: mvad                # mvad (default), pca (linear multivariate, no torch) or ewma (per-feature baseline, no torch)
  lookback_hours: 168          # 2016 five-minute buckets
  numeric_fields:
    - "rule.level"
  categorical_fields: []       # Optional: fields counted per value (top-k vocabulary + __other)
  categorical_top_k: 10
  bucket_minutes: 5
  sliding_window: 200
  device: "cpu"
  extra_params:
    interval: 1                # train on every window position (see the scenario guide)
  derived_features: true       # true, false, or a list such as [is_auth_failure, is_ssh_event]
  numeric_fill: zero           # empty buckets: zero, or ffill for gauge metrics

detection:
  mode: "realtime"  # historical, batch, or realtime
  lookback_minutes: 60         # Window to score; earlier context is fetched automatically
  ingest_delay_seconds: 60     # Score a bucket only this long after it ended (late alerts)
  max_consecutive_failures: 5  # Realtime: exit 1 after this many failed polls in a row
  threshold: null              # Optional minimum MVAD severity (0-1) on top of MVAD's flag
  min_consecutive: 1           # Minimum run of consecutive anomalous buckets
  anomaly_confidence: null     # Measured precision (0-1), sent to Wazuh; null sends 0.5 with a warning

output:                        # Optional: where anomalies go (defaults in default_config.yaml)
  sinks: [wazuh]               # wazuh, datastream, index, jsonl, stdout
  wazuh:
    transport: file            # file (SONAR on the manager host) or api (dedicated host)

shipping:                      # Optional: scenario ID and the data stream
  enabled: false               # true adds the datastream sink
  scenario_id: null            # null: the model name (names the stream and the watermark file)

debug:                         # Optional: offline testing without Wazuh
  enabled: false
  data_dir: "../test_data/synthetic_alerts"   # relative to this file; unset: the packaged synthetic_alerts
  training_data_file: "normal_baseline.json"
  detection_data_file: "with_anomalies.json"
```

See [example_scenario.yaml](./scenarios/example_scenario.yaml) for a complete template.

Notes on what the code does with these keys:

- **`threshold` and `min_consecutive` filter the backend's anomalies.** A bucket is reported only when the backend's own `is_anomaly` flag is set, its severity (between 0 and 1; for MVAD, score / (e − 1)) is at least `threshold` when one is set, and it belongs to a run of at least `min_consecutive` such buckets. Set a threshold or raise `min_consecutive` to cut false positives. `threshold` defaults to `null`; a value outside [0, 1] is an error when the scenario loads. Plain `sonar detect` without `--scenario` applies no extra filter.
- **`lookback_minutes` is the window to score.** Detection scores the complete buckets of the last `lookback_minutes` (the current, still filling bucket is never scored) and fetches the `input_size + threshold_window − 1` buckets of context the model needs before them, so any lookback of at least one bucket works. Training needs many more buckets than `sliding_window`; `train` states how many when there are too few.
- **Obsolete keys are ignored.** `fill_with_synthetic`, `synthetic_count`, `synthetic_mode`, `synthetic_level` and `synthetic_srcip` log a warning and have no effect: SONAR no longer writes alerts to Wazuh.
- **All scenario keys apply to every scenario command.** `sonar scenario --use-case`, `sonar train --scenario` and `sonar detect --scenario` apply the same `training:` keys (including `backend`, `derived_features`, `alert_filter` and `max_numeric_fields`), `model_name`, `models_dir` and the `wazuh:`, `debug:`, `shipping:` and `output:` sections.
- **Paths in the file are relative to the file.** `models_dir`, `debug.data_dir`, `output.state_dir`, `output.jsonl_path`, `output.wazuh.file_path` and `detection.payload_dir`; unset ones default to the SONAR home (`$SONAR_HOME`, else `sonar/` in a checkout, else `~/.sonar`).
- **Debug runs deliver to the debug sinks.** `--debug` (local test data) and `debug.enabled: true` (which still reads alerts from Wazuh) send the anomalies to `output.debug_sinks`, by default `stdout`: one SONAR event per line on standard output, logs on standard error. No watermark is used.

#### 2. Execute a use-case scenario

```bash
# Run with the detection mode from the YAML
poetry run sonar scenario --use-case my_scenario.yaml

# Override the mode: one detection run (batch behaves exactly like historical)
poetry run sonar scenario --use-case my_scenario.yaml --mode historical

# Real-time continuous detection (ctrl+c to stop)
poetry run sonar scenario --use-case my_scenario.yaml --mode realtime
```

Which phases run depends only on the YAML sections, not on `--mode`. If the file has a `training:` section, every run retrains the model first, replacing the previous one, then detects. A detection-only file loads the existing model from `<models_dir>/<model_name>/` (`sonar/models/<model_name>/` in a checkout). `--mode` only selects the detection mode.

#### 3. Check Wazuh connection

```bash
poetry run sonar check [--config CONFIG_YAML]
```

#### 4. Install SONAR's Wazuh rules

```bash
poetry run sonar wazuh install-rules [--config CONFIG_YAML] [--api-url URL] [--user USER] [--restart]
```

Uploads `sonar/wazuh/rules/sonar_rules.xml` to the manager through its API (`PUT /rules/files/sonar_rules.xml?overwrite=true`) and, with `--restart`, restarts the manager. The user needs `rules:update` (an administrator, not the `event:ingest` user); with `--user`, its password comes from `SONAR_WAZUH_ADMIN_PASSWORD` or a prompt. See [Install the rules](../docs/manual/sonar_docs/setup-guide.md#install-the-rules).

#### 5. Train model

```bash
poetry run sonar train [--config CONFIG_YAML] [--scenario YAML] [--model-name NAME] [--lookback-hours HOURS] [--ship]
```

Train the model (MVAD unless `backend` is `pca` or `ewma`) on historical Wazuh alerts and save it to `<models_dir>/<model_name>/`. Defaults to 168 hours of history. `train` exits with status 0 when the model was saved and 1 on any failure; with too few buckets for MVAD to train, it logs an error stating how many are needed and saves nothing.

`--config` and `--scenario` can be combined: the config is the base and the scenario is merged over it. With `--scenario`, the query window is the scenario's `lookback_hours` unless `--lookback-hours` is given.

#### 6. Run detection

```bash
poetry run sonar detect [--config CONFIG_YAML] [--lookback-minutes MINUTES] [--ship]
```

Execute anomaly detection on recent Wazuh alerts and deliver the anomalies to the configured sinks (by default the Wazuh manager). With `--scenario`, the window is the scenario's `lookback_minutes` unless `--lookback-minutes` is given, and the scenario's `threshold` and `min_consecutive` apply. Without a scenario the default is 10 minutes. The context the model needs before the window is fetched automatically.

Exit status: 0 when the window was scored and its anomalies reached at least one sink, 2 when there was too little data to score anything (no alerts, or fewer buckets than the model needs), 1 on an error (unknown sink, model missing or incompatible, connection failure, prediction error, or every sink failed and no fallback stored the anomalies). A sink that failed while others succeeded retries on the next run, thanks to its own watermark. `sonar scenario` in `historical` or `batch` mode returns the same codes.

`detect` has no `--model-name`: it loads the model named by the scenario (`model_name`, else its `name`) or by the config's `model_name`. A separate `train` and `detect` with the same scenario or config use the same model.

#### 7. Evaluate detection quality

```bash
poetry run sonar evaluate --scenario NAME_OR_YAML --train-file F --test-file F --test-labels F \
  [--validation-file F --validation-labels F] [--config YAML] [--backend mvad|pca|ewma] [--agent NAME] [--event-types a,b] \
  [--tolerance-minutes N] [--max-false-alarms-per-day N] [--output-dir DIR] [--name NAME]
poetry run sonar evaluate --detections F --test-labels F [--validation-detections F --validation-labels F] [--detector-name NAME]
```

Trains the scenario's backend on a labelled alert file (or reads another detector's results) and reports event-level precision, recall, F1, detection delay and false alarms per day as JSON and Markdown. With a validation split it calibrates `threshold` and `min_consecutive` within the false-alarm budget (`--max-false-alarms-per-day`, default 5) and measures `anomaly_confidence`. The report is `<output-dir>/<name>.json` and `.md`; without `--name` it is `<scenario>-<backend>`, or the detector name with `--detections`. See the [evaluation guide](../docs/manual/sonar_docs/evaluation-guide.md).

#### 8. Export a live window for evaluation

```bash
poetry run sonar export --scenario NAME_OR_YAML --start T --end T --output-dir DIR \
  [--agent NAME] [--radar-results INDEX] [--event TYPE,START,END ...] [--context-minutes N]
```

Writes the scenario's alerts of the window (plus the context its backend needs before it), a label file and, with `--radar-results`, the results of a RADAR detector, as inputs of `sonar evaluate`. Exit status 2 when the window holds no alerts. See the [RADAR comparison guide](../docs/manual/sonar_docs/radar-comparison-guide.md).

#### 9. CLI flags reference

Comprehensive list of available flags:

| Command | Flag | Description |
|---------|------|-------------|
| All | `--config YAML` | Path to configuration file (default: `sonar/default_config.yaml`). For `scenario` it is the base the use case is merged over |
| `train`, `detect`, `scenario` | `--debug` | Use local JSON test data instead of Wazuh. Anomalies go to `output.debug_sinks` (default: stdout), without watermarks |
| `detect`, `scenario` | `--print-payloads` | Also print the SONAR events on standard output (adds the `stdout` sink) |
| `detect`, `scenario` | `--dry-run` | Write the SONAR events to `<payload-dir>/anomalies.jsonl` instead of the configured sinks; no watermark |
| `detect`, `scenario` | `--payload-dir DIR` | Directory of the dry-run file (default: the scenario's `detection.payload_dir`, else `<SONAR home>/payloads`) |
| `train`, `detect`, `scenario`, `evaluate`, `export` | `--agent NAME` | Only this `agent.name`: model `<model_name>-<NAME>`, scenario ID with the same suffix, the agent added to `alert_filter` (and applied to local files) |
| `train` | `--lookback-hours HOURS` | Hours of historical data for training (default: the scenario's `lookback_hours`, else 168) |
| `train` | `--scenario YAML` | Use scenario file for training configuration |
| `train` | `--model-name NAME` | Save the model as `<models_dir>/NAME/` (default: the scenario's or config's model name) |
| `train` | `--ship` | Install the data stream's index templates and ISM policy (the stream is created by the first anomaly written to it) |
| `detect` | `--lookback-minutes MIN` | Minutes of complete buckets to score; earlier context is fetched automatically (default: the scenario's `lookback_minutes`, else 10) |
| `detect` | `--scenario YAML` | Use scenario file for detection configuration |
| `detect` | `--ship` | Add the `datastream` sink (the scenario's data stream) to the configured sinks |
| `scenario` | `--use-case YAML` | Path to scenario YAML file, or the name of a packaged example such as `linux_resource_monitoring` (required) |
| `scenario` | `--mode MODE` | Override scenario mode: `historical`, `batch`, or `realtime` |
| `scenario` | `--ship` | Add the `datastream` sink for this run. It is added if either `--ship` or YAML `shipping.enabled` is set; the CLI cannot remove it |
| `check` | `--config YAML` | The only flag `check` accepts |
| `wazuh install-rules` | `--api-url`, `--user`, `--restart` | See [Install SONAR's Wazuh rules](#4-install-sonars-wazuh-rules) |
| `evaluate` | see above | See [Evaluate detection quality](#7-evaluate-detection-quality) |
| `export` | see above | See [Export a live window for evaluation](#8-export-a-live-window-for-evaluation) |

`train` also accepts `--print-payloads`, `--dry-run` and `--payload-dir`, but has no effect with them, since training writes no anomalies.

**Example usage:**

```bash
# Debug mode with the scenario's local test data
poetry run sonar scenario --use-case sonar/scenarios/linux_resource_monitoring.yaml --debug

# Inspect the SONAR events without delivering them (written to ./debug/anomalies.jsonl and printed)
poetry run sonar detect --dry-run --print-payloads --payload-dir ./debug

# Production scenario: Wazuh manager plus the scenario's data stream
poetry run sonar scenario --use-case sonar/scenarios/brute_force_detection.yaml --ship
```

For the sinks, the event format and delivery, see the [anomaly output guide](../docs/manual/sonar_docs/data-shipping-guide.md).

## Python API

### Quick start

```python
from datetime import datetime, timedelta, timezone
from sonar.config import PipelineConfig
from sonar.engine import ModelEngine
from sonar.features import WazuhFeatureBuilder
from sonar.wazuh_client import WazuhIndexerClient

# Load configuration (train on every window position, as the shipped configs do).
# The model is <models_dir>/<model_name>/; models_dir defaults to models/ in the SONAR home.
cfg = PipelineConfig(model_name="my_model")
cfg.mvad.extra_params = {"interval": 1}

# Connect to Wazuh
client = WazuhIndexerClient(cfg.wazuh)

# Fetch 7 days of alerts (MVAD needs about 3.5 days of 5-minute buckets to train)
end = datetime.now(timezone.utc)
start = end - timedelta(hours=168)
alerts = client.search_alerts(start, end)

# Build time series features
fb = WazuhFeatureBuilder(cfg.features)
ts_data = fb.build_timeseries(alerts)

# Train model (the vocabulary is stored with it, so detection builds the same columns)
engine = ModelEngine(cfg)
engine.train(ts_data, vocabulary=fb.vocabulary)
engine.save()

# Later: load model and score the last 10 minutes of complete buckets
engine2 = ModelEngine(cfg)
engine2.load()
bucket = timedelta(minutes=cfg.features.bucket_minutes)
now = datetime.now(timezone.utc)
end = datetime.fromtimestamp(now.timestamp() // bucket.total_seconds() * bucket.total_seconds(), tz=timezone.utc)
# The backend needs engine2.context_buckets buckets before the first bucket it scores
fetch_start = end - timedelta(minutes=10) - engine2.context_buckets * bucket
recent_alerts = client.search_alerts(fetch_start, end)
detect_fb = WazuhFeatureBuilder(engine2.feature_config, vocabulary=engine2.vocabulary)
recent_ts = detect_fb.build_timeseries(recent_alerts, start=fetch_start, end=end)
results = engine2.predict(recent_ts)  # one PointResult per bucket from fetch_start + context on
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
# client = WazuhIndexerClient(cfg, print_payloads=True, dry_run=True, payload_dir="/tmp/payloads")
client = WazuhIndexerClient(cfg)

# Check connection
if not client.check_connection():
    print("Connection failed!")

# Fetch every alert in [start_dt, end_dt), oldest first. The client pages through the
# matches with a point-in-time and search_after, and stops at cfg.max_alerts, keeping
# the most recent alerts (with a warning).
alerts = client.search_alerts(start_dt, end_dt)

# Fetch only the fields the features read (as the CLI does)
# alerts = client.search_alerts(start_dt, end_dt, source_fields=WazuhFeatureBuilder(feature_cfg).required_source_fields())

# Index anomaly (safe JSON serialization + index resolution). A document with an
# anomaly_id is created under that id; if the index already holds it, that is not an error.
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
# DataFrame: one row per bucket (empty buckets included); columns = alert_count,
# numeric_fields (means), <field>__max for max_numeric_fields, derived-feature counts
# (all 13 by default) and per-value category counts. The vocabulary fitted here is in
# builder.vocabulary; pass it to ModelEngine.train so detection reuses it.
```

#### ModelEngine and the detector backends

```python
from sonar.engine import ModelEngine
from sonar.config import PipelineConfig

cfg = PipelineConfig(models_dir="/var/lib/sonar/models", model_name="my_model", backend="ewma")
engine = ModelEngine(cfg)

# Train and write /var/lib/sonar/models/my_model/ (metadata.json + ewma_state.json)
engine.train(ts_df, vocabulary=builder.vocabulary)
engine.save()

# Load (no unpickling) and predict
engine.load()
results = engine.predict(new_ts_df)  # List[PointResult]
for r in results:
    if r.is_anomaly:
        print(r.timestamp, r.severity, r.raw_score, [c.variable for c in r.contributors[:3]])
```

`backend="mvad"` (the default) uses Microsoft MVAD and writes `mvad_config.json` and `mvad_weights.pt`. A backend implements `sonar.backends.DetectorBackend` (`fit`, `predict` returning `PointResult`, `save_state`, `from_state`, `min_points`, `metadata`); see [Detector backends](../docs/manual/sonar_docs/architecture.md#detector-backends). `MVADModelEngine` remains as an alias of `ModelEngine`.

#### MVADPostProcessor

```python
from sonar.pipeline import MVADPostProcessor
from sonar.config import FeatureConfig

pp = MVADPostProcessor(FeatureConfig())
anomaly_docs = pp.build_wazuh_anomaly_docs(
    results=results,  # List[PointResult] from ModelEngine.predict
    context={"scenario_id": "my_model", "model_name": "my_model", "lookback_minutes": 10},
)
```

## Testing

Run the comprehensive test suite:

```bash
# Install test dependencies
poetry install --with test

# Run the tests
poetry run pytest tests/sonartests/ -v

# Skip the slow tests (the real MVAD library, the MVAD regression, the wheel build)
poetry run pytest tests/sonartests/ -m "not slow"

# Run with coverage
poetry run pytest tests/sonartests/ --cov=sonar --cov-report=html
```

### Test coverage

Test files in `tests/sonartests/`:

- `test_wazuh_and_pipeline.py`: Anomaly document generation (threshold, runs, contributors)
- `test_engine_and_features.py`: Feature extraction, time-series aggregation, model training, prediction
- `test_config.py`: Configuration initialization and validation
- `test_scenario.py`: Scenario loading, execution modes, CLI integration
- `test_local_data_provider.py`: Debug mode data provider functionality
- `test_detection_cli.py`: Detection window and context, exit codes, one detection path for every command
- `test_evaluation.py`: Detection-quality metrics, calibration and the `sonar evaluate` command
- `test_features_v2.py`: Feature schema 2 (time grid, volume features, vocabulary, feature contract)
- `test_indexer_client.py`: The shared OpenSearch client (TLS options), paged point-in-time alert search, `max_alerts` cap, source filtering
- `test_engine_real_mvad.py`: Training and prediction with the real MVAD library (marked `slow`)
- `test_e2e_detection.py`: End to end with real detectors (MVAD and `pca`): generated alerts with injected anomalies, features, training, verdicts and sinks (marked `slow`)
- `test_backends.py`: The backend contract for `mvad`, `pca` and `ewma`, what `pca` finds (broken correlations, features that never moved), the model directory format, and the MVAD regression against verdicts recorded before the backend interface (MVAD tests marked `slow`)
- `test_paths.py`: The SONAR home, file-relative paths, model names, packaged examples
- `test_radar_alignment.py`: SONAR on RADAR's `linux_resource_utilization` data: the packaged scenario, one model per agent (`--agent`), RADAR's detector results and `sonar export`
- `test_packaging.py`: Builds the wheel and runs a packaged example outside the repository (marked `slow`; needs `poetry`)
- `test_realtime_delivery.py`: At-most-once delivery (anomaly ids, watermark), realtime polling and backoff
- `test_shipper.py`: Index templates, ISM policy and data-stream writes
- `test_sinks.py`: Sinks, SONAR events, the Wazuh file and API transports, per-sink watermarks and fallback

## Configuration parameters

### WazuhIndexerConfig

| Parameter | Default | Description |
|-----------|---------|-------------|
| `base_url` | `https://localhost:9200` | OpenSearch API endpoint |
| `username` | `admin` | OpenSearch username |
| `password` | `admin` | OpenSearch password |
| `verify_ssl` | `False` | Certificate verification: `False` (none), `True` (system trust store), or a CA bundle path such as the Wazuh `root-ca.pem`. When verifying, the `base_url` host must match the certificate. Applies to alert search and the `datastream` and `index` sinks |
| `alerts_index_pattern` | `wazuh-alerts-*` | Wazuh alerts index pattern |
| `anomalies_index` | `wazuh-anomalies-mvad` | Index of the legacy `index` sink |
| `timeout_seconds` | `30.0` | Timeout for every request to the indexer |
| `max_alerts` | `2000000` | Most alerts one search returns; beyond it the most recent are kept, with a warning |
| `exclude_rule_groups` | `["sonar"]` | Alerts in these rule groups are never read, so SONAR does not learn from its own alerts; `[]` disables |

### MVADConfig

| Parameter | Default | Description |
|-----------|---------|-------------|
| `sliding_window` | `200` | Time points in detection window |
| `device` | `cpu` | Computation device (`cpu` or `cuda`) |
| `extra_params` | `{}` | Additional parameters for MVAD library |
| `min_gradient_steps` | `500` | Warn when training would perform fewer optimiser updates |

### PCAConfig

The `pca` backend's settings (top-level `pca:` in a config, `training.pca` in a scenario):

| Parameter | Default | Description |
|-----------|---------|-------------|
| `window` | `3` | Buckets that score a bucket: the bucket and the `window - 1` before it |
| `variance` | `0.95` | Share of the training variance the principal components keep (0 < variance < 1) |
| `z_threshold` | `4.0` | Robust z-score of a window's distance from which a bucket is anomalous; a bucket at the threshold has severity 0.5 |

### EWMAConfig

The `ewma` backend's settings (top-level `ewma:` in a config, `training.ewma` in a scenario):

| Parameter | Default | Description |
|-----------|---------|-------------|
| `alpha` | `0.5` | EWMA smoothing factor, 0 < alpha ≤ 1 (1: no smoothing) |
| `z_threshold` | `4.0` | Robust z-score from which a bucket is anomalous; a bucket at the threshold has severity 0.5 |

### Model settings (PipelineConfig)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `backend` | `mvad` | Detector trained: `mvad`, `pca` or `ewma`. A loaded model brings its own |
| `models_dir` | `None` | Directory of the models; `None`: `models/` in the SONAR home |
| `model_name` | `sonar` | The model is `<models_dir>/<model_name>/` |

### FeatureConfig

| Parameter | Default | Description |
|-----------|---------|-------------|
| `numeric_fields` | `["rule.level"]` | Wazuh fields to extract as features |
| `bucket_minutes` | `5` | Time-series aggregation bucket size |
| `categorical_fields` | `[]` | Wazuh fields counted per value (dot-notation paths) |
| `categorical_top_k` | `10` | Values per field in the vocabulary fitted at training; all others are counted in `<field>__other` |
| `derived_features` | `true` | Per-bucket counts of alerts matching a condition (auth failures, severity, metric thresholds): `true`, `false` or a list of names |
| `numeric_fill` | `zero` | Numeric value in buckets where no alert carries the field: `zero` or `ffill` |
| `count_transform` | `none` | Transform for count columns: `none` or `log1p` |
| `alert_filter` | `null` | Optional OpenSearch query fragment to filter alerts on ingestion. Set from a scenario's `training:` section or `features.alert_filter` in a `--config` file; ignored in debug mode |
| `max_numeric_fields` | `[]` | Numeric fields for which a per-bucket `<field>__max` column is also computed. Set from a scenario's `training:` section or `features.max_numeric_fields` in a `--config` file |

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

### Timestamp parsing
We accept ISO 8601 formats including `Z` (UTC) and fractional seconds. Malformed timestamps are skipped and logged; check logs for warnings about skipped alerts.

### Sliding window / training errors
If training fails with `MVAD cannot train on N time buckets`, the error states how many buckets your settings need. Lengthen the training window, set `extra_params.interval: 1`, or reduce `sliding_window`; see [Training data size](../docs/manual/sonar_docs/scenario-guide.md#training-data-size).

### Model file not found
```bash
sonar train --config config.yaml
```
Ensure model is trained before running detection, with the same model name, `models_dir` and `SONAR_HOME`. An old `.pkl` model is refused: retrain it. See the [model guide](../docs/manual/sonar_docs/model-naming-guide.md#troubleshooting).

### GPU support
Set `device: "cuda"` in `MVADConfig` if you have a compatible GPU. Ensure `torch` with CUDA support is installed.

## Architecture differences from legacy MTAD-GAT implementation

| Aspect | v1 (ADBox) | v2 (SONAR) |
|--------|---------------|----------|
| Algorithm | Research-oriented implementation of slightly modified MTAD-GAT | Pluggable backends: `mvad` (Microsoft MVAD, in the line of MTAD-GAT; default), `pca` (linear multivariate) and `ewma` (per-feature baseline) |
| GPU Required | Yes | Optional (works on CPU) |
| Dependencies | PyTorch, TensorBoard | Microsoft MVAD library (on PyTorch); the `pca` and `ewma` backends need neither |
| Production Readiness | Research | TRL 6 |

## Contributing

To extend SONAR:

1. **Add new features**: Add a derived feature (a predicate on one alert) to `DERIVED_FEATURES` in `sonar/features.py`, and the alert fields it reads to `DERIVED_FEATURE_FIELDS`; fields not listed there are not fetched, so the predicate sees them as missing
2. **Custom post-processing**: Subclass or extend `MVADPostProcessor`
3. **Model configuration**: Add parameters to `MVADConfig.extra_params`
4. **New detector**: Implement `DetectorBackend` in `sonar/backends/` and register it in `sonar/backends/__init__.py`

## References

- [Microsoft Anomaly Detector](https://pypi.org/project/time-series-anomaly-detector/)
- [IDPS-ESCAPE README](../README.md)
