# SONAR setup and usage guide

Complete guide for installing, configuring, and using SONAR (SIEM-Oriented Neural Anomaly Recognition).

## Quick start

```bash
# 1. Install dependencies
cd /home/alab/soar
poetry install --with sonar

# 2. Try SONAR on the bundled test data (no Wazuh needed)
poetry run sonar scenario --use-case sonar/scenarios/linux_resource_monitoring.yaml --debug

# 3. Verify the connection to the Wazuh Indexer
poetry run sonar check

# 4. Run a scenario against Wazuh
poetry run sonar scenario --use-case sonar/scenarios/brute_force_detection.yaml
```

SONAR does not depend on the directory you run it from: paths inside configuration and scenario files are relative to those files, and models go to `sonar/models/` in a source checkout. See [Where SONAR keeps its files](./model-naming-guide.md#where-sonar-keeps-its-files).

## Installation

### Prerequisites

- Python 3.10.12 (exact version required)
- Poetry for dependency management
- Wazuh/OpenSearch instance (for production) or debug mode (for development)

### Setup steps

```bash
# SONAR and its tests
poetry install --with sonar,test

# SONAR only
poetry install --with sonar

# Exactly what SONAR needs, without the root project's other groups (as the Docker image does)
poetry install --only main,sonar
```

The `sonar` dependency group declares everything SONAR imports: `time-series-anomaly-detector` (Microsoft MVAD), `torch`, `numpy`, `pandas`, `opensearch-py`, `pyyaml` and `requests`. It needs no ADBox dependency.

`python -m sonar` works like the `sonar` command.

### Installing the wheel

`poetry build -f wheel` builds the project wheel (`idps_escape-<version>-py3-none-any.whl`). Besides the code, its `sonar` package contains the example scenarios, the debug datasets they use (`test_data/synthetic_alerts`, `test_data/resource_monitoring`, `test_data/radar_resource_utilization`), `default_config.yaml` and `sonar/wazuh/` (rules, `<localfile>` block, compose overlay). It leaves out secrets, `sonar/models/`, payloads, the test data generators and the other datasets.

Install it with its `sonar` extra, which pulls in SONAR's dependencies (the same pins as the `sonar` dependency group; the project requires Python 3.10.12):

```bash
pip install "idps_escape-<version>-py3-none-any.whl[sonar]"

cd /tmp && sonar scenario --use-case linux_resource_monitoring --debug
```

An installed SONAR keeps its models and other files in `~/.sonar` unless `SONAR_HOME` is set, and `--use-case` / `--scenario` accept the name of a packaged example. The wheel also contains ADBox, which makes it large.

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
  password: "SecretPassword"
  verify_ssl: false  # or true, or a CA bundle path; see TLS certificate verification below
  alerts_index_pattern: "wazuh-alerts-*"
  anomalies_index: "wazuh-anomalies-mvad"
  timeout_seconds: 30  # per request to the indexer
  max_alerts: 2000000  # most alerts one search fetches; beyond it the most recent are kept
  exclude_rule_groups: ["sonar"]  # never read SONAR's own alerts ([] to disable)

# MVAD model settings
mvad:
  sliding_window: 200
  device: "cpu"
  extra_params:
    interval: 1           # train on every window position
  min_gradient_steps: 500

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
  data_dir: "test_data/synthetic_alerts"  # relative to this file (the packaged debug data)
  training_data_file: "normal_baseline.json"
  detection_data_file: "with_anomalies.json"

# Where anomalies go (see the anomaly output guide)
output:
  sinks: [wazuh]
  fallback: none
  debug_sinks: [stdout]
  wazuh:
    transport: file
    file_path: /var/log/sonar/anomalies.json
    api_url: https://localhost:55000
    api_username: sonar
    api_password: ""        # empty: read SONAR_WAZUH_API_PASSWORD
    verify_ssl: false
    severity_medium: 0.5
    severity_high: 0.8

# Models: <models_dir>/<model_name>/
# models_dir: /var/lib/sonar/models   # default: models/ in the SONAR home
model_name: sonar          # scenarios use their model_name, or their name
backend: mvad              # detector trained by `sonar train`: mvad, pca or ewma (baseline)
pca:                       # settings of the pca backend
  window: 3
  variance: 0.95
  z_threshold: 4.0
ewma:                      # settings of the ewma backend
  alpha: 0.5
  z_threshold: 4.0
```

A `--config` file replaces this file rather than adding to it: settings it leaves out take the built-in defaults, which are not all the values above. Without an `mvad.extra_params` section, MVAD trains with the library's `interval` of 10 unless the scenario's `training.extra_params` sets it and needs at least 1725 buckets instead of 1010 (see [Training data size](./scenario-guide.md#training-data-size)), so copy `extra_params: {interval: 1}` into your file; the built-in `wazuh.password` is `admin`. A relative path in it (`models_dir`, `debug.data_dir`, `output.state_dir`, `output.jsonl_path`, `output.wazuh.file_path`) is relative to that file, so a copy of `default_config.yaml` placed elsewhere needs its `debug.data_dir` line removed (to use the packaged test data) or adjusted. The old `model_path` key is still read, with a deprecation warning; see [Model names](./model-naming-guide.md#model-names).

The `output:` section is described in the [anomaly output guide](./data-shipping-guide.md#choosing-the-sinks). With the defaults, detection sends anomalies to the Wazuh manager through the file `/var/log/sonar/anomalies.json`; set up the manager side as described in [Wazuh integration](#wazuh-integration).

### TLS certificate verification

`wazuh.verify_ssl` controls how SONAR checks the indexer's certificate. The same setting applies to alert search and to the `index` and `datastream` sinks: all three use one OpenSearch client built from the `wazuh:` section. The Wazuh server API used by the `wazuh` sink's `api` transport has its own setting, `output.wazuh.verify_ssl`.

| `verify_ssl` | Behaviour |
|---|---|
| `false` (default) | No certificate check. Suitable for a lab indexer with a self-signed certificate |
| `true` | Checks the certificate against the system trust store |
| A file path | Checks the certificate against that CA bundle |

A Wazuh indexer's certificate is normally issued by the Wazuh root CA, which is not in the system trust store. To verify it, copy the root CA certificate, `root-ca.pem`, from your Wazuh deployment (it sits with the indexer's certificates) to the machine that runs SONAR and point `verify_ssl` at it:

```yaml
wazuh:
  base_url: "https://wazuh.indexer:9200"
  verify_ssl: /path/to/root-ca.pem
```

Whenever certificates are verified, the host name is verified too: the host in `base_url` must match a name in the indexer's certificate. Wazuh's default indexer certificate is issued for the indexer node's name, so connecting by IP address with verification on may fail; use the name the certificate was issued for (adding it to `/etc/hosts` if DNS does not resolve it). See [SSL verification failed](./troubleshooting.md#error-ssl-verification-failed).

### Environment-specific configurations

Create custom configs for different environments. `--config` is the base configuration; a scenario (`--use-case` or `--scenario`) is merged over it:

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
# Train on the last 7 days
poetry run sonar train --lookback-hours 168

# With custom config
poetry run sonar train --lookback-hours 168 --config prod.yaml

# With custom model name (sonar/models/baseline_v2/)
poetry run sonar train --model-name "baseline_v2" --lookback-hours 168

# Also prepare the anomaly data stream (index templates and ISM policy; the stream appears on first write)
poetry run sonar train --lookback-hours 168 --ship

# Debug mode (the packaged local test data)
poetry run sonar train --debug
```

Model location: `train` saves to `<models_dir>/<model_name>/`, which is where `detect` with the same configuration or scenario loads from. With the default config that is `sonar/models/sonar/`; a scenario uses its `model_name`, else its `name`; `--model-name NAME` saves to `sonar/models/NAME/`. See the [model guide](./model-naming-guide.md). `train` trains the MVAD backend unless the scenario's `training.backend` or the configuration's `backend` says `pca` or `ewma` (see [backend](./scenario-guide.md#backend)).

Training needs enough time buckets for the MVAD library to perform training updates: with the default config (`sliding_window: 200`, `interval: 1`) at least 1010 5-minute buckets from the first alert in the window (buckets without alerts count), about 3.5 days. With fewer, `train` refuses, saves nothing and exits with status 1; the error states the bucket count needed. See [Training data size](./scenario-guide.md#training-data-size).

**All train options:**

| Option | Description | Default |
|--------|-------------|------|
| `--config PATH` | Path to config YAML | `default_config.yaml` |
| `--scenario PATH` | Path to scenario YAML, merged over `--config` (the config is the base) | - |
| `--model-name NAME` | Save to `<models_dir>/NAME/` | The scenario's or config's model name |
| `--agent NAME` | Train on this `agent.name` only, as the model `<model name>-NAME` (see [One model per host](./radar-comparison-guide.md#one-model-per-host)) | All agents |
| `--lookback-hours N` | Hours of historical data for training | Scenario's `lookback_hours`, else 168 |
| `--print-payloads` | No effect on training | False |
| `--dry-run` | No effect on training | False |
| `--payload-dir DIR` | No effect on training | – |
| `--debug` | Use local test data instead of Wazuh | False |
| `--ship` | Install the data stream's index templates and ISM policy after training (also done when `output.sinks` lists `datastream`) | False |

With `--scenario`, the scenario's `lookback_hours` applies unless `--lookback-hours` is given. All scenario feature keys (`derived_features`, `alert_filter`, `max_numeric_fields`, `sliding_window`, ...) and the scenario's `wazuh:` section are applied, exactly as `sonar scenario` does: `sonar train`, `sonar train --scenario` and `sonar scenario` share one training path.

`train` exits with status 0 when the model was trained and saved, and 1 on any failure, including too little data.

### Run detection

Detect anomalies in recent data:

```bash
# Score the last 60 minutes (12 complete five-minute buckets)
poetry run sonar detect --lookback-minutes 60

# Also write the anomalies to the scenario's data stream
poetry run sonar detect --lookback-minutes 60 --ship

# Debug mode (the packaged local test data; ignores the time range)
poetry run sonar detect --debug
```

`--lookback-minutes` is the window to score: the complete buckets of the last N minutes, ending at the start of the current (still filling) bucket, or one bucket earlier while the last bucket ended less than [`ingest_delay_seconds`](./scenario-guide.md#ingest_delay_seconds) (default 60) ago. SONAR also fetches the buckets of context the model's backend needs before the window (for `mvad`, `input_size + threshold_window − 1`: 199 for the default `sliding_window: 200`; for `pca`, `window − 1`; for `ewma`, a short warm-up), so any lookback of at least one bucket works, including the default 10 minutes. Only buckets inside the window are reported. With `--scenario`, the scenario's `lookback_minutes` is used unless you pass `--lookback-minutes`. `--debug` ignores the time range and scores every bucket of the local file after those context buckets.

Anomalies go to the sinks in `output.sinks` (by default `wazuh`, the Wazuh manager); see the [anomaly output guide](./data-shipping-guide.md).

`detect` exits with status 0 when the window was scored and its anomalies delivered to at least one sink, 2 when there was too little data to score anything (no alerts, or fewer buckets than the model needs), and 1 on an error (unknown sink name, model missing or incompatible, connection failure, prediction error, or every sink failed to take the anomalies and no fallback stored them).

Each anomalous bucket is delivered once to each sink: a watermark per scenario and sink records the last bucket the sink accepted, so running `detect` again over the same window delivers nothing new, and a sink that failed catches up on the next run. See [Delivery and the watermark](./scenario-guide.md#delivery-and-the-watermark).

**Note:** A bucket is reported only when the backend (MVAD by default) flags it (`is_anomaly`), its severity (0–1) is at least the scenario's `threshold` when one is set, and it is part of a run of at least `min_consecutive` such buckets (default 1). The default `threshold` is `null` (the backend's decision alone); plain `sonar detect` without `--scenario` applies no threshold and writes `threshold: null`.

**All detect options:**

| Option | Description | Default |
|--------|-------------|------|
| `--config PATH` | Path to config YAML | `default_config.yaml` |
| `--scenario PATH` | Path to scenario YAML, merged over `--config` (the config is the base) | - |
| `--lookback-minutes N` | Minutes of complete buckets to score (context is fetched automatically) | Scenario's `lookback_minutes`, else 10 |
| `--agent NAME` | Score this `agent.name` with its own model `<model name>-NAME` | All agents |
| `--print-payloads` | Also print the SONAR events on standard output (adds the `stdout` sink) | False |
| `--dry-run` | Write the SONAR events to `<payload-dir>/anomalies.jsonl` instead of the configured sinks; the watermark is not used | False |
| `--payload-dir DIR` | Directory of the dry-run file (relative to the current directory) | The scenario's `detection.payload_dir`, else `<SONAR home>/payloads` (`sonar/payloads/` in a checkout) |
| `--debug` | Use local test data instead of Wazuh; anomalies go to `output.debug_sinks` (default: stdout) | False |
| `--ship` | Add the `datastream` sink (the scenario's data stream) | False |

### Scenario execution

Execute complete workflows defined in YAML:

```bash
# Run scenario with training and detection
poetry run sonar scenario --use-case sonar/scenarios/brute_force_detection.yaml

# Debug mode on the scenario's own test data
poetry run sonar scenario --use-case sonar/scenarios/linux_resource_monitoring.yaml --debug

# The same packaged example by name, from any directory
poetry run sonar scenario --use-case linux_resource_monitoring --debug
```

**Notes:**

- Scenario models are saved to `<models_dir>/<model_name>/` (`sonar/models/<model_name>/` in a checkout); without `model_name`, the name is the scenario's `name` in lower case (`brute_force_detection`), the same on every run.
- Training runs whenever the YAML has a `training:` section, and detection whenever it has a `detection:` section. For a training-only or detection-only run, write a scenario with just that section (a detection-only scenario must set `model_name` to an existing model).
- A scenario's `wazuh:` section is applied over the `--config` (or default) connection settings.
- `--agent NAME` restricts both phases to one `agent.name`, with the model `<model name>-NAME` and the scenario ID `<scenario ID>-NAME`; run one process per host. `train`, `detect`, `evaluate` and `export` take the same option.
- `sonar scenario` returns the exit status of its last phase: training as `sonar train`, detection in `historical` or `batch` mode as `sonar detect` (0 scored and delivered, 2 too little data, 1 error or no sink accepted the anomalies). In `realtime` mode it keeps polling when there is too little data, retries a failed poll with a growing delay, and exits with status 1 after `max_consecutive_failures` failed polls in a row (see [Realtime mode](./scenario-guide.md#realtime-mode)).

### Evaluate and export

`sonar evaluate` measures a scenario's detection quality on labelled alert files and calibrates its decision rule; it also scores another detector's exported results the same way. `sonar export` writes a live window from the indexer as the files `sonar evaluate` reads: the scenario's alerts (with the context its backend needs before the window), a label file built from `--event TYPE,START,END`, and, with `--radar-results`, the results of a RADAR detector.

```bash
poetry run sonar export --scenario radar_linux_resource_utilization --config sonar.yaml --agent web-01 \
  --start 2026-11-19T00:00:00Z --end 2026-11-20T00:00:00Z --output-dir cmp/test \
  --radar-results 'opensearch-ad-plugin-result-linux-resource-utilization*' \
  --event cpu_load,2026-11-19T09:00:00Z,2026-11-19T09:05:00Z
```

`export` exits with 0 when it wrote the files, 2 when the window holds no alerts, and 1 on an error (including a malformed `--event`). See the [evaluation guide](./evaluation-guide.md) and the [RADAR comparison guide](./radar-comparison-guide.md).

## Debug mode

Run SONAR without Wazuh infrastructure using local JSON test data.

### Enable debug mode

Only the `--debug` command-line flag switches the data source to local files:

```bash
# Default configuration: the packaged test_data/synthetic_alerts
poetry run sonar train --debug
poetry run sonar detect --debug

# A scenario with its own debug data
poetry run sonar scenario --use-case sonar/scenarios/linux_resource_monitoring.yaml --debug
```

Setting `debug.enabled: true` in YAML does **not** switch to local data: SONAR still reads alerts from the Wazuh Indexer. It sends the anomalies to the debug sinks instead of the configured ones, like `--debug`.

The `debug:` section selects which files `--debug` reads. A relative `data_dir` is relative to the scenario or configuration file that sets it; unset, it is the packaged `sonar/test_data/synthetic_alerts`. For a scenario in `sonar/scenarios/`:

```yaml
debug:
  data_dir: "../test_data/synthetic_alerts"   # sonar/test_data/synthetic_alerts
  training_data_file: "normal_baseline.json"
  detection_data_file: "with_anomalies.json"
```

Debug mode ignores the query time range and any `alert_filter`, except the agent given with `--agent`, which it applies to the local data. It sends the anomalies to `output.debug_sinks` instead of the configured sinks: by default `stdout`, which prints one SONAR event (the line the `wazuh` sink would send) per line on standard output, while the logs go to standard error. It neither reads nor moves the delivery watermark, and by default writes nothing to Wazuh.

```bash
# Keep only the events
poetry run sonar scenario --use-case sonar/scenarios/linux_resource_monitoring.yaml --debug > events.jsonl
```

Set `output.debug_sinks: [jsonl]` to write the events to `output.jsonl_path` instead. `output.debug_sinks` accepts any sink but `index`: `[wazuh]` sends the anomalies of the local test data to a Wazuh manager, which is how a lab manager can be tested end to end without real alerts. Debug runs use no watermark, so every debug run sends all its anomalies again; use this only with a lab manager.

Debug training (`train --debug`) never installs the data stream templates, even with `--ship`.

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

Locations are relative to `sonar/`. The datasets marked as packaged are also installed with the wheel.

| Dataset | Location | Description | Packaged |
|---------|----------|-------------|----------|
| Normal baseline | `test_data/synthetic_alerts/normal_baseline.json` | 12,000 normal alerts | Yes |
| With anomalies | `test_data/synthetic_alerts/with_anomalies.json` | 6,000 alerts with anomalies | Yes |
| Normal training | `test_data/generated_scenarios/normal_training.json` | 12,000 alerts with realistic patterns | No |
| Attack scenarios | `test_data/generated_scenarios/attack_scenarios.json` | 2,000 alerts with known attacks | No |
| Resource monitoring (train) | `test_data/resource_monitoring/resource_monitoring_training.json` | 24h normal system activity | Yes |
| Resource monitoring (detect) | `test_data/resource_monitoring/resource_monitoring_detection.json` | 2h normal context, then 6h with CPU/memory attacks | Yes |
| RADAR resource utilization (train) | `test_data/radar_resource_utilization/training.json` | The resource monitoring training data as RADAR collector events | Yes |
| RADAR resource utilization (detect) | `test_data/radar_resource_utilization/detection.json` | The resource monitoring detection data as RADAR collector events | Yes |

### Generate custom test data

Use the provided generators:

```bash
# Resource monitoring data
poetry run python sonar/test_data/generate_resource_data.py

# Attack scenarios
poetry run python sonar/test_data/generate_attack_data.py

# Resource alerts rewritten as RADAR's linux_resource_utilization events (same timestamps and hosts)
poetry run python sonar/test_data/radar_format.py sonar/test_data/resource_monitoring/resource_monitoring_detection.json detection.json
```

## Wazuh integration

SONAR reads alerts from the Wazuh Indexer and reports the anomalies it finds to the Wazuh manager, which turns them into ordinary Wazuh alerts.

SONAR runs on the Wazuh manager host or on a dedicated machine, never on the monitored endpoints, whose resources may be limited. No Wazuh agent is needed on the SONAR host. Choose one topology:

| Topology | `output.wazuh.transport` | Section |
|----------|--------------------------|---------|
| SONAR on the manager host | `file` | [SONAR on the manager host](#sonar-on-the-manager-host) |
| SONAR in a container next to the manager container | `file` | [SONAR in Docker next to the manager](#sonar-in-docker-next-to-the-manager) |
| SONAR on a dedicated host | `api` | [SONAR on a dedicated host](#sonar-on-a-dedicated-host) |

In every topology SONAR also needs the Wazuh Indexer (port 9200) to read alerts, configured in the `wazuh:` section.

### Alert ingestion

SONAR reads from Wazuh alert indices:
- Pattern: `wazuh-alerts-*` (`wazuh.alerts_index_pattern`, also settable in a scenario's `wazuh:` section; `radar_linux_resource_utilization` reads `wazuh-archives-*`)
- Time-based queries using `timestamp` field
- Supports OpenSearch query DSL for filtering
- Every alert in the window is read: SONAR pages through the matches with a point-in-time and `search_after`, fetching only the fields the features use, and logs `Fetched N of M matching alerts.`
- A search stops at `wazuh.max_alerts` (default 2,000,000) and keeps the most recent alerts, with a warning
- Alerts whose rule groups include one of `wazuh.exclude_rule_groups` (default `["sonar"]`) are never read, so SONAR does not learn from its own alerts. `[]` disables this
- The indexer user needs permission to create and delete a point-in-time (`indices:data/read/point_in_time/create` and `indices:data/read/point_in_time/delete`). Wazuh's `admin` user has it; add it to a restricted read-only role
- `sonar export --radar-results` reads RADAR's result index through a scroll, so that user also needs read access to `opensearch-ad-plugin-result-*`

See [Alert retrieval](./architecture.md#alert-retrieval) for details.

### Install the rules

The manager raises alerts for SONAR events only with SONAR's rules, [`sonar/wazuh/rules/sonar_rules.xml`](../../../sonar/wazuh/rules/sonar_rules.xml) (IDs 100500–100519, rule group `sonar`; see [Rules](./data-shipping-guide.md#rules)). Install them through the Wazuh server API with an administrator account:

```bash
# Prompts for the password unless SONAR_WAZUH_ADMIN_PASSWORD is set
poetry run sonar wazuh install-rules --config my_config.yaml --user wazuh-wui --restart
```

| Option | Description |
|--------|-------------|
| `--config PATH` | Config whose `output.wazuh` section gives `api_url`, `verify_ssl` and `timeout_seconds` (default: `sonar/default_config.yaml`) |
| `--api-url URL` | Wazuh server API URL (default: `output.wazuh.api_url`) |
| `--user USER` | API user allowed to update rules (default: `output.wazuh.api_username`). With `--user`, the configured `api_password` is not used |
| `--restart` | Restart the manager afterwards (`PUT /manager/restart`) so the rules take effect |

The command uploads the file with `PUT /rules/files/sonar_rules.xml?overwrite=true`, which needs a user allowed `rules:update` (and `manager:restart` for `--restart`), such as Wazuh's `wazuh-wui` or `wazuh` administrator. The `event:ingest` user of the `api` transport is not allowed to. With `--user`, the password comes from `SONAR_WAZUH_ADMIN_PASSWORD` or a prompt; `SONAR_WAZUH_API_PASSWORD` and `output.wazuh.api_password`, which belong to the `event:ingest` user, are not used. Without `--user`, the command logs in as `output.wazuh.api_username` with that user's password. The command exits with status 0 on success and 1 on failure. Without `--restart`, restart the manager yourself.

Alternatively, copy the file on the manager host and restart the manager:

```bash
sudo cp sonar/wazuh/rules/sonar_rules.xml /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/rules/sonar_rules.xml
sudo chmod 660 /var/ossec/etc/rules/sonar_rules.xml
sudo systemctl restart wazuh-manager
```

Re-installing overwrites `sonar_rules.xml`; keep your own per-scenario rules (IDs 100510–100519) in a separate file.

### SONAR on the manager host

SONAR appends its events to a file that the manager reads like any other JSON log.

1. **Install the rules** as described in [Install the rules](#install-the-rules).

2. **Create the output directory**, writable by the user that runs SONAR (here `sonar`):

   ```bash
   sudo install -d -o sonar -g sonar -m 0755 /var/log/sonar
   ```

3. **Add the `<localfile>` block** of [`sonar/wazuh/ossec-localfile.xml`](../../../sonar/wazuh/ossec-localfile.xml) inside `<ossec_config>` in `/var/ossec/etc/ossec.conf`, then restart the manager (`sudo systemctl restart wazuh-manager`):

   ```xml
   <localfile>
     <log_format>json</log_format>
     <location>/var/log/sonar/anomalies.json</location>
   </localfile>
   ```

4. **Configure SONAR** (these are the defaults):

   ```yaml
   output:
     sinks: [wazuh]
     wazuh:
       transport: file
       file_path: /var/log/sonar/anomalies.json
   ```

5. **Verify** as described in [Verify the integration](#verify-the-integration).

The file is rotated at 10 MiB, keeping five old copies (`output.wazuh.max_file_bytes`, `backup_count`).

### SONAR in Docker next to the manager

When both run in containers, they share the anomaly directory through a host directory: SONAR writes `anomalies.json` into it, and the manager container mounts it read-only at `/var/log/sonar`. The SONAR image runs as uid 1000, so create the directory with that owner:

```bash
sudo install -d -o 1000 -g 1000 /srv/sonar/anomalies
```

For a compose project that defines the `wazuh.manager` service (Wazuh's single-node Docker deployment, or RADAR's `radar/docker-compose.core.yml`), the overlay [`sonar/wazuh/docker-compose.sonar.yml`](../../../sonar/wazuh/docker-compose.sonar.yml) adds both mounts and a `sonar` service running a realtime scenario:

```bash
docker compose -f docker-compose.yml -f sonar/wazuh/docker-compose.sonar.yml up -d
```

Edit the overlay's `command` to name your scenario, and mount a config whose `wazuh.base_url` reaches the indexer from the SONAR container (for example `https://wazuh.indexer:9200` on the compose network).

`sonar/sonar.sh` mounts the same directory: `$SONAR_ANOMALIES_DIR` (default `/srv/sonar/anomalies`) at `/var/log/sonar` in the SONAR container.

Then, as on a manager host: install the rules (the API on port 55000, or `docker cp` the file into `/var/ossec/etc/rules/` in the manager container), and add the `<localfile>` block with location `/var/log/sonar/anomalies.json` to the manager's `ossec.conf` (in Wazuh's single-node Docker deployment, `config/wazuh_cluster/wazuh_manager.conf` on the host; in a container without a mounted configuration, `/var/ossec/etc/ossec.conf` inside it, which is lost when the container is recreated). Restart the manager container afterwards.

The `<localfile>` location is the path the manager sees. If SONAR runs in a container but the manager runs directly on the host, the manager reads `/srv/sonar/anomalies/anomalies.json`, so use that as `location`.

### SONAR on a dedicated host

SONAR posts its events to the Wazuh server API (`POST /events`, Wazuh 4.6 and later) on port 55000. The SONAR host needs to reach the manager on that port and the indexer on port 9200.

1. **Install the rules** with an administrator account, as described in [Install the rules](#install-the-rules), pointing `--api-url` at the manager.

2. **Create the `event:ingest` API user** as described below.

3. **Configure SONAR:**

   ```yaml
   output:
     sinks: [wazuh]
     wazuh:
       transport: api
       api_url: https://wazuh-manager.example.org:55000
       api_username: sonar
       verify_ssl: /etc/sonar/wazuh-api-ca.pem   # CA of the API certificate; false skips the check
   ```

   and give SONAR the password through the environment, for example in the systemd unit (`Environment=SONAR_WAZUH_API_PASSWORD=...`, or an `EnvironmentFile=` readable only by root):

   ```bash
   export SONAR_WAZUH_API_PASSWORD='<sonar API password>'
   ```

4. **Verify** as described in [Verify the integration](#verify-the-integration).

How the manager decodes events received through the API (their location, and whether the JSON decoder applies exactly as for the file transport) is verified on Wazuh 4.14.1 in lab test [TST-068](../../specs/tst/TST-068.md).

#### Create the event:ingest API user

Give SONAR an API user whose role allows only `event:ingest`, so a leaked password lets an attacker inject events but not read or change the manager's configuration. Create it as an administrator through the Wazuh server API:

```bash
API=https://wazuh-manager.example.org:55000
TOKEN=$(curl -sk -u wazuh-wui:'<admin password>' -X POST "$API/security/user/authenticate?raw=true")

# 1. A policy that allows event:ingest only (note data.affected_items[0].id: POLICY_ID)
curl -sk -X POST "$API/security/policies" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "sonar_event_ingest", "policy": {"actions": ["event:ingest"], "resources": ["*:*:*"], "effect": "allow"}}'

# 2. A role (note its id: ROLE_ID)
curl -sk -X POST "$API/security/roles" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "sonar_event_ingest"}'

# 3. Attach the policy to the role
curl -sk -X POST "$API/security/roles/ROLE_ID/policies?policy_ids=POLICY_ID" -H "Authorization: Bearer $TOKEN"

# 4. The user (note its id: USER_ID)
curl -sk -X POST "$API/security/users" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"username": "sonar", "password": "<sonar API password>"}'

# 5. Give the user the role
curl -sk -X POST "$API/security/users/USER_ID/roles?role_ids=ROLE_ID" -H "Authorization: Bearer $TOKEN"
```

Replace `ROLE_ID`, `POLICY_ID` and `USER_ID` with the ids returned by the earlier calls, and use `-k` only in a lab (or replace it with `--cacert`). Wazuh requires API passwords of 8 to 64 characters with at least one uppercase letter, one lowercase letter, one number and one symbol.

To check the user, authenticate as `sonar` and send one test event:

```bash
SONAR_TOKEN=$(curl -sk -u sonar:'<sonar API password>' -X POST "$API/security/user/authenticate?raw=true")
curl -sk -X POST "$API/events" -H "Authorization: Bearer $SONAR_TOKEN" -H "Content-Type: application/json" \
  -d '{"events": ["{\"integration\":\"sonar\",\"anomaly_grade\":0.9,\"anomaly_confidence\":0.5,\"sonar\":{\"scenario\":\"test\",\"severity\":0.9,\"severity_band\":\"high\"}}"]}'
```

The response should report `total_affected_items: 1`. With the rules installed, the event raises rule 100503.

### Verify the integration

1. **Test the decoding and rules on the manager.** Run `/var/ossec/bin/wazuh-logtest` and paste an event line:

   ```json
   {"integration":"sonar","anomaly_grade":0.9,"anomaly_confidence":0.5,"sonar":{"scenario":"test","severity":0.9,"severity_band":"high"}}
   ```

   Phase 2 should show the `json` decoder, phase 3 rule 100503 (level 10).

2. **Send a test event end to end.** With the file transport, append the same line to the file the manager reads (`echo '<line>' | sudo tee -a /var/log/sonar/anomalies.json`, or the host directory in Docker); with the API transport, use the `POST /events` call above.

3. **Run SONAR.** A detection run logs `Anomaly sinks: wazuh` at start-up and `wazuh: delivered N anomalies; watermark ...` when it found anomalies. The default bands put anomalies below a severity of 0.5 into `low` (rule 100501); the bundled resource-monitoring scenario reaches about 0.45, so its anomalies arrive as rule 100501 until the bands are tuned (see [Severity bands](./data-shipping-guide.md#severity-bands)).

4. **Find the alerts.** On the manager:

   ```bash
   sudo grep '"integration":"sonar"' /var/ossec/logs/alerts/alerts.json | tail -n 1
   ```

   In the dashboard or the indexer, search `wazuh-alerts-*` for `rule.groups: sonar` or `data.integration: sonar`:

   ```bash
   curl -sk -u admin:'<indexer password>' "https://localhost:9200/wazuh-alerts-*/_search?q=rule.groups:sonar&size=1&sort=timestamp:desc"
   ```

If nothing arrives, see [No SONAR alerts in Wazuh](./data-shipping-guide.md#no-sonar-alerts-in-wazuh).

### Anomaly output

Besides the `wazuh` sink, anomalies can go to a data stream in the indexer (`datastream`, for dashboards and history, also enabled by `--ship` or `shipping.enabled`), the legacy plain index (`index`), a local JSON-lines file (`jsonl`) or standard output (`stdout`). See the [anomaly output guide](./data-shipping-guide.md).

### RADAR integration

SONAR alerts carry `data.anomaly_grade` and `data.anomaly_confidence`, the fields RADAR's active response reads for anomaly-detection scenarios, so RADAR can act on SONAR alerts through its `ar.yaml` without code changes. SONAR's own configuration does not set this up. See [SWD-037](../../specs/swd/SWD-037.md).

## Production deployment

### Recommended workflow

```bash
# 1. Initial baseline (weekly)
poetry run sonar scenario --use-case sonar/scenarios/brute_force_detection.yaml

# 2. Continuous monitoring (cron/systemd): score the last 10 minutes with the same model;
#    the context the model needs before them is fetched automatically.
*/10 * * * * poetry run sonar detect --scenario sonar/scenarios/brute_force_detection.yaml --lookback-minutes 10

# 3. Weekly retraining (cron), under the same model name
0 2 * * 0 poetry run sonar train --scenario sonar/scenarios/brute_force_detection.yaml
```

Every step names the scenario, so all three use the model `brute_force_detection`; a plain `sonar detect` or `sonar train` would use the default configuration's model `sonar` instead. Alternatively, run the scenario with `detection.mode: realtime` (or `--mode realtime`) as a service, which polls once per bucket.

### Docker deployment

Build the SONAR image from the project root:

```bash
docker build -f sonar/Dockerfile.sonar -t sonar:v0.8 .
```

`build.sh sonar` runs the same command. The image installs only the `main` and `sonar` dependency groups (no ADBox dependency, no git) and contains only SONAR (`sonar/`, its scenarios and debug data), never ADBox assets, secrets or `.env` files. Its entry point is the `sonar` command, started in `/home/alab/soar`, so `sonar/sonar.sh scenario --use-case sonar/scenarios/linux_resource_monitoring.yaml --debug` works as in a source checkout. The image is a source checkout, so its SONAR home is `/home/alab/soar/sonar` and its models are in `sonar/models/` unless `SONAR_HOME` is set. `sonar/sonar.sh` mounts `sonar/models`, `sonar/test_data`, `sonar/scenarios` and `sonar/default_config.yaml` from the host, and `$SONAR_ANOMALIES_DIR` (default `/srv/sonar/anomalies`) at `/var/log/sonar`, where the `wazuh` sink's file transport writes by default.

The build uses `sonar/Dockerfile.sonar.dockerignore`, which BuildKit (the default builder since Docker 23) reads instead of the root `.dockerignore`. With the legacy builder the whole repository is sent as build context, but the image still contains only the copied paths.

[`sonar/wazuh/docker-compose.sonar.yml`](../../../sonar/wazuh/docker-compose.sonar.yml) is a compose overlay that runs SONAR next to a Wazuh manager container; see [SONAR in Docker next to the manager](#sonar-in-docker-next-to-the-manager).

### Monitoring and logging

SONAR logs to stderr through Python logging at a fixed `INFO` level; there is no option or environment variable to change it.

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
2. **Sliding window**: Keep 100-300 for most use cases; training needs many more buckets than `sliding_window` (see [Training data size](./scenario-guide.md#training-data-size))
3. **Categorical encoding**: Limit with `categorical_top_k` parameter
4. **Historical lookback**: Balance between baseline quality and performance

## Common use cases

These are shortened versions of the bundled scenarios. Their `threshold` and `min_consecutive` are the values calibrated on the labelled synthetic data and shipped in `sonar/scenarios/`; recalibrate them on labelled data from your own environment (see [Calibration](./evaluation-guide.md#calibration)).

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
  lookback_minutes: 1440  # window to score; context is fetched automatically
  threshold: 0.2  # report only MVAD anomalies with severity >= 0.2
  min_consecutive: 3  # in runs of at least 3 buckets
```

### Resource monitoring

```yaml
name: "Linux Resource Monitoring"
training:
  lookback_hours: 24   # 1440 one-minute buckets
  numeric_fields: ["data.cpu_usage_%", "data.memory_usage_%", "rule.level"]
  categorical_fields: ["agent.name", "rule.groups"]
  bucket_minutes: 1
  sliding_window: 120  # the 10% validation split must exceed sliding_window / 2
  extra_params:
    interval: 1        # train on every window position
detection:
  mode: "historical"  # one run
  lookback_minutes: 360  # window to score; context is fetched automatically
  threshold: 0.05  # minimum MVAD severity (0-1)
  min_consecutive: 4
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
  mode: "realtime"  # polls once per bucket, shortly after it ends (the bundled file: historical)
  lookback_minutes: 60  # window to score; context is fetched automatically
  threshold: 0.2  # minimum MVAD severity (0-1)
  min_consecutive: 5  # ignore runs shorter than 5 anomalous buckets
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
poetry run sonar scenario --use-case sonar/scenarios/linux_resource_monitoring.yaml --debug

# Verify outputs: the model directory sonar/models/linux_resource_monitoring/
ls sonar/models/linux_resource_monitoring/
```

## Troubleshooting

See [troubleshooting.md](./troubleshooting.md) for detailed error diagnosis and solutions.

### Quick fixes

**Connection errors:**
```bash
# Check the indexer is running (-k: no certificate check, as with verify_ssl: false)
curl -k -u admin:'<indexer password>' https://localhost:9200/_cluster/health

# Use debug mode for development
poetry run sonar train --debug
```

**Model built with an older feature schema:**
- Retrain the model; models trained by an older SONAR, including every `.pkl` model, are refused
- Detection always builds the features the model was trained on; check the `Feature matrix:` log line for counts

**Model not found:**
```bash
# Train before detection (default config: sonar/models/sonar/)
poetry run sonar train --lookback-hours 168

# Or point detect at another model: set model_name (and models_dir) in a config file
poetry run sonar detect --config my_config.yaml  # my_config.yaml: model_name: custom_model

# Or use the scenario the model was trained with (loads sonar/models/<model_name>/)
poetry run sonar detect --scenario sonar/scenarios/example_model_naming.yaml
```