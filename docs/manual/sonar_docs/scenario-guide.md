# SONAR scenario guide

Complete guide to scenario-based anomaly detection with SONAR (SIEM-Oriented Neural Anomaly Recognition).

## Overview

SONAR uses **YAML-based scenarios** to define complete anomaly detection workflows. Each scenario specifies what data to analyze, how to train models, and how to detect anomalies.

Run a scenario with `poetry run sonar scenario --use-case sonar/scenarios/<file>.yaml`. The scenario path is relative to your current directory; the paths inside the scenario file are relative to the file itself (see [Where SONAR keeps its files](./model-naming-guide.md#where-sonar-keeps-its-files)). `--use-case` and `--scenario` also accept the name of a packaged example (`--use-case linux_resource_monitoring`) when no file of that name exists, so the examples run from any directory and from an installed SONAR. The packaged examples are `brute_force_detection`, `lateral_movement_detection`, `privilege_escalation_detection`, `linux_resource_monitoring`, `radar_linux_resource_utilization` (RADAR's resource-utilization data, see the [RADAR comparison guide](./radar-comparison-guide.md)), `example_scenario` and `example_model_naming`.

**Which command applies which key.** `sonar scenario --use-case`, `sonar train --scenario` and `sonar detect --scenario` apply the same scenario keys on top of `--config` (or the default config): the `wazuh:`, `debug:`, `shipping:` and `output:` sections, `model_name`, `models_dir`, and every feature, window and backend key under `training:`. `train`/`detect --scenario` take their query window from the scenario's `lookback_hours` / `lookback_minutes` unless you pass `--lookback-hours` / `--lookback-minutes`.

## Scenario structure

### Complete scenario template

```yaml
name: "Scenario Name"
description: "What this scenario detects"
enabled: true

# Optional: the model is <models_dir>/<model_name>/
model_name: "my_scenario_baseline_v1"  # default: the name above, slugged (scenario_name)
models_dir: "../models"                # default: models/ in the SONAR home; relative to this file

# Training phase (optional)
training:
  backend: mvad          # mvad (default), pca or ewma (baseline); see Backend below
  lookback_hours: 168
  numeric_fields:
    - "rule.level"
    - "data.cpu_usage_%"
  categorical_fields:
    - "agent.id"
    - "rule.groups"
  categorical_top_k: 10
  bucket_minutes: 5
  sliding_window: 200
  device: "cpu"
  derived_features: true  # Enable computed security features
  extra_params:           # any MultiADConfig field of the MVAD library
    interval: 1           # train on every window position (library default: every 10th)
  min_gradient_steps: 500 # warn when training would perform fewer optimiser updates
  # Optional: restrict which alerts are fetched from OpenSearch
  alert_filter:
    bool:
      should:
        - match: {"rule.groups": "authentication"}
        - match: {"rule.groups": "sudo"}

# Optional: scenario ID and the anomaly data stream
shipping:
  enabled: false  # true adds the datastream sink (the scenario's data stream)
  install_templates: true  # Install index templates and the ISM policy after training
  scenario_id: "custom_id"  # Optional: custom scenario ID (names the stream and the watermark file)

# Optional: where anomalies go (defaults in sonar/default_config.yaml)
output:
  sinks: [wazuh]        # wazuh, datastream, index, jsonl, stdout
  fallback: none        # none, datastream or index
  wazuh:
    transport: file     # file (SONAR on the manager host) or api (dedicated host)

# Detection phase (optional)
detection:
  mode: "historical"  # or "batch" (same as historical) or "realtime"
  lookback_minutes: 1440  # window to score; earlier context is fetched automatically
  threshold: null       # minimum MVAD severity (0-1) to report; null (default) = MVAD's decision alone
  min_consecutive: 2    # minimum run of consecutive anomalous buckets (default 1)
  anomaly_confidence: null  # trust in this scenario's anomalies (0-1), sent to Wazuh; null sends 0.5
```

### Fields

All top-level fields are optional. A useful scenario has at least a `training` or a `detection` section.

- `name`: Scenario identifier (default: `unnamed_scenario`)
- `description`: What the scenario detects (default: empty)
- `enabled`: Enable/disable scenario (default: true)
- `model_name`: Name of the model directory (default: `name` in lower case, `[a-z0-9_-]` only)
- `models_dir`: Directory of the models, relative to the scenario file (default: `models/` in the SONAR home)
- `training`: Training phase configuration
- `detection`: Detection phase configuration
- `shipping`: Scenario ID and data stream settings
- `output`: Where anomalies go (sinks); see the [anomaly output guide](./data-shipping-guide.md)
- `wazuh`: Indexer settings that override the configuration's `wazuh:` section for this scenario, for example `alerts_index_pattern: "wazuh-archives-*"` (as in `radar_linux_resource_utilization.yaml`)
- `debug`: The local files `--debug` reads (see [Debug mode testing](#debug-mode-testing))

#### model_name

The name of the model the scenario trains and loads, the directory `<models_dir>/<model_name>/`:

```yaml
model_name: "brute_force_v2"
```

- If omitted, the model name is the scenario's `name` in lower case, with every run of characters outside `[a-z0-9_-]` replaced by `_` (`"Brute Force Detection"` → `brute_force_detection`). It is the same on every run, so `sonar train --scenario` and a later `sonar detect --scenario` use the same model.
- Training again under the same name replaces the model. Use a new name (for example `brute_force_v2`) to keep the previous one, and set `shipping.scenario_id` so that the new name does not start new watermarks.
- `sonar train --model-name NAME` overrides it for that training run.

See the [model guide](./model-naming-guide.md) for locations, the model directory's contents and how to protect it.

**Example naming conventions**:
- `{scenario}_{version}`: `brute_force_v2`
- `{scenario}_{environment}`: `auth_anomaly_production`
- `{scenario}_{datasource}`: `lateral_movement_dc1`

#### alert_filter

OpenSearch query DSL placed under the `training:` section to pre-filter alerts before feature extraction. The filter is used for both training and detection queries.

`sonar scenario --use-case`, `sonar train/detect --scenario` and `features.alert_filter` in a `--config` file all apply it. Debug mode (`--debug`) ignores it and uses every alert in the local file. `sonar evaluate` reads local files too, so it ignores it as well; `sonar export` applies it, so an exported file already holds only the matching alerts.

`--agent HOST` adds `{"term": {"agent.name": HOST}}` to the filter (debug mode and `sonar evaluate` apply that term to local files). The model stores the combined filter, and detection with that model uses it.

```yaml
training:
  alert_filter:
    bool:
      must:
        - match: {"rule.groups": "authentication"}
      should:
        - match: {"rule.groups": "sudo"}
        - match: {"rule.groups": "ssh"}
      must_not:
        - match: {"agent.name": "test-agent"}
```

**Use cases**:
- Limit to specific rule groups (authentication, web, network)
- Exclude test/development agents
- Focus on high-severity alerts only: `{"range": {"rule.level": {"gte": 7}}}`
- Filter by attack techniques: `{"match": {"rule.mitre.technique": "T1078"}}`

#### shipping

The scenario ID and the scenario's data stream in the Wazuh Indexer:

```yaml
shipping:
  enabled: true
  install_templates: true
  scenario_id: "auth_monitoring"
  rollover_days: 7
  retention_days: 30
```

**Fields**:
- `enabled`: Add the `datastream` sink, which writes every anomaly to `sonar_anomalies_mvad_<scenario_id>` as well (same as `--ship`, or listing `datastream` in `output.sinks`)
- `install_templates`: After training, install the index templates and the ISM policy (rollover after `rollover_days`, deletion after `retention_days`)
- `scenario_id`: Scenario identifier, used in the stream name, the watermark file, each anomaly's `anomaly_id` and the `sonar.scenario` field of Wazuh events (the model name in lower case if omitted)

The `wazuh` sink, which sends the anomalies to the Wazuh manager, is the default in any case. See the [anomaly output guide](./data-shipping-guide.md) for all sinks.

## Execution modes

The scenario system automatically determines execution based on YAML sections:

| YAML sections | Execution behavior | Use case |
|---------------|-------------------|----------|
| `training` + `detection` | Train, then detect in the configured `mode` | Full workflow with fresh model |
| `training` only | Train (save model) | Establish baseline, no detection |
| `detection` only | Detect (load model) | Ad-hoc investigation with existing model |

Training runs whenever a `training:` section is present, on every invocation. The detection `mode` (YAML, or `--mode` on the CLI) only controls how detection runs; it does not turn training on or off.

## Detection modes

### Historical mode

One-shot detection on recent data:

```yaml
detection:
  mode: "historical"
  lookback_minutes: 1440  # scores the last 288 complete 5-minute buckets
```

- Analyzes last N minutes
- Exits after detection completes (status 0 if the window was scored, 2 if there was too little data, 1 on error)
- Best for: Ad-hoc investigations

### Batch mode

`batch` currently behaves exactly like `historical`: one detection run, then exit.

```yaml
training:
  lookback_hours: 168
detection:
  mode: "batch"
  lookback_minutes: 1440
```

- Whether a model is trained first depends only on the `training:` section, not on the mode
- Kept for compatibility; prefer `historical`

### Realtime mode

Continuous monitoring:

```yaml
detection:
  mode: "realtime"
  lookback_minutes: 60
```

- Polls once per bucket: each poll runs when the next bucket has ended and [`ingest_delay_seconds`](#ingest_delay_seconds) have passed. Set [`polling_interval_seconds`](#polling_interval_seconds) for a fixed interval instead.
- Delivers each anomalous bucket once, although every poll re-scores the whole window (see [Delivery and the watermark](#delivery-and-the-watermark))
- Runs until Ctrl+C. A failed poll (indexer unreachable, or no sink accepted the anomalies) is retried after 10 s, then 20 s, 40 s and so on, at most one bucket apart; after [`max_consecutive_failures`](#max_consecutive_failures) failures in a row, SONAR exits with status 1. A poll with too little data is not a failure.
- Best for: Production monitoring

#### Delivery and the watermark

Every poll scores the whole `lookback_minutes` window, so an anomalous bucket is found again by every poll whose window holds it. SONAR delivers it only once to each [sink](./data-shipping-guide.md#sinks):

- Each sink has a **watermark** per scenario: the last anomalous bucket that sink accepted. A sink receives only the anomalies after its own watermark. A sink reports how many anomalies it accepted from the oldest on, and its watermark advances over exactly those.
- The watermarks of a scenario are stored together in `<state_dir>/<scenario_id>.json`, which survives restarts, so restarting SONAR does not deliver old anomalies again:

  ```json
  {
    "scenario_id": "brute_force",
    "sinks": {
      "datastream": "2026-01-06T15:30:00+00:00",
      "wazuh": "2026-01-06T15:40:00+00:00"
    }
  }
  ```

- Each anomaly has an `anomaly_id` computed from the scenario and the bucket. The `datastream` and `index` sinks store each document under that id and refuse a second copy, which SONAR counts as delivered. The Wazuh manager cannot recognise a duplicate event, so for the `wazuh` sink the watermark is the only protection.

If a sink fails, its watermark stays where it was and the next run (in realtime mode, the next poll) offers it the anomalies it missed, while the sinks that accepted them are not sent them again. A run in which at least one sink accepted the anomalies logs a warning naming the failed sinks and exits with status 0; it exits with status 1 only when every sink that had anomalies failed and no [fallback](./data-shipping-guide.md#fallback) stored them all.

The watermarks apply to every detection run that delivers anomalies, not only to realtime mode. Running `sonar detect` twice over the same hour delivers its anomalies once. To deliver them again, delete the scenario's watermark file, or remove one sink's entry from it to re-deliver to that sink only. A sink added later starts without a watermark and receives every anomaly in the next window. Debug runs (`--debug` or `debug.enabled: true`) and dry runs (`--dry-run`) neither read nor move the watermarks: they deliver everything they find to their local sinks.

Run one SONAR process per scenario: two processes with the same scenario ID and different `state_dir`s would each deliver the same anomalies.

The state directory is `output.state_dir`, by default `<models_dir>/state` (`sonar/models/state/` in a source checkout). A relative `state_dir` is relative to the file that sets it:

```yaml
output:
  state_dir: "/var/lib/sonar/state"
```

`min_consecutive` is evaluated over the whole window. If a run of anomalous buckets is still too short at the end of one poll, its buckets are delivered together by the poll that makes it long enough.

## Training parameters

### backend

The detector the scenario trains:

```yaml
training:
  backend: pca    # mvad (default), pca or ewma
  pca:            # settings of the pca backend (defaults shown)
    window: 3
    variance: 0.95
    z_threshold: 4.0
  ewma:           # settings of the ewma backend (defaults shown)
    alpha: 0.5
    z_threshold: 4.0
```

| Backend | What it does | Use it for |
|---------|--------------|------------|
| `mvad` | Microsoft's multivariate anomaly detector (`time-series-anomaly-detector`), a graph-attention network that models every feature and the correlations between them | Production scenarios |
| `pca` | A probabilistic PCA of short windows of every feature: models the features' levels and the correlations between them, linearly | Machines without torch, fast retraining, and scenarios where it evaluates as well as MVAD (see the [evaluation guide](./evaluation-guide.md)) |
| `ewma` | Smooths each feature with an exponentially weighted moving average and compares it with the training distribution | A fast baseline the other backends have to beat, and tests |

When `backend` is unset, the configuration's top-level `backend` applies (default `mvad`); the configuration's top-level `pca:` and `ewma:` sections hold the backends' default settings. Detection always uses the backend stored in the model, whatever the scenario says now. An unknown backend name is an error when the scenario loads.

**How `ewma` scores a bucket.** For each feature column, the EWMA-smoothed value (`alpha` between 0 and 1; 1 means no smoothing) is turned into a robust z-score: its distance to the training median, divided by the training median absolute deviation scaled to a standard deviation (or by the standard deviation when that is 0, or by 1 for a column that never moved). A bucket is anomalous when its largest z-score reaches `z_threshold`. Its severity is that z-score divided by `2 × z_threshold`, capped at 1, so a bucket exactly at the threshold has severity 0.5; non-anomalous buckets have severity 0. Each feature's contribution is its share of the bucket's summed z-scores. The first `ceil(1 / alpha)` buckets (2 for the default, none for `alpha: 1`) only warm up the average and get no verdict; training needs at least 10 buckets, or `ceil(1 / alpha) + 2` if that is more.

**How `pca` scores a bucket.** Each feature column is standardised with its training median and scaled median absolute deviation (as in `ewma`), and each bucket is scored on the vector of its last `window` buckets of every column. Training fits a probabilistic PCA to the training windows: the principal components that keep `variance` of the training variance, plus noise of equal variance in every other direction. A window's score is its Mahalanobis distance under that model, which grows both for a window far out along a direction normal data varies in (a spike, a level never seen, a slow leak once it leaves the usual range) and for a window that breaks the usual relations between features (one feature moving without its usual partners, a category that never moved). A bucket is anomalous when the robust z-score of its score, against the training windows' scores, reaches `z_threshold`; severity follows the same convention as `ewma` (0.5 at the threshold, 1 from twice the threshold). Each feature's contribution is its share of the squared distance. The first `window - 1` buckets only give context; training needs at least `window + 19` buckets and takes well under a second.

Keep the window short. An anomaly confined to a few features and buckets is diluted in a long window: on the labelled privilege-escalation data, a window of 10 fifteen-minute buckets found none of the attacks that a window of 3 found. An anomalous bucket stays in the window for `window - 1` more buckets, so alarms outlast the anomaly by up to that much.

`ewma` ignores correlations between features, the main strength of MVAD and `pca`. On the bundled resource-monitoring debug data, it trains and detects in about two seconds and finds the CPU spike and the fork bomb, but not the slow memory leak that MVAD flags. The keys `sliding_window`, `device`, `extra_params` and `min_gradient_steps` apply to `mvad` only.

The anomaly documents and events have the same fields for every backend. The fields named `mvad_score` (the backend's raw score: MVAD's score, the robust z-score of `pca`'s distance, or `ewma`'s largest z-score) and `mvad_severity` keep their names for compatibility, and `sliding_window` is 0 for `pca` and `ewma`.

### lookback_hours

How much historical data to use for training:

```yaml
training:
  lookback_hours: 168  # 1 week
```

Guidelines:
- **24-72 hours**: Quick baseline, less stable
- **168 hours (1 week)**: Balanced, recommended
- **336+ hours (2+ weeks)**: Comprehensive, captures weekly patterns

### numeric_fields

Numeric features to analyze:

```yaml
training:
  numeric_fields:
    - "rule.level"
    - "data.cpu_usage_%"
    - "data.memory_usage_%"
```

Common fields:
- `rule.level`: Alert severity
- `rule.firedtimes`: Alert frequency
- `data.cpu_usage_%`: CPU metrics
- `data.memory_usage_%`: Memory metrics
- `data.login_attempts`: Authentication attempts

### categorical_fields

Categorical features, counted per value:

```yaml
training:
  categorical_fields:
    - "agent.id"
    - "agent.name"
    - "rule.groups"
  categorical_top_k: 10
```

Common fields:
- `agent.id`: Agent identifier
- `agent.name`: Agent hostname
- `rule.groups`: Rule category
- `data.srcip`: Source IP address
- `data.dstip`: Destination IP address

Training keeps the `categorical_top_k` most frequent values of each field. This vocabulary is stored in the model. Each of its values gets a column `<field>__<value>` holding the number of alerts with that value in the bucket (for a list field such as `rule.groups`, each element counts). Every other value, including values that first appear at detection time, is counted in `<field>__other`, which always exists. A new kind of event therefore shows up as a rise in `__other` instead of being dropped.

**Note**: Limit categorical fields to avoid feature explosion. Use `categorical_top_k` to keep only top N values.

### Feature columns

Every bucket of the analysed period is a row, including buckets without alerts. The columns are:

| Column | Value per bucket | Bucket without alerts |
|--------|------------------|-----------------------|
| `alert_count` | number of alerts | 0 |
| each `numeric_fields` entry | mean over the alerts that carry the field | `numeric_fill` |
| `<field>__max` (`max_numeric_fields`) | maximum over the alerts that carry the field | `numeric_fill` |
| each derived feature | number of alerts matching its condition | 0 |
| `<field>__<value>`, `<field>__other` | number of alerts with that value | 0 |

Training starts at the bucket of the first alert; detection covers the whole detection window, so a drop in alert volume is visible.

### max_numeric_fields

Numeric fields that also get a per-bucket maximum column, `<field>__max` (default: none):

```yaml
training:
  max_numeric_fields:
    - "data.cpu_usage_%"
```

The mean spreads a short spike over the whole bucket; the maximum keeps it. A field listed here is read even if it is not in `numeric_fields`.

### numeric_fill

What a numeric column holds in a bucket where no alert carries the field:

```yaml
training:
  numeric_fill: zero   # default; "ffill" carries the last value forward
```

Use `ffill` for gauge metrics such as CPU or memory, where "no reading" does not mean 0 %.

### count_transform

```yaml
training:
  count_transform: none   # default; "log1p" compresses bursts in count columns
```

### bucket_minutes

Time bucket size for aggregation:

```yaml
training:
  bucket_minutes: 5
```

Guidelines:
- **1-2 min**: High-frequency monitoring (CPU, memory)
- **5 min**: Standard security monitoring
- **10-15 min**: Lower-frequency aggregation

Trade-off: Smaller buckets = more features = longer training

### sliding_window

MVAD algorithm parameter:

```yaml
training:
  sliding_window: 200
```

Guidelines:
- **50-100**: Small datasets, faster training
- **200**: Default, balanced
- **300-500**: Large datasets, more context

At detection time the model needs `input_size + threshold_window − 1` buckets of context before the first bucket it scores (`input_size` = `sliding_window / 2`, `threshold_window` = min(200, `sliding_window − input_size`); 199 buckets for `sliding_window: 200`). SONAR fetches that context on its own (see [lookback_minutes](#lookback_minutes)). Training needs considerably more; see [Training data size](#training-data-size).

### Training data size

The MVAD library trains on windows of `sliding_window / 2` buckets, taken every `interval` buckets (default 10). It uses 80% of the buckets for training in batches of `batch_size` (default 128, incomplete batches are dropped) and 10% for validation. With too few buckets it would perform no training update at all and save a random network. SONAR computes this before fitting and refuses to train in that case. The error states how many buckets your settings need:

```
MVAD cannot train on 288 time buckets with sliding_window=200: 13 training windows (stride interval=10) fill no batch of batch_size=128; the validation split is shorter than the input window (100 buckets). At least 1725 buckets are needed with these settings. Increase lookback_hours, decrease bucket_minutes or sliding_window, or lower batch_size/interval in extra_params.
```

A run that trains but performs fewer than `min_gradient_steps` updates (default 500) logs a warning. The log line `Fitting MVAD on N time buckets: ...` shows the windows, batches and total steps of every training run, and the model file records them.

To make a scenario trainable, in order of preference:

1. Set `extra_params: {interval: 1}` to train on every window position. This multiplies the training windows by ten without losing context. All shipped scenarios use it.
2. Increase `lookback_hours`, or decrease `bucket_minutes`.
3. Decrease `sliding_window`. The validation split (10% of the buckets) must be longer than `sliding_window / 2`.
4. Lower `batch_size` in `extra_params`.

The buckets counted are those from the first alert in the lookback to its end, including buckets without alerts. Time before the first alert does not count, so on an indexer with less history than `lookback_hours` the training set is shorter than the arithmetic suggests.

`extra_params` accepts any field of the library's `MultiADConfig` (for example `epochs`, `batch_size`, `interval`, `lr`, `seed`). An unknown key is an error that suggests the right name, for example `learning_rate` → `lr`. `input_size` and `threshold_window` are derived from `sliding_window` and cannot be set.

### derived_features

Derived features count, per bucket, the alerts that match a condition:

```yaml
training:
  derived_features: true  # Default: all of them
  # or a focused list:
  derived_features: [is_auth_failure, is_auth_success, is_ssh_event]
  # or none:
  derived_features: false
```

All three scenario entry points (`sonar scenario`, `sonar train/detect --scenario`) apply this key.

**What are derived features?**

Each enabled feature is a column holding the number of alerts in the bucket that meet its condition:

| Feature | Condition |
|---------|----------|
| `is_auth_failure` | Rule groups include `failed_login` / `authentication_failed` / `invalid_login` |
| `is_auth_success` | Rule groups include `authentication_success` / `session_opened` |
| `is_brute_force` | Rule groups include `brute_force` |
| `is_privilege_event` | Rule groups include `sudo` / `su` / `privilege_escalation` / `account_changed` |
| `is_high_severity` | `rule.level >= 10` |
| `is_critical_severity` | `rule.level >= 12` |
| `is_ssh_event` | Rule groups include `ssh` / `sshd` |
| `is_windows_logon` | Rule groups include `windows_logon` / `windows` / `win_logon` |
| `is_cpu_high` | `data.cpu_usage_% >= 80` |
| `is_cpu_critical` | `data.cpu_usage_% >= 95` |
| `is_memory_high` | `data.memory_usage_% >= 80` |
| `is_memory_critical` | `data.memory_usage_% >= 95` |
| `is_high_load` | `data.1min_loadAverage >= 4.0` |

**When to use**: list only the features relevant to the use case. MVAD's anomaly score is a mean over all columns, so every irrelevant column dilutes it. The shipped scenarios use focused lists. An unknown name is an error.

## Detection parameters

### mode

Execution mode (see [Detection modes](#detection-modes)):

```yaml
detection:
  mode: "historical"  # or "batch" (same as historical) or "realtime"
```

### lookback_minutes

The window to score:

```yaml
detection:
  lookback_minutes: 1440  # 288 buckets at bucket_minutes: 5
```

Detection scores the complete buckets of the last `lookback_minutes`. The window ends at the start of the current bucket, which is still filling and is never scored, or one bucket earlier while the last bucket ended less than [`ingest_delay_seconds`](#ingest_delay_seconds) ago. Before the window, SONAR fetches the `input_size + threshold_window − 1` buckets of context the loaded model needs (199 buckets for `sliding_window: 200`), so any lookback of at least one bucket works. Only buckets inside the window are reported.

Against a live indexer, buckets without alerts count as zero activity, including context buckets from before the indexer held any data, so a fresh installation is scored against a mostly empty context. If the fetched range holds no alerts at all, the run logs `No alerts in the detection window`, scores nothing and exits with status 2 (realtime mode keeps polling).

In `--debug` mode the time range is ignored: every bucket of the local file after its first `input_size + threshold_window − 1` buckets is scored. A file shorter than `input_size + threshold_window` buckets logs `Insufficient data for detection` and exits with status 2.

`sonar detect --scenario` uses this key unless you pass `--lookback-minutes`.

In realtime mode the watermark keeps a long window from re-delivering anomalies, so the window only needs to cover the longest run of anomalous buckets that `min_consecutive` should see; scoring cost grows with it.

### ingest_delay_seconds

```yaml
detection:
  ingest_delay_seconds: 60  # default
```

Seconds a bucket must have ended before it is scored. Alerts reach the indexer some time after they happen; scoring a bucket the moment it ends would count only the alerts indexed so far. Raise it if your Wazuh pipeline lags more than a minute. An integer of at least 0.

### polling_interval_seconds

```yaml
detection:
  polling_interval_seconds: 120  # default null
```

Realtime mode only. Fixed wait between polls. When unset (the default), each poll runs once the next bucket has ended plus `ingest_delay_seconds`, which scores every bucket as soon as it can be scored and never twice for nothing.

### max_consecutive_failures

```yaml
detection:
  max_consecutive_failures: 5  # default
```

Realtime mode only. Number of failed polls in a row after which SONAR exits with status 1 (for a service manager to restart or alert on). At least 1.

### threshold

```yaml
detection:
  threshold: 0.5  # default null
```

Minimum severity (0.0–1.0) a bucket needs to be reported. A bucket is reported only when the backend's own `is_anomaly` flag is set **and**, if `threshold` is set, its severity is at least `threshold`, so `threshold` can only make detection stricter, never flag a bucket the backend did not. The value is also written to the `threshold` field of each anomaly document.

With the `mvad` backend, the severity is MVAD's raw score divided by e − 1, so it lies between 0 and 1, and it is 0 for buckets MVAD does not flag (for `pca` and `ewma`, see [backend](#backend)). The raw score is a mean over all feature columns, so columns unrelated to the attack dilute it; a focused feature list (see [derived_features](#derived_features)) keeps the severity of a real anomaly high.

- `null` (the default): report every bucket MVAD flags
- Lower (for example 0.3): report more of MVAD's anomalies, including weaker ones
- Higher (for example 0.7): report only strong anomalies, fewer false positives

A value outside [0, 1], or one that is not a number, is an error when the scenario loads. The bundled detection scenarios ship a `threshold`, `min_consecutive` and `anomaly_confidence` calibrated on labelled synthetic data (see the [evaluation guide](./evaluation-guide.md)); recalibrate them on data from your environment. `example_scenario.yaml` keeps `threshold: null`. Plain `sonar detect` without `--scenario` applies no threshold.

### min_consecutive

```yaml
detection:
  min_consecutive: 2  # default 1
```

Minimum number of consecutive qualifying buckets (flagged by MVAD and, if `threshold` is set, at or above it). Shorter runs are dropped; every bucket of a long-enough run is reported. Use it to suppress one-off spikes: with 5-minute buckets, `min_consecutive: 3` reports only anomalies that last at least 15 minutes. `1` (the default) reports single buckets.

### anomaly_confidence

```yaml
detection:
  anomaly_confidence: 0.8  # default null
```

How far this scenario's anomalies can be trusted, between 0 and 1. Set it to the scenario's measured precision (the share of reported anomalies that were real). SONAR sends it with every anomaly: as `anomaly_confidence` in the Wazuh event (`data.anomaly_confidence` in the alert, read by RADAR next to `data.anomaly_grade`, the severity) and in the data stream document. It does not change which buckets are reported.

When it is `null` (the default), SONAR sends 0.5 and warns at start-up that the value is not measured. A value outside [0, 1], or one that is not a number, is an error when the scenario loads.

### print_payloads, dry_run and payload_dir

```yaml
detection:
  print_payloads: false  # true: also print every anomaly event on standard output (like --print-payloads)
  dry_run: false         # true: write the events to <payload_dir>/anomalies.jsonl instead of the sinks (like --dry-run)
  payload_dir: null      # directory of the dry-run file; default: payloads/ in the SONAR home
```

`true` in the scenario or the flag on the command line turns each option on. A `--payload-dir` on the command line wins over `payload_dir`, which is relative to the scenario file. A dry run neither reads nor moves the watermarks.

## Query filters (alert_filter)

Filter which alerts are fetched using OpenSearch query DSL. Place `alert_filter` inside the `training:` section. Every scenario entry point applies it; `--debug` ignores it (see [alert_filter](#alert_filter)).

### Authentication events only

```yaml
training:
  alert_filter:
    bool:
      should:
        - match: {"rule.groups": "authentication"}
        - match: {"rule.groups": "sudo"}
```

### Specific agents

```yaml
training:
  alert_filter:
    bool:
      must:
        - terms:
            agent.id: ["001", "002", "003"]
```

### High-severity alerts

```yaml
training:
  alert_filter:
    range:
      rule.level:
        gte: 10
```

### Complex filters

```yaml
training:
  alert_filter:
    bool:
      must:
        - range:
            rule.level:
              gte: 5
      should:
        - match: {"rule.groups": "web"}
        - match: {"rule.groups": "attack"}
      must_not:
        - match: {"agent.name": "test-agent"}
```

## Built-in scenarios

SONAR includes ready-to-use scenarios in `sonar/scenarios/`. They are also installed with SONAR, so `--use-case <name>` (for example `--use-case brute_force_detection`) finds them from any directory. None sets `model_name`, except `linux_resource_monitoring.yaml`, `radar_linux_resource_utilization.yaml` and `example_model_naming.yaml`, so their models are named after their `name`.

### Brute force detection

**File**: `sonar/scenarios/brute_force_detection.yaml`

**Use case**: Detect unusual authentication patterns indicating brute force attacks.

Needs at least 1010 5-minute buckets of training history, counted from the first alert.

### Lateral movement detection

**File**: `sonar/scenarios/lateral_movement_detection.yaml`

**Use case**: Identify unusual cross-host authentication patterns.

Needs at least 730 10-minute buckets of training history, counted from the first alert.

### Privilege escalation detection

**File**: `sonar/scenarios/privilege_escalation_detection.yaml`

**Use case**: Detect unusual privilege escalation attempts via sudo/su.

Needs at least 490 15-minute buckets of training history, counted from the first alert (the scenario trains on 14 days).

### Linux resource monitoring

**File**: `sonar/scenarios/linux_resource_monitoring.yaml`

**Use case**: Identify CPU spikes, memory leaks, fork bombs, resource exhaustion.

Needs at least 610 one-minute buckets of training history. The debug data (`resource_monitoring_training.json`) holds 24 hours.

### RADAR Linux resource utilization

**File**: `sonar/scenarios/radar_linux_resource_utilization.yaml`

**Use case**: Detect anomalous CPU and memory use on the events of RADAR's `linux_resource_utilization` collector, read from `wazuh-archives-*` with RADAR's four features, for comparison with RADAR's detector (see the [RADAR comparison guide](./radar-comparison-guide.md)).

Needs at least 610 one-minute buckets of training history.

## Advanced patterns

### Weekly retraining

Maintain fresh baseline with weekly retraining:

```bash
# Crontab entry: Every Sunday at 2 AM
0 2 * * 0 cd /home/alab/soar && poetry run sonar scenario --use-case sonar/scenarios/brute_force_detection.yaml
```

Scenario should include only a `training:` section to update the model without immediate detection. Each run replaces the model of the same name, which later detection runs of the same scenario load.

### Continuous monitoring

Run detection continuously:

```yaml
detection:
  mode: "realtime"
  lookback_minutes: 60  # window to score on each poll; context is fetched automatically
```

If the scenario also has a `training:` section, the service retrains once at every start before polling.

The watermark keeps restarts from delivering anomalies twice. Set `output.state_dir` to a directory the service user can write and that survives reinstalls. After `max_consecutive_failures` failed polls SONAR exits with status 1, and `Restart=always` starts it again.

Deploy as systemd service:

```ini
[Unit]
Description=SONAR Continuous Monitoring
After=network.target

[Service]
Type=simple
User=alab
WorkingDirectory=/home/alab/soar
Environment=SONAR_HOME=/var/lib/sonar
ExecStart=/home/alab/.local/bin/poetry run sonar scenario --use-case sonar/scenarios/my_realtime_monitor.yaml
Restart=always

[Install]
WantedBy=multi-user.target
```

`my_realtime_monitor.yaml` stands for your own scenario with `mode: "realtime"`; no such file ships with SONAR. With `SONAR_HOME` set, the models and watermarks go to `/var/lib/sonar/models/` instead of the checkout's `sonar/models/`.

### Staged rollout

Test new scenarios safely:

```yaml
# 1. sonar/scenarios/new_scenario.yaml: training only, with a stable model name
name: "New Scenario"
model_name: "new_scenario_v1"
training:
  lookback_hours: 168
  # ... parameters
```

```bash
# 1. Train and check the logs for bucket and feature counts
poetry run sonar scenario --use-case sonar/scenarios/new_scenario.yaml

# 2. Detect against the stage-1 model without delivering anything, and review the events
poetry run sonar detect --scenario sonar/scenarios/new_scenario.yaml --lookback-minutes 1440 --dry-run
cat sonar/payloads/anomalies.jsonl   # <SONAR home>/payloads; --payload-dir chooses another directory
```

3. For production, add a `detection:` section (and `output:` or `shipping:` if needed) to the file and run it with `sonar scenario`. Note that the run then retrains before detecting.

Stage 2 passes `--lookback-minutes` because the file has no `detection:` section yet (the default would be 10 minutes). Raise `threshold` or `min_consecutive` in the stage-3 `detection:` section if stage 2 reports too many anomalies.

### Multi-scenario monitoring

Run multiple scenarios for comprehensive coverage:

```bash
#!/bin/bash
# monitor_all.sh

poetry run sonar scenario --use-case sonar/scenarios/brute_force_detection.yaml
poetry run sonar scenario --use-case sonar/scenarios/lateral_movement_detection.yaml
poetry run sonar scenario --use-case sonar/scenarios/privilege_escalation_detection.yaml
poetry run sonar scenario --use-case sonar/scenarios/linux_resource_monitoring.yaml
```

Schedule via cron:
```
*/30 * * * * /home/alab/soar/monitor_all.sh >> /var/log/sonar/monitor.log 2>&1
```

Each shipped scenario has a `training:` section, so every run retrains before detecting.

## Testing scenarios

### Debug mode testing

Test scenarios without Wazuh:

```bash
# Test with local data
poetry run sonar scenario --use-case sonar/scenarios/linux_resource_monitoring.yaml --debug
```

Only the `--debug` CLI flag switches SONAR to local data. `debug.enabled: true` in YAML switches the anomalies to the debug sinks, like `--debug`, but SONAR still reads alerts from the Wazuh Indexer.

The `debug:` section chooses the local files. A relative `data_dir` is relative to the scenario file; without one, SONAR reads the packaged `sonar/test_data/synthetic_alerts`. `linux_resource_monitoring.yaml` points at its own dataset:

```yaml
debug:
  data_dir: "../test_data/resource_monitoring"   # relative to sonar/scenarios/
  training_data_file: "resource_monitoring_training.json"
  detection_data_file: "resource_monitoring_detection.json"
```

Debug mode sends the anomalies to `output.debug_sinks` (by default `stdout`: one SONAR event per line on standard output, logs on standard error) instead of the configured sinks, and it ignores `alert_filter` and the watermarks. `debug_sinks` accepts any sink but `index`; `[wazuh]` sends the test data's anomalies to a lab manager, again on every run, since debug runs use no watermark. The events are exactly the lines the `wazuh` sink would send, so a debug run also checks the output format.

### Validation checklist

Before deploying scenarios:

- [ ] Scenario loads without errors
- [ ] Training completes successfully
- [ ] Detection finds expected patterns in test data
- [ ] False positive rate is acceptable
- [ ] Performance is adequate (< 5 min for training)
- [ ] Documentation is clear

### Common issues

**Feature settings changed after training**:
- Detection uses the feature settings and vocabulary stored in the model and logs a warning listing the settings that differ. Retrain to apply the new ones.
- Verify: the `Feature matrix:` log line shows bucket, column and empty-bucket counts

**Empty training data**:
- Solution: Extend `lookback_hours` or add/adjust `alert_filter` under `training:`
- Verify: Check alert count in logs

**Too many features**:
- Solution: Reduce `categorical_top_k` or limit `categorical_fields`
- Verify: Feature count should be < 50 for most use cases

## Best practices

1. **Start simple**: Begin with numeric features only, add categorical gradually
2. **Tune thresholds gradually**: start with `threshold: null` and `min_consecutive: 1`, then set a minimum severity or raise `min_consecutive` if false positives dominate
3. **Version control**: Store scenarios in git alongside code
4. **Document assumptions**: Add comments explaining field choices
5. **Monitor performance**: Track training/detection times
6. **Regular retraining**: Update baselines weekly or monthly
7. **Test before production**: Always validate with debug mode first
