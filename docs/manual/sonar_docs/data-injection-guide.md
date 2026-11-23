# Data injection guide for production testing

## Overview

The `inject_wazuh_data.py` tool solves a critical problem for SONAR testing and development: **fresh Wazuh installations don't have enough historical data** to train the MVAD model (with the default settings, about 1000 five-minute buckets between the first alert and the end of the training window, empty buckets included; the training error states the number for your settings).

Instead of waiting 24+ hours for real alerts to accumulate, inject synthetic data and start testing immediately.

## Quick start

All commands shown from project root (`/home/alab/soar/`):

```bash
# Navigate to test data directory
cd /home/alab/soar/sonar/test_data

# 1. Preview what would be injected (safe, no changes)
poetry run python inject_wazuh_data.py --hours 24 --dry-run

# 2. Inject 7 days of normal baseline (training needs about 3.5 days of 5-minute buckets)
poetry run python inject_wazuh_data.py --days 7 --source generated_scenarios/normal_training.json

# 3. Train SONAR (from project root); the model is sonar/models/brute_force_detection/
cd /home/alab/soar
poetry run sonar train --scenario sonar/scenarios/brute_force_detection.yaml

# 4. Inject attack data
cd sonar/test_data
poetry run python inject_wazuh_data.py --hours 48 --source generated_scenarios/attack_scenarios.json

# 5. Run detection (from project root). The scenario's lookback_minutes (1440) applies;
#    --lookback-minutes 2880 widens it to the full 48 injected hours
cd /home/alab/soar
poetry run sonar detect --scenario sonar/scenarios/brute_force_detection.yaml --lookback-minutes 2880
```

Notes on this walkthrough:

- **`train` and `detect` use the same model.** `brute_force_detection.yaml` has no `model_name`, so both commands use its `name` in lower case, `brute_force_detection`: the directory `sonar/models/brute_force_detection/`. Training again replaces it; see the [model guide](./model-naming-guide.md) to keep versions.
- **Lookback comes from the scenario** (`lookback_hours: 168`, `lookback_minutes: 1440`) unless you pass `--lookback-hours` or `--lookback-minutes`.
- **`lookback_minutes` is the window to score.** Detection also fetches the 199 buckets (about 16.6 hours at 5-minute buckets, for `sliding_window: 200`) of context the model needs before that window. Buckets without alerts count as silence, so inject history that covers the context too, or the window is scored against an empty context. With no alerts at all in the fetched range, `detect` exits with status 2 without scoring.
- Alternatively, run training and detection in one `sonar scenario --use-case` run, which applies the same scenario settings.

## Use cases

### Use case 1: Fresh installation testing

Problem: Just deployed Wazuh, need to test SONAR but have < 1 hour of alerts

Solution:
```bash
# Inject 14 days of baseline for comprehensive training
poetry run python inject_wazuh_data.py --days 14 --source generated_scenarios/normal_training.json
```

**Path context**: When running from `sonar/test_data/`, paths like `generated_scenarios/attack_scenarios.json` are relative to that directory.

### Use case 2: Attack scenario demos

Problem: Need to demonstrate anomaly detection with known attack patterns

Solution:
```bash
# First: Train on normal baseline
poetry run python inject_wazuh_data.py --days 14 --source generated_scenarios/normal_training.json
# Train model...

# Second: Inject attacks
poetry run python inject_wazuh_data.py --hours 48 --source generated_scenarios/attack_scenarios.json
# Run detection...
```

### Use case 3: Integration testing

Problem: Need to validate full production pipeline without real infrastructure under attack

Solution:
```bash
# Inject various scenarios in sequence
poetry run python inject_wazuh_data.py --hours 24 --source synthetic_alerts/normal_baseline.json
# Test detection...

poetry run python inject_wazuh_data.py --hours 24 --source synthetic_alerts/with_anomalies.json
# Validate anomaly detection...
```

### Use case 4: Custom time ranges

Problem: Need specific historical data for backfilling or testing time-based queries

Solution:
```bash
# Inject data for specific date range
poetry run python inject_wazuh_data.py \
  --range "2025-12-01 00:00:00" "2025-12-15 23:59:59" \
  --source generated_scenarios/normal_training.json
```

### Use case 5: Replay labelled evaluation splits

Problem: Need labelled data in a lab indexer, for example to score another detector with `sonar evaluate`

Solution:
```bash
# Write labelled splits (training, validation and test files plus *_labels.json)
poetry run python generate_attack_data.py --evaluation --output-dir /tmp/eval/auth

# Index a split at its own timestamps, so its label file stays valid
poetry run python inject_wazuh_data.py --source /tmp/eval/auth/test.json --keep-timestamps
```

`--keep-timestamps` leaves every alert's `timestamp` unchanged; the splits are dated in the past, so the alerts land in the daily indices of those dates. See [Evaluating detection quality](./evaluation-guide.md#comparing-with-another-detector).

## Command reference

### Basic options

| Option | Description | Example |
|--------|-------------|---------|
| `--config` | Path to config YAML | `--config ../default_config.yaml` |
| `--source` | JSON file holding a plain array of alert documents (an OpenSearch `_search` response is not accepted) | `--source generated_scenarios/attack_scenarios.json` |
| `--dry-run` | Preview without indexing | `--dry-run` |
| `--verbose` | Detailed logging | `--verbose` |

### Time range options (mutually exclusive)

| Option | Description | Example |
|--------|-------------|---------|
| `--hours N` | Last N hours | `--hours 24` |
| `--days N` | Last N days | `--days 14` |
| `--range START END` | Custom range | `--range "2025-12-29 00:00:00" "2025-12-30 23:59:59"` |
| `--keep-timestamps` | Keep the alerts' own timestamps (labelled evaluation splits) | `--keep-timestamps` |

Without any of them, the alerts are spread over the last 24 hours.

### Connection options

| Option | Description | Default |
|--------|-------------|---------|
| `--host` | Wazuh Indexer host | From config or `localhost` |
| `--port` | Wazuh Indexer port | From config or `9200` |
| `--username` | Auth username | From config or `admin` |
| `--password` | Auth password | From config or `admin` |
| `--no-verify-ssl` | Disable SSL verification | From config (`wazuh.verify_ssl`, `false` in `default_config.yaml`), or enabled without a config |
| `--bulk-size` | Docs per bulk request | `1000` |

## Available data sources

All paths relative to `sonar/test_data/`:

| File | Alerts | Time span | Use case |
|------|--------|-----------|----------|
| `generated_scenarios/normal_training.json` | ~12,000 | 14 days | Training baseline with realistic patterns |
| `generated_scenarios/attack_scenarios.json` | ~2,000 | 2 days | Detection testing with known attacks |
| `synthetic_alerts/normal_baseline.json` | ~12,000 | 1 year | Legacy simple training data |
| `synthetic_alerts/with_anomalies.json` | ~6,000 | 6 months | Legacy detection test data |

### Attack patterns in attack_scenarios.json

- **Brute force** (Hour 8): 200 rapid failed SSH logins
- **Lateral movement** (Hour 14): Sequential auth across 5 servers
- **Privilege escalation** (Hour 26): Failed sudo → user creation
- **Password spray** (Hour 38): One password against all users

## How it works

1. **Loads** synthetic alerts from JSON file
2. **Adjusts** timestamps to fit target time range while maintaining temporal distribution (skipped with `--keep-timestamps`)
3. **Validates** connection to Wazuh Indexer (OpenSearch API)
4. **Groups** alerts by daily indices (e.g., `wazuh-alerts-4.x-2025.12.30`)
5. **Indexes** using bulk API for performance (1000 docs/request by default)

## Troubleshooting

### Connection refused

```bash
# Check if Wazuh Indexer is running
curl -k -u admin:admin https://localhost:9200

# Verify config has correct settings
grep -A10 "wazuh:" /home/alab/soar/sonar/default_config.yaml
```

### SSL certificate errors

```bash
# Disable SSL verification (dev/test environments only)
poetry run python inject_wazuh_data.py --hours 24 --no-verify-ssl
```

### Not enough data after injection

```bash
# Check if alerts were indexed
curl -k -u admin:admin "https://localhost:9200/wazuh-alerts-*/_count"

# Verify time range matches scenario requirements
# Training with the shipped 5-minute scenarios needs days of buckets:
poetry run python inject_wazuh_data.py --days 7  # 2016 time points
```

### Wrong index pattern

The injector always writes to `wazuh-alerts-4.x-YYYY.MM.DD`; `wazuh.alerts_index_pattern` does not change that. The setting is where SONAR searches, so it must match the injected indices:

```yaml
# default_config.yaml (or your own config)
wazuh:
  base_url: "https://localhost:9200"
  alerts_index_pattern: "wazuh-alerts-*"  # matches wazuh-alerts-4.x-*
```

## Best practices

### 1. Match scenario requirements

For SONAR scenarios with 5-minute buckets and `sliding_window: 200`:
- **Training**: enough buckets between the first alert and the end of the training window (empty ones count) for MVAD to perform training updates; the error message states how many (about 3.5 days with `interval: 1`, see [Training data size](./scenario-guide.md#training-data-size))
- **Detection**: the scored window (`lookback_minutes`) plus 199 buckets (about 16.6 hours) of context before it, which SONAR fetches on its own

```bash
# Enough for detection with lookback_minutes: 1440 (context plus window): 2 days = 576 time points
poetry run python inject_wazuh_data.py --days 2

# Better: 7 days = 2016 time points
poetry run python inject_wazuh_data.py --days 7

# Best: 14 days = 4032 time points
poetry run python inject_wazuh_data.py --days 14
```

### 2. Clean old data between tests

```bash
# Delete old test indices (CAUTION: Deletes data!)
curl -k -u admin:admin -X DELETE "https://localhost:9200/wazuh-alerts-4.x-2025.12.*"

# Or use specific date
curl -k -u admin:admin -X DELETE "https://localhost:9200/wazuh-alerts-4.x-2025.12.30"
```

### 3. Tune bulk size for performance

```bash
# Small Wazuh instances (< 4GB RAM)
poetry run python inject_wazuh_data.py --hours 24 --bulk-size 500

# Large instances (8GB+ RAM)
poetry run python inject_wazuh_data.py --hours 24 --bulk-size 5000
```

## Technical details

### Timestamp adjustment algorithm

The tool maintains the relative temporal distribution of alerts:

1. Parse original timestamps from JSON
2. Calculate original time span: `orig_duration = max_ts - min_ts`
3. Calculate target time span: `target_duration = end - start`
4. For each alert:
   ```
   relative_pos = (alert_ts - orig_start) / orig_duration
   new_ts = target_start + (relative_pos * target_duration)
   ```

This preserves:
- Attack sequence timing
- Business hours patterns
- Event clustering
- Relative frequencies

### Index naming convention

Wazuh uses daily indices: `wazuh-alerts-4.x-YYYY.MM.DD`

The tool automatically:
- Groups alerts by date
- Creates proper index names
- Uses bulk API for each index
- Handles index rollover at midnight

### Bulk indexing format

```json
{"index": {"_index": "wazuh-alerts-4.x-2025.12.30"}}
{"timestamp": "2025-12-30T10:30:00.000Z", "rule": {...}, ...}
{"index": {"_index": "wazuh-alerts-4.x-2025.12.30"}}
{"timestamp": "2025-12-30T10:31:00.000Z", "rule": {...}, ...}
```

- NDJSON format (newline-delimited JSON)
- Action line + document line pairs
- Default: 1000 documents per request

## Comparison with debug mode

| Aspect | Debug mode (`--debug`) | Production + injection |
|--------|------------------------|------------------------|
| Wazuh required | No | Yes |
| OpenSearch API | Not tested | Fully tested |
| Indexing pipeline | Skipped | Validated |
| Realistic testing | Partial | Complete |
| Setup time | Instant | < 1 minute |
| Best for | Quick dev/test | Integration testing |

## See also

- [Setup guide](setup-guide.md) - SONAR installation and configuration
- [Scenario guide](scenario-guide.md) - Creating detection scenarios
- [Test data README](../../../sonar/test_data/README.md) - Available synthetic data files
- [Troubleshooting](troubleshooting.md) - Common issues and solutions
