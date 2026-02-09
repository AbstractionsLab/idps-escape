# Data injection guide for production testing

## Overview

The `inject_wazuh_data.py` tool solves a critical problem for SONAR testing and development: **fresh Wazuh installations don't have enough historical data** for the MVAD model (requires 200+ time points).

Instead of waiting 24+ hours for real alerts to accumulate, inject synthetic data and start testing immediately.

## Quick start

All commands shown from project root (`/home/alab/soar/`):

```bash
# Navigate to test data directory
cd /home/alab/soar/sonar/test_data

# 1. Preview what would be injected (safe, no changes)
poetry run python inject_wazuh_data.py --hours 24 --dry-run

# 2. Inject 24 hours of normal baseline
poetry run python inject_wazuh_data.py --hours 24

# 3. Train SONAR (from project root)
cd /home/alab/soar
poetry run sonar train --scenario sonar/scenarios/brute_force_detection.yaml

# 4. Inject attack data
cd sonar/test_data
poetry run python inject_wazuh_data.py --hours 48 --source generated_scenarios/attack_scenarios.json

# 5. Run detection (from project root)
cd /home/alab/soar
poetry run sonar detect --scenario sonar/scenarios/brute_force_detection.yaml
```

## Use cases

### Use case 1: Fresh installation testing

Problem: Just deployed Wazuh, need to test SONAR but have < 1 hour of alerts

Solution:
```bash
# Inject 14 days of baseline for comprehensive training
poetry run python inject_wazuh_data.py --days 14 --source generated_scenarios/normal_training.json
```

### Use case 1b: Export from existing Wazuh and inject

Problem: Have production Wazuh data, want to replicate in test environment

Solution:
```bash
# Step 1: Export from production Wazuh using Dev Tools or curl
curl -k -u admin:admin "https://prod-wazuh:9200/wazuh-alerts-*/_search" \
  -H "Content-Type: application/json" \
  -d '{"query": {"range": {"@timestamp": {"gte": "now-7d"}}}, "size": 10000}' \
  > exported_alerts.json

# Step 2: Inject to test environment (OpenSearch format auto-detected)
poetry run python inject_wazuh_data.py --days 7 --source exported_alerts.json

# Step 3: Use for training (also supports OpenSearch format)
cd /home/alab/soar/sonar
poetry run sonar train --debug  # If using local file in debug mode
```

**Note**: The inject tool automatically detects OpenSearch API response format `{hits: {hits: [{_source: {...}}]}}` and extracts alert documents.

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

## Command reference

### Basic options

| Option | Description | Example |
|--------|-------------|---------|
| `--config` | Path to config YAML | `--config ../default_config.yaml` |
| `--source` | JSON file with alerts | `--source generated_scenarios/attack_scenarios.json` |
| `--dry-run` | Preview without indexing | `--dry-run` |
| `--verbose` | Detailed logging | `--verbose` |

### Time range options (mutually exclusive)

| Option | Description | Example |
|--------|-------------|---------|
| `--hours N` | Last N hours | `--hours 24` |
| `--days N` | Last N days | `--days 14` |
| `--range START END` | Custom range | `--range "2025-12-29 00:00:00" "2025-12-30 23:59:59"` |

### Connection options

| Option | Description | Default |
|--------|-------------|---------|
| `--host` | Wazuh Indexer host | From config or `localhost` |
| `--port` | Wazuh Indexer port | From config or `9200` |
| `--username` | Auth username | From config or `admin` |
| `--password` | Auth password | From config or `admin` |
| `--no-verify-ssl` | Disable SSL verification | SSL enabled by default |
| `--bulk-size` | Docs per bulk request | `1000` |

## Available data sources

All paths relative to `sonar/test_data/`:

| File | Alerts | Time span | Use case |
|------|--------|-----------|----------|
| `generated_scenarios/normal_training.json` | ~12,000 | 14 days | Training baseline with realistic patterns |
| `generated_scenarios/attack_scenarios.json` | ~2,000 | 2 days | Detection testing with known attacks |
| `synthetic_alerts/normal_baseline.json` | ~12,000 | 30 days | Legacy simple training data |
| `synthetic_alerts/with_anomalies.json` | ~6,000 | 30 days | Legacy detection test data |

### Attack patterns in attack_scenarios.json

- **Brute force** (Hour 8): 200 rapid failed SSH logins
- **Lateral movement** (Hour 14): Sequential auth across 5 servers
- **Privilege escalation** (Hour 26): Failed sudo → user creation
- **Password spray** (Hour 38): One password against all users

## How it works

1. **Loads** synthetic alerts from JSON file
2. **Adjusts** timestamps to fit target time range while maintaining temporal distribution
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
# For 200+ time points with 5-minute buckets:
poetry run python inject_wazuh_data.py --days 1  # 288 time points
```

### Wrong index pattern

```bash
# Override index pattern in config
# Edit default_config.yaml:
wazuh:
  base_url: "https://localhost:9200"
  alerts_index_pattern: "wazuh-alerts-*"  # Must match your Wazuh version
```

## Best practices

### 1. Always dry-run first

```bash
poetry run python inject_wazuh_data.py --hours 24 --dry-run
```

Preview shows:
- How many alerts will be indexed
- Which indices will be targeted
- Time range adjustments

### 2. Match scenario requirements

For SONAR scenarios with 5-minute buckets:
- **Minimum**: 1000 minutes (16.7 hours) = 200 time points
- **Recommended**: 24+ hours for robust training

```bash
# Good: 24 hours = 288 time points
poetry run python inject_wazuh_data.py --hours 24

# Better: 7 days = 2016 time points
poetry run python inject_wazuh_data.py --days 7

# Best: 14 days = 4032 time points
poetry run python inject_wazuh_data.py --days 14
```

### 3. Separate training and detection data

```bash
# Phase 1: Train on normal baseline
poetry run python inject_wazuh_data.py --days 14 --source generated_scenarios/normal_training.json
poetry run sonar train --scenario scenarios/brute_force_detection.yaml

# Phase 2: Inject attack data
poetry run python inject_wazuh_data.py --hours 48 --source generated_scenarios/attack_scenarios.json
poetry run sonar detect --scenario scenarios/brute_force_detection.yaml
```

### 4. Clean old data between tests

```bash
# Delete old test indices (CAUTION: Deletes data!)
curl -k -u admin:admin -X DELETE "https://localhost:9200/wazuh-alerts-4.x-2025.12.*"

# Or use specific date
curl -k -u admin:admin -X DELETE "https://localhost:9200/wazuh-alerts-4.x-2025.12.30"
```

### 5. Tune bulk size for performance

```bash
# Small Wazuh instances (< 4GB RAM)
poetry run python inject_wazuh_data.py --hours 24 --bulk-size 500

# Large instances (8GB+ RAM)
poetry run python inject_wazuh_data.py --hours 24 --bulk-size 5000
```

## Complete workflow example

```bash
# 1. Generate fresh attack scenarios
cd /home/alab/soar/sonar/test_data
python generate_attack_data.py

# 2. Preview injection (dry run)
poetry run python inject_wazuh_data.py --days 14 \
  --source generated_scenarios/normal_training.json \
  --dry-run

# 3. Inject training data
poetry run python inject_wazuh_data.py --days 14 \
  --source generated_scenarios/normal_training.json

# 4. Wait for indexing to complete
sleep 10

# 5. Verify data was indexed
curl -k -u admin:admin "https://localhost:9200/wazuh-alerts-*/_count"

# 6. Train SONAR (production mode)
cd /home/alab/soar/sonar
poetry run sonar train --scenario scenarios/brute_force_detection.yaml

# 7. Inject attack data
cd test_data
poetry run python inject_wazuh_data.py --hours 48 \
  --source generated_scenarios/attack_scenarios.json

# 8. Run detection
cd /home/alab/soar/sonar
poetry run sonar detect --scenario scenarios/brute_force_detection.yaml

# 9. Check for anomalies
curl -k -u admin:admin "https://localhost:9200/wazuh-anomalies-mvad/_search?size=10&pretty"
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
