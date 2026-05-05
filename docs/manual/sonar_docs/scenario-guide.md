# SONAR scenario guide

Complete guide to scenario-based anomaly detection with SONAR (SIEM-Oriented Neural Anomaly Recognition).

## Overview

SONAR uses **YAML-based scenarios** to define complete anomaly detection workflows. Each scenario specifies what data to analyze, how to train models, and how to detect anomalies.

## Scenario structure

### Complete scenario template

```yaml
name: "Scenario Name"
description: "What this scenario detects"
enabled: true

# Optional: Custom model name for saving/loading
model_name: "my_scenario_baseline_v1"  # Auto-generated if omitted

# Training phase (optional)
training:
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
  extra_params: {}
  # Optional: restrict which alerts are fetched from OpenSearch
  alert_filter:
    bool:
      should:
        - match: {"rule.groups": "authentication"}
        - match: {"rule.groups": "sudo"}

# Optional: Data shipping configuration (for production)
shipping:
  enabled: false  # Set true to ship anomalies to dedicated data streams
  install_templates: true  # Install index templates on first run
  scenario_id: "custom_id"  # Optional: custom scenario ID

# Detection phase (optional)
detection:
  mode: "batch"  # or "historical" or "realtime"
  lookback_minutes: 60
  threshold: 0.7
  min_consecutive: 2
```

### Required fields

- `name`: Scenario identifier
- `description`: What the scenario detects
- At least one of: `training` or `detection` section

### Optional top-level fields

- `enabled`: Enable/disable scenario (default: true)
- `model_name`: Custom model filename for saving/loading (auto-generated if omitted)
- `training`: Training phase configuration
- `detection`: Detection phase configuration
- `shipping`: Data shipping configuration for production deployments

#### model_name

Custom identifier for saving and loading trained models:

```yaml
model_name: "brute_force_baseline_v2_20260125"
```

**Behavior**:
- If provided: Model saved as `./models/{model_name}.pkl`
- If omitted: Auto-generated from scenario name and timestamp
- **Best practice**: Use versioned names for production baselines

**Example naming conventions**:
- `{scenario}_{version}_{date}`: `brute_force_v2_20260125`
- `{scenario}_{environment}`: `auth_anomaly_production`
- `{scenario}_{datasource}`: `lateral_movement_dc1`

#### alert_filter

OpenSearch query DSL placed under the `training:` section to pre-filter alerts before feature extraction:

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

Configure data stream shipping for production deployments:

```yaml
shipping:
  enabled: true
  install_templates: true
  scenario_id: "auth_monitoring"
```

**Fields**:
- `enabled`: Enable data shipping to dedicated streams
- `install_templates`: Install index templates (disable after first run)
- `scenario_id`: Custom stream identifier (auto-generated if omitted)

**For complete shipping configuration, RADAR integration, and troubleshooting:** See [data-shipping-guide.md](./data-shipping-guide.md).

## Execution modes

The scenario system automatically determines execution based on YAML sections:

| YAML Sections | Execution Behavior | Use Case |
|---------------|-------------------|----------|
| `training` + `detection` | Train → Detect (batch) | Full workflow with fresh model |
| `training` only | Train (save model) | Establish baseline, no detection |
| `detection` only | Detect (load model) | Ad-hoc investigation with existing model |

## Detection modes

### Historical mode

One-shot detection on recent data:

```yaml
detection:
  mode: "historical"
  lookback_minutes: 60
  threshold: 0.7
```

- Analyzes last N minutes
- Exits after detection completes
- Best for: Ad-hoc investigations

### Batch mode

Detection immediately after training:

```yaml
training:
  lookback_hours: 24
detection:
  mode: "batch"
  lookback_minutes: 10
```

- Trains model, then detects
- Uses freshly trained model
- Best for: Full workflow execution

### Realtime mode

Continuous monitoring:

```yaml
detection:
  mode: "realtime"
  lookback_minutes: 10
  polling_interval_seconds: 60
  threshold: 0.8
```

- Polls for new data every N seconds
- Runs until Ctrl+C
- Best for: Production monitoring

## Training parameters

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

Categorical features (one-hot encoded):

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

**Note**: Limit categorical fields to avoid feature explosion. Use `categorical_top_k` to keep only top N values.

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

Must be ≤ number of time buckets in training data.

### min_samples

Minimum samples required for training:

```yaml
training:
  min_samples: 500
```

**Status: This field is currently ignored by the training engine.**

This parameter was intended to enforce a minimum number of alert samples before training, but validation is not yet implemented. SONAR currently validates only that enough time buckets exist for the sliding window size (≥ sliding_window + 1).

**Planned behavior**:
- Reject training if alert count < min_samples
- Useful for ensuring baseline quality in low-alert environments

**Current workaround**: Use `lookback_hours` to ensure sufficient training data. Monitor logs for time bucket count warnings.

### derived_features

Enable automatic computation of security-relevant derived features:

```yaml
training:
  derived_features: true  # Default
```

**What are derived features?**

SOAR computes boolean indicator columns from alert rule groups and data fields. These are appended to the numeric feature matrix alongside raw fields:

| Feature | Condition |
|---------|----------|
| `is_auth_failure` | Rule groups include `failed_login` / `authentication_failed` |
| `is_auth_success` | Rule groups include `authentication_success` / `session_opened` |
| `is_brute_force` | Rule groups include `brute_force` |
| `is_privilege_event` | Rule groups include `sudo` / `privilege_escalation` / `account_changed` |
| `is_high_severity` | `rule.level >= 10` |
| `is_critical_severity` | `rule.level >= 12` |
| `is_ssh_event` | Rule groups include `ssh` / `sshd` |
| `is_windows_logon` | Rule groups include `windows_logon` / `win_logon` |
| `is_cpu_high` | `data.cpu_usage_% >= 80` |
| `is_cpu_critical` | `data.cpu_usage_% >= 95` |
| `is_memory_high` | `data.memory_usage_% >= 80` |
| `is_memory_critical` | `data.memory_usage_% >= 95` |
| `is_high_load` | `data.1min_loadAverage >= 4.0` |

**When to use**:
- Enable (default): All security attack scenarios; captures event type transitions
- Disable: Only when analyzing pure numeric metrics where raw values are sufficient and the boolean flags add noise

## Detection parameters

### mode

Execution mode (see [Detection modes](#detection-modes)):

```yaml
detection:
  mode: "historical"  # or "batch" or "realtime"
```

### lookback_minutes

How much recent data to analyze:

```yaml
detection:
  lookback_minutes: 60
```

Guidelines:
- **10-30 min**: Quick checks
- **60 min**: Standard hourly detection
- **120+ min**: Extended investigation

### threshold

Anomaly score threshold (0-1):

```yaml
detection:
  threshold: 0.7
```

Guidelines:
- **0.5-0.6**: High sensitivity (more alerts)
- **0.7-0.8**: Balanced (recommended)
- **0.85-0.95**: Low sensitivity (fewer, high-confidence alerts)

### min_consecutive

Minimum consecutive anomalous buckets:

```yaml
detection:
  min_consecutive: 2
```

Reduces false positives by requiring sustained anomalies.

## Query filters (alert_filter)

Filter which alerts are fetched using OpenSearch query DSL. Place `alert_filter` inside the `training:` section:

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

SONAR includes ready-to-use scenarios in `sonar/scenarios/` (from project root):

### Brute force detection

**File**: `sonar/scenarios/brute_force_detection.yaml`

**Use case**: Detect unusual authentication patterns indicating brute force attacks.

### Lateral movement detection

**File**: `sonar/scenarios/lateral_movement_detection.yaml`

**Use case**: Identify unusual cross-host authentication patterns.

### Privilege escalation detection

**File**: `sonar/scenarios/privilege_escalation_detection.yaml`

**Use case**: Detect unusual privilege escalation attempts via sudo/su.

### Linux resource monitoring

**File**: `sonar/scenarios/linux_resource_monitoring.yaml`

**Use case**: Identify CPU spikes, memory leaks, fork bombs, resource exhaustion.

## Advanced patterns

### Weekly retraining

Maintain fresh baseline with weekly retraining:

```bash
# Crontab entry: Every Sunday at 2 AM
0 2 * * 0 cd /home/alab/soar && poetry run sonar scenario --use-case sonar/scenarios/brute_force_detection.yaml
```

Scenario should include only `training:` section to update model without immediate detection.

### Continuous monitoring

Run detection continuously:

```yaml
detection:
  mode: "realtime"
  lookback_minutes: 10
  polling_interval_seconds: 60
```

Deploy as systemd service:

```ini
[Unit]
Description=SONAR Continuous Monitoring
After=network.target

[Service]
Type=simple
User=alab
WorkingDirectory=/home/alab/soar
ExecStart=/home/alab/.local/bin/poetry run sonar scenario --use-case scenarios/realtime_monitor.yaml
Restart=always

[Install]
WantedBy=multi-user.target
```

### Staged rollout

Test new scenarios safely:

```yaml
# 1. Training only (validate data quality)
name: "New Scenario - Training Test"
training:
  lookback_hours: 24
  # ... parameters

# 2. Detection with high threshold (reduce noise)
name: "New Scenario - Detection Test"
detection:
  mode: "historical"
  threshold: 0.9  # Very strict

# 3. Production with tuned threshold
name: "New Scenario - Production"
training:
  lookback_hours: 168
detection:
  mode: "batch"
  threshold: 0.75  # Tuned based on testing
```

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

## Testing scenarios

### Debug mode testing

Test scenarios without Wazuh:

```bash
# Test with local data
poetry run sonar scenario --use-case scenarios/example_scenario.yaml --debug
```

Ensure debug configuration points to appropriate test data:

```yaml
debug:
  enabled: true
  data_dir: "sonar/test_data/resource_monitoring"
  training_data_file: "resource_monitoring_training.json"
  detection_data_file: "resource_monitoring_detection.json"
```

### Validation checklist

Before deploying scenarios:

- [ ] Scenario loads without errors
- [ ] Training completes successfully
- [ ] Detection finds expected patterns in test data
- [ ] False positive rate is acceptable
- [ ] Performance is adequate (< 5 min for training)
- [ ] Documentation is clear

### Common issues

**Feature mismatch errors**:
- Solution: Column alignment is automatic in SONAR
- Verify: Check logs for feature count details

**Empty training data**:
- Solution: Extend `lookback_hours` or add/adjust `alert_filter` under `training:`
- Verify: Check alert count in logs

**Too many features**:
- Solution: Reduce `categorical_top_k` or limit `categorical_fields`
- Verify: Feature count should be < 50 for most use cases

## Best practices

1. **Start simple**: Begin with numeric features only, add categorical gradually
2. **Tune thresholds**: Use debug mode to test different threshold values
3. **Version control**: Store scenarios in git alongside code
4. **Document assumptions**: Add comments explaining field choices
5. **Monitor performance**: Track training/detection times
6. **Regular retraining**: Update baselines weekly or monthly
7. **Test before production**: Always validate with debug mode first
