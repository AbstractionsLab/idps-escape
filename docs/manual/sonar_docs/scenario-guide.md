# SONAR scenario guide

Complete guide to scenario-based anomaly detection with SONAR (SIEM-Oriented Neural Anomaly Recognition).

## Overview

SONAR uses **YAML-based scenarios** to define complete anomaly detection workflows. Each scenario specifies what data to analyze, how to train models, and how to detect anomalies.

### Key benefits

- **Reproducible**: Version control scenario definitions
- **Flexible**: Training-only, detection-only, or combined workflows
- **Reusable**: Share scenarios across teams and environments
- **Maintainable**: Centralized detection logic

## Scenario structure

### Complete scenario template

```yaml
name: "Scenario Name"
description: "What this scenario detects"
enabled: true

# Optional: Custom model name for saving/loading
model_name: "my_scenario_baseline_v1"  # Auto-generated if omitted

# Optional: OpenSearch query filter to limit processed alerts
# NOTE: This feature is planned but not yet implemented
# query_filter:
#   bool:
#     should:
#       - match: {"rule.groups": "authentication"}
#       - match: {"rule.groups": "sudo"}
#     # Also supports: must, must_not, filter for complex queries

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
- `query_filter`: OpenSearch query DSL to filter alerts before processing (**Planned feature - not yet implemented**)
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

#### query_filter

**Status: Planned feature - not yet implemented in current version**

OpenSearch query DSL to pre-filter alerts before feature extraction:

```yaml
# query_filter:  # Commented out until implemented
#   bool:
#     must:
#       - match: {"rule.groups": "authentication"}
#     should:
#       - match: {"rule.groups": "sudo"}
#       - match: {"rule.groups": "ssh"}
#     must_not:
#       - match: {"agent.name": "test-agent"}
```

**Planned use cases**:
- Limit to specific rule groups (authentication, web, network)
- Exclude test/development agents
- Focus on high-severity alerts only: `{"range": {"rule.level": {"gte": 7}}}`
- Filter by attack techniques: `{"match": {"rule.mitre.technique": "T1078"}}`

**Note**: Currently, alerts are processed from all indices matching the pattern. Use scenario-specific models for focused detection.

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

### Example: Full workflow

```yaml
name: "Brute Force Detection"
description: "Detect authentication attack patterns"
enabled: true

training:
  lookback_hours: 168  # 1 week baseline
  numeric_fields: ["rule.level"]
  categorical_fields: ["agent.id", "rule.groups"]
  bucket_minutes: 5
  sliding_window: 200

detection:
  mode: "batch"
  lookback_minutes: 60
  threshold: 0.7
```

Execution:
```bash
poetry run sonar scenario --use-case brute_force_detection.yaml
```

Output:
```
Phase 1: Training model on 168 hours of data...
✓ Training complete. Model saved to ./model/mvad_model.pkl

Phase 2: Running detection on last 60 minutes...
✓ Detection complete. Found 3 anomalies.
```

### Example: Training only

```yaml
name: "Weekly Baseline"
description: "Establish detection baseline (no immediate detection)"
enabled: true

training:
  lookback_hours: 336  # 2 weeks
  numeric_fields: ["rule.level"]
  categorical_fields: ["agent.id"]
  bucket_minutes: 10
  sliding_window: 250
```

Execution:
```bash
poetry run sonar scenario --use-case weekly_baseline.yaml
```

Use case: Scheduled weekly retraining via cron without immediate detection.

### Example: Detection only

```yaml
name: "Ad-hoc Investigation"
description: "Investigate recent activity with existing model"
enabled: true

detection:
  mode: "historical"
  lookback_minutes: 120
  threshold: 0.75
```

Execution:
```bash
poetry run sonar scenario --use-case adhoc_investigation.yaml
```

Use case: Quick investigation using pre-trained model from baseline.

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

Instead of just raw alert fields (e.g., `rule.level`), SONAR computes additional features:
- **Alert frequency patterns**: Sudden spikes or drops in alert rate
- **Severity trends**: Changes in average alert severity over time
- **Source diversity**: Unique source IPs, users, or hosts per bucket
- **Temporal patterns**: Hour-of-day, day-of-week encoding

**When to use**:
- Enable (default): Most security scenarios benefit from derived features
- Disable: Only when analyzing simple numeric metrics (CPU, memory) where raw values are sufficient

**Example**: For authentication monitoring:
- Raw: `rule.level = 5`
- Derived: `auth_failures_per_minute = 15`, `unique_srcip_count = 8`, `hour_of_day_encoded = 0.75`

**Impact**: Adds ~5-10 computed columns to feature set, improves detection of complex attack patterns.

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

## Query filters

Filter which alerts to analyze using OpenSearch query DSL:

### Authentication events only

```yaml
query_filter:
  bool:
    should:
      - match: {"rule.groups": "authentication"}
      - match: {"rule.groups": "sudo"}
```

### Specific agents

```yaml
query_filter:
  bool:
    must:
      - terms:
          agent.id: ["001", "002", "003"]
```

### High-severity alerts

```yaml
query_filter:
  range:
    rule.level:
      gte: 10
```

### Complex filters

```yaml
query_filter:
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

```yaml
name: "Brute Force Detection"
description: "Detect authentication attack patterns"
enabled: true

query_filter:
  bool:
    should:
      - match: {"rule.groups": "authentication"}

training:
  lookback_hours: 168
  numeric_fields: ["rule.level"]
  categorical_fields: ["agent.id", "rule.groups"]
  bucket_minutes: 5
  sliding_window: 200

detection:
  mode: "historical"
  lookback_minutes: 60
  threshold: 0.7
```

**Use case**: Detect unusual authentication patterns indicating brute force attacks.

### Lateral movement detection

**File**: `sonar/scenarios/lateral_movement_detection.yaml`

```yaml
name: "Lateral Movement Detection"
description: "Detect lateral movement via authentication patterns"
enabled: true

query_filter:
  bool:
    should:
      - match: {"rule.groups": "authentication"}
      - match: {"rule.groups": "ssh"}

training:
  lookback_hours: 336  # 2 weeks
  numeric_fields: ["rule.level"]
  categorical_fields: ["agent.id", "data.srcip"]
  bucket_minutes: 10
  sliding_window: 250

detection:
  mode: "batch"
  lookback_minutes: 120
  threshold: 0.75
```

**Use case**: Identify unusual cross-host authentication patterns.

### Privilege escalation detection

**File**: `sonar/scenarios/privilege_escalation_detection.yaml`

```yaml
name: "Privilege Escalation Detection"
description: "Monitor privilege escalation attempts"
enabled: true

query_filter:
  bool:
    should:
      - match: {"rule.groups": "sudo"}
      - match: {"rule.groups": "privilege_escalation"}

training:
  lookback_hours: 168
  numeric_fields: ["rule.level"]
  categorical_fields: ["agent.id", "data.command"]
  categorical_top_k: 15
  bucket_minutes: 15
  sliding_window: 150

detection:
  mode: "historical"
  lookback_minutes: 60
  threshold: 0.8
```

**Use case**: Detect unusual privilege escalation attempts via sudo/su.

### Linux resource monitoring

**File**: `sonar/scenarios/linux_resource_monitoring.yaml`

```yaml
name: "Linux Resource Monitoring"
description: "Detect resource exhaustion and abnormal usage"
enabled: true

query_filter:
  bool:
    should:
      - match: {"rule.groups": "syslog"}
      - match: {"rule.groups": "performance"}

training:
  lookback_hours: 24
  numeric_fields:
    - "data.cpu_usage_%"
    - "data.memory_usage_%"
    - "rule.level"
  categorical_fields:
    - "agent.name"
    - "rule.groups"
  categorical_top_k: 10
  bucket_minutes: 1
  sliding_window: 300
  device: "cpu"

detection:
  mode: "batch"
  lookback_minutes: 10
  threshold: 0.85
```

**Use case**: Identify CPU spikes, memory leaks, fork bombs, resource exhaustion.

## Advanced patterns

### Weekly retraining

Maintain fresh baseline with weekly retraining:

```bash
# Crontab entry: Every Sunday at 2 AM
0 2 * * 0 cd /home/alab/soar && poetry run sonar scenario --use-case scenarios/brute_force_detection.yaml
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

poetry run sonar scenario --use-case scenarios/brute_force_detection.yaml
poetry run sonar scenario --use-case scenarios/lateral_movement_detection.yaml
poetry run sonar scenario --use-case scenarios/privilege_escalation_detection.yaml
poetry run sonar scenario --use-case scenarios/linux_resource_monitoring.yaml
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
  data_dir: "./test_data/resource_monitoring"
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
- Solution: Extend `lookback_hours` or adjust `query_filter`
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

## Next steps

- Review [setup-guide.md](./setup-guide.md) for installation details
- See [architecture.md](./architecture.md) for system design
- Check [troubleshooting.md](./troubleshooting.md) for error resolution
