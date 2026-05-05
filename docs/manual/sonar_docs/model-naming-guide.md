# Model Naming and Identification in SONAR

## Overview

SONAR now supports unique model naming and identification for trained models. This feature helps you:
- **Track model versions** (e.g., `brute_force_v1`, `brute_force_v2`)
- **Prevent conflicts** when training multiple scenarios
- **Organize models** by scenario or experiment
- **Enable reproducibility** with timestamped auto-generated names

## Model Naming

### Three Ways to Name Models

#### 1. Via CLI `--model-name` (Highest Priority)
```bash
poetry run sonar train --scenario scenarios/my_scenario.yaml --model-name custom_model_v1
# Saves to: ./sonar/models/custom_model_v1.pkl
```

#### 2. Via Scenario YAML `model_name` Field
```yaml
# scenarios/my_scenario.yaml
name: "My Scenario"
model_name: "my_scenario_v1"  # Model will be saved with this name

training:
  lookback_hours: 24
  # ...
```

```bash
poetry run sonar train --scenario scenarios/my_scenario.yaml
# Saves to: ./sonar/models/my_scenario_v1.pkl
```

#### 3. Auto-Generated (Default)
If no model name is provided, SONAR generates a unique name:
- **Format**: `<scenario_name>_<timestamp>`
- **Example**: `brute_force_detection_20260112_143022.pkl`

```bash
poetry run sonar train --scenario scenarios/brute_force_detection.yaml
# Saves to: ./sonar/models/brute_force_detection_20260112_143022.pkl
```

### Model Name Priority

When multiple sources provide a model name:

1. **CLI `--model-name`** (highest priority)
2. **Scenario YAML `model_name`**
3. **Auto-generated from scenario name + timestamp** (lowest priority)

Example with multiple sources:
```bash
# Scenario YAML has: model_name: "yaml_name"
# CLI provides: --model-name cli_name
poetry run sonar train --scenario my_scenario.yaml --model-name cli_name
# Result: ./sonar/models/cli_name.pkl (CLI wins)
```

## Commands Supporting Model Naming

### `sonar train` Command

Train with explicit model name:
```bash
# Name via CLI
poetry run sonar train --scenario scenarios/linux_resource_monitoring.yaml --model-name linux_monitor_v1

# Name from scenario YAML
poetry run sonar train --scenario scenarios/linux_resource_monitoring.yaml

# Standard mode (without scenario)
poetry run sonar train --config my_config.yaml --model-name my_model
```

### `sonar scenario` Command

The scenario command automatically uses `model_name` from the YAML file:
```bash
poetry run sonar scenario --use-case scenarios/brute_force_detection.yaml
# Uses model_name from YAML, or auto-generates if not specified
```

### `sonar detect` Command

Detection automatically loads the model specified during training:
```bash
# If you trained with a specific model name, detection uses the same path
poetry run sonar detect --scenario scenarios/brute_force_detection.yaml
# Loads model from path determined by scenario's model_name
```

## Scenario YAML Structure

### Complete Example with Model Naming

```yaml
name: "Brute Force Detection"
description: "Detect SSH/RDP brute force attempts"

# Optional: Specify model name (recommended for production)
model_name: "brute_force_v2"

wazuh:
  base_url: "https://localhost:9200"
  username: "admin"
  password: "admin"

training:
  lookback_hours: 168  # 7 days
  numeric_fields:
    - "rule.level"
    - "data.srcip"
  categorical_fields:
    - "agent.name"
  bucket_minutes: 5
  sliding_window: 200

detection:
  mode: "historical"
  lookback_minutes: 60
```

### Without Model Name (Auto-Generated)

```yaml
name: "Quick Test Scenario"
# No model_name specified

training:
  lookback_hours: 24
  numeric_fields: ["rule.level"]
  
detection:
  lookback_minutes: 10

# Model will be: ./sonar/models/quick_test_scenario_20260112_150322.pkl
```

## Model Storage

All models are stored in: `./sonar/models/`

Directory structure:
```
sonar/
├── models/
│   ├── brute_force_v1.pkl
│   ├── brute_force_v2.pkl
│   ├── linux_monitor_20260112_143022.pkl
│   ├── insider_threat_v1.pkl
│   └── .gitkeep
├── scenarios/
│   ├── brute_force_detection.yaml
│   └── linux_resource_monitoring.yaml
└── ...
```

## Best Practices

### Document model configurations
Keep a log of what each model version includes:
```
brute_force_v1: 24h lookback, rule.level only
brute_force_v2: 7d lookback, rule.level + srcip
brute_force_v3: 7d lookback, rule.level + srcip + categorical agent.name
```

## Migration Guide

### Existing Workflows

**Old approach** (single default model):
```bash
poetry run sonar train --config my_config.yaml
# Always overwrites: ./mvad_model.pkl
```

**New approach** (unique identified models):
```bash
# With explicit name
poetry run sonar train --config my_config.yaml --model-name my_model_v1
# Saves to: ./sonar/models/my_model_v1.pkl

# With scenario
poetry run sonar train --scenario scenarios/my_scenario.yaml
# Saves to: ./sonar/models/my_scenario_20260112_143022.pkl
```

### Updating Scenarios

Add `model_name` field to existing scenarios:

**Before**:
```yaml
name: "My Scenario"
training:
  lookback_hours: 24
```

**After**:
```yaml
name: "My Scenario"
model_name: "my_scenario_v1"  # Add this line
training:
  lookback_hours: 24
```

## Troubleshooting

### Model Not Found

**Error**: `FileNotFoundError: model.pkl not found`

**Solution**: Check model path
```bash
# List available models
ls -la ./sonar/models/

# Verify scenario uses correct model_name
cat scenarios/my_scenario.yaml | grep model_name

# Train model if missing
poetry run sonar train --scenario scenarios/my_scenario.yaml
```

### Model Overwrite

**Issue**: Training overwrites existing model

**Cause**: Same model name used twice

**Solutions**:
1. Use versioned names: `model_v1`, `model_v2`
2. Let auto-generation create unique names (includes timestamp)
3. Rename old model before retraining

### Wrong Model Loaded

**Issue**: Detection loads wrong model

**Cause**: Model name mismatch between training and detection

**Solution**: Ensure detection uses same scenario as training
```bash
# Train
poetry run sonar train --scenario scenarios/my_scenario.yaml

# Detect with SAME scenario
poetry run sonar detect --scenario scenarios/my_scenario.yaml
```

## Examples

### Example 1: Production Model with Stable Name

```yaml
# scenarios/prod_brute_force.yaml
name: "Production Brute Force Detection"
model_name: "prod_brute_force"  # Stable name for production

training:
  lookback_hours: 168
  numeric_fields: ["rule.level", "data.srcip"]
  
detection:
  mode: "realtime"
  lookback_minutes: 10
```

```bash
# Train (creates/updates ./sonar/models/prod_brute_force.pkl)
poetry run sonar train --scenario scenarios/prod_brute_force.yaml

# Deploy detection
poetry run sonar detect --scenario scenarios/prod_brute_force.yaml
```

### Example 2: Versioned Development Models

```bash
# Development iteration 1
poetry run sonar train --scenario scenarios/dev.yaml --model-name dev_v1

# Development iteration 2
poetry run sonar train --scenario scenarios/dev.yaml --model-name dev_v2

# Compare results
poetry run sonar detect --scenario scenarios/dev.yaml --model-name dev_v1
poetry run sonar detect --scenario scenarios/dev.yaml --model-name dev_v2
```

### Example 3: Auto-Generated Names for Experiments

```bash
# Experiment 1 (auto-generates with timestamp)
poetry run sonar train --scenario scenarios/experiment.yaml
# Creates: experiment_20260112_100000.pkl

# Experiment 2 (different timestamp)
poetry run sonar train --scenario scenarios/experiment.yaml
# Creates: experiment_20260112_113000.pkl

# Both preserved for comparison
```
