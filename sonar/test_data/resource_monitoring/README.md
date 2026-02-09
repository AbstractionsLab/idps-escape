# Linux Resource Monitoring Scenario

This directory contains test data for the Linux resource monitoring anomaly detection scenario.

## Overview

The resource monitoring scenario detects anomalous system resource usage patterns that may indicate:
- Cryptocurrency mining attacks
- Resource exhaustion/DoS attacks
- Memory leaks
- Fork bombs
- Misconfigured applications
- System compromise

## Test Data Files

### Training Data
- **File**: `resource_monitoring_training.json`
- **Content**: 24 hours of normal system resource monitoring data
- **Alerts**: 11,520 alerts (8 agents × 60 samples/hour × 24 hours)
- **Features**: CPU usage %, memory usage % with realistic patterns
- **Patterns**: 
  - Business hours load variations
  - Server-type specific baselines
  - Periodic batch jobs (backup server at 2-4 AM)
  - Small random fluctuations

### Detection Data
- **File**: `resource_monitoring_detection.json`
- **Content**: 6 hours of data with injected anomalies
- **Alerts**: 3,038 alerts (includes attack patterns)
- **Anomalies Included**:
  1. **CPU Spike (Hour 1)**: Sustained high CPU (88-98%) for 45 minutes
     - Simulates crypto mining or CPU-intensive malware
     - Affects 2-3 random servers
  2. **Memory Leak (Hour 3)**: Gradual memory increase over 60 minutes
     - Linear growth from 50% to 95%
     - Single server affected
     - Simulates memory leak or memory-exhaustion attack
  3. **Fork Bomb (Hour 5)**: Rapid resource exhaustion for 8 minutes
     - Both CPU (92-99%) and memory (88-98%) spike
     - Single server affected
     - Simulates fork bomb or rapid resource abuse

## Usage

### Generate Test Data

```bash
cd sonar/test_data
python generate_resource_data.py --output-dir ./resource_monitoring
```

Options:
- `--training-hours N`: Hours of training data (default: 168 = 7 days)
- `--detection-hours N`: Hours of detection data (default: 6)

### Train Model (Debug Mode)

```bash
# Using scenario file
poetry run sonar scenario \
  --use-case scenarios/linux_resource_monitoring.yaml \
  --config resource_monitoring_config.yaml \
  --debug

# Or using direct train command
poetry run sonar train \
  --config resource_monitoring_config.yaml \
  --debug
```

### Run Detection (Debug Mode)

```bash
# Using scenario file
poetry run sonar scenario \
  --use-case scenarios/linux_resource_monitoring.yaml \
  --config resource_monitoring_config.yaml \
  --debug

# Or using direct detect command
poetry run sonar detect \
  --config resource_monitoring_config.yaml \
  --debug
```

## Configuration

The resource monitoring scenario uses specific configuration:

### Time Buckets
- **1 minute buckets**: Fine-grained monitoring for detecting short-duration spikes

### Sliding Window
- **300 time points**: Captures 5 hours of context (at 1-min buckets)
- Balances detection of both gradual trends and sudden spikes

### Features
- **CPU usage %**: Primary indicator for compute-intensive attacks
- **Memory usage %**: Detects memory leaks and exhaustion
- **Agent name**: Identifies which servers are affected
- **Rule level**: Alert severity

### Thresholds
- **Anomaly threshold**: 0.75 (balanced for resource anomalies)
- **Consecutive buckets**: 3 (sustained anomaly detection)

## Attack Pattern Details

### 1. Crypto Mining / CPU Spike
**Indicators**:
- Sustained high CPU (>85%)
- Normal memory usage
- May affect multiple hosts (botnet-style)
- Duration: 30-60 minutes

**Detection**: MVAD detects the sudden shift from baseline CPU patterns

### 2. Memory Leak
**Indicators**:
- Gradual linear memory increase
- Eventually reaches 90-95%
- CPU remains relatively normal
- Single host affected
- Duration: 30-90 minutes

**Detection**: MVAD detects the unusual memory growth trend

### 3. Fork Bomb / Resource Exhaustion
**Indicators**:
- Sudden spike in both CPU and memory
- Very high levels (>90%)
- Short duration (system crashes/kills processes)
- Single host affected
- Duration: 5-15 minutes

**Detection**: MVAD detects dramatic deviation from baseline

## Data Format

Each alert follows standard Wazuh format with resource-specific fields:

```json
{
  "timestamp": "2024-12-01T14:23:00.000Z",
  "rule": {
    "id": 8001,
    "level": 3,
    "description": "System resource monitoring check",
    "groups": ["system_monitor", "performance", "syslog"]
  },
  "agent": {
    "id": "001",
    "name": "web-server-01",
    "ip": "192.168.1.10"
  },
  "data": {
    "cpu_usage_%": 42.5,
    "memory_usage_%": 58.3,
    "title": "resource monitoring"
  },
  "decoder": {"name": "sysmon"},
  "location": "/var/log/sysstat"
}
```

## Real-World Deployment

For production use with real Wazuh data:

1. **Configure Wazuh agents** to collect resource metrics:
   ```xml
   <localfile>
     <log_format>syslog</log_format>
     <location>/var/log/sysstat</location>
   </localfile>
   ```

2. **Create custom decoders** to extract CPU/memory fields into `data.cpu_usage_%` and `data.memory_usage_%`

3. **Train on baseline**: Use 7+ days of normal operation data

4. **Tune thresholds**: Adjust based on your environment's normal patterns

5. **Set up alerting**: Configure RADAR or other response systems to act on anomalies

## Scenario File

The scenario configuration is in [`scenarios/linux_resource_monitoring.yaml`](../scenarios/linux_resource_monitoring.yaml).

Key parameters:
- Training window: 168 hours (7 days)
- Detection window: 30 minutes
- Bucket size: 1 minute
- Sliding window: 300 time points
- Anomaly threshold: 0.75
- Alert level: 10

## Troubleshooting

### Model doesn't detect anomalies
- Check that training data covers sufficient normal patterns
- Verify sliding_window size matches training time points
- Lower the threshold (try 0.65)

### Too many false positives
- Increase threshold (try 0.85)
- Increase min_consecutive buckets
- Train on more diverse baseline data

### Feature extraction errors
- Ensure `data.cpu_usage_%` and `data.memory_usage_%` fields exist
- Check field names match your Wazuh configuration
- Verify numeric values are present (not null/missing)

## References

- SONAR Documentation: [`docs/`](../docs/)
- Scenario Specification: [`scenarios/linux_resource_monitoring.yaml`](../scenarios/linux_resource_monitoring.yaml)
- Legacy MTAD-GAT UC6: [`siem_mtad_gat/ad_driver/assets/uc_6.yaml`](../../siem_mtad_gat/ad_driver/assets/uc_6.yaml)
