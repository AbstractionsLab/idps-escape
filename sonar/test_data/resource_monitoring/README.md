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
- **Content**: 2 hours of normal context (2024-12-14T22:00 to 23:59), then 6 hours with injected anomalies (2024-12-15T00:00 to 05:59)
- **Alerts**: 3,998 alerts (includes attack patterns)
- **Why the context**: in debug mode the file is all the data there is. MVAD scores a bucket only after `input_size + threshold_window − 1` earlier buckets (119 one-minute buckets for `sliding_window: 120`), so the 2 normal hours let every bucket of the 6 attack hours be scored.
- **Anomalies Included**:
  1. **CPU Spike (01:00)**: Sustained high CPU (88-98%) for 45 minutes
     - Simulates crypto mining or CPU-intensive malware
     - Affects 2-3 random servers
  2. **Memory Leak (03:00)**: Gradual memory increase over 60 minutes
     - Linear growth from 50% to 95%
     - Single server affected
     - Simulates memory leak or memory-exhaustion attack
  3. **Fork Bomb (05:00)**: Rapid resource exhaustion for 8 minutes
     - Both CPU (92-99%) and memory (88-98%) spike
     - Single server affected
     - Simulates fork bomb or rapid resource abuse

## Usage

### Generate Test Data

```bash
# From the project root
poetry run python sonar/test_data/generate_resource_data.py --output-dir sonar/test_data/resource_monitoring --training-hours 24
```

Options:
- `--training-hours N`: Hours of training data (default: 168 = 7 days; the shipped file holds 24)
- `--detection-hours N`: Hours of detection data after the context, containing the attacks at hours 1, 3 and 5 (default: 6)
- `--context-hours N`: Hours of normal data before the detection hours (default: 2)
- `--detection-only`: Regenerate only the detection file and keep the existing training file

### Train and detect (debug mode)

```bash
# From the project root: train on the training file, then detect on the detection file
poetry run sonar scenario \
  --use-case sonar/scenarios/linux_resource_monitoring.yaml \
  --debug

# Detection only, with the model trained above (the scenario sets model_name)
poetry run sonar detect \
  --scenario sonar/scenarios/linux_resource_monitoring.yaml \
  --debug
```

Debug mode ignores the time range: every bucket of the detection file after its first 119 is scored.

## Configuration

The resource monitoring scenario uses specific configuration:

### Time Buckets
- **1 minute buckets**: Fine-grained monitoring for detecting short-duration spikes

### Sliding Window
- **120 time points**: Captures 2 hours of context (at 1-min buckets)
- Balances detection of both gradual trends and sudden spikes

### Features
- **CPU usage %**: Primary indicator for compute-intensive attacks
- **Memory usage %**: Detects memory leaks and exhaustion
- **Agent name**: Identifies which servers are affected
- **Rule level**: Alert severity

### Thresholds
- **Anomaly threshold**: `null` (MVAD's own decision; a minimum severity between 0 and 1 can be set once calibrated)
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
- Training window: 24 hours
- Detection window: 360 minutes scored (earlier context is fetched automatically)
- Bucket size: 1 minute
- Sliding window: 120 time points
- Anomaly threshold: `null` (MVAD's decision alone)
- Alert level: 10

## Troubleshooting

### Model doesn't detect anomalies
- Check that training data covers sufficient normal patterns
- Verify sliding_window size matches training time points
- Lower the threshold, or set it to `null`

### Too many false positives
- Set a minimum severity as threshold (between 0 and 1), or raise it
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
