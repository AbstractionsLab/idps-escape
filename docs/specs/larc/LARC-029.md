---
active: true
derived: false
level: 2.13
links:
- HARC-004: B-4i2SClF5iGbeV-cWw9l0nDiMns0PHC2fNuaqSQAmo=
- LARC-022: tH9LfjIxzDfssQPvlDYNSMqEW06cLQf9ts3l08QvrXI=
- LARC-023: 1al71zOScUDcuFYGnl139cdZd_uzPCZ1O4tqOuASCNA=
- LARC-026: Ga9LLhP4KMUK4ofaZY7Eh15_ZEQ_FIbOsCd8rgrwEyA=
- SRS-054: GaZPljJjNzyrhDvEPGnqeAwYrN9hb9axsmolD_rCzeE=
- SRS-056: xKvRTfbWPnFhLmrKkVnKcrA1gfDRFhhKwc6tXbXmnJw=
normative: true
ref: ''
release: Alpha
reviewed: Y7NkIAtxANb_8TT4fYF93Es3Bj0RSVDO95voZCO2IEc=
version: '0.1'
---

# RADAR log volume detection scenario flow

The diagram below depicts the end-to-end flow for the log volume detection scenario, which uses **behavior-based anomaly detection** (OpenSearch RCF) to identify abnormal increases in log generation that may indicate attacks, system issues, or data exfiltration.

## Scenario overview

Log volume detection is a **behavior-based** scenario using OpenSearch Anomaly Detection:

- Monitors log file size growth on endpoints
- Uses RRCF (Robust Random Cut Forest) algorithm for anomaly detection
- Per-endpoint baselines via high-cardinality detection
- Webhook integration routes anomalies to Wazuh rule engine
- Active response executes tiered actions based on risk score

## Flow stages

### 1. Log collection on agent
- Wazuh agent runs localfile command every 20 seconds:
  ```xml
  <localfile>
    <log_format>command</log_format>
    <command>du -sb /var/log | awk '{print $1}'</command>
    <alias>log_volume_metric</alias>
    <frequency>20</frequency>
  </localfile>
  ```
- Command output: log size in bytes for `/var/log`

### 2. Log forwarding
- Agent forwards log to Wazuh Manager
- Manager applies decoder: `local_decoder.xml` extracts `data.log_bytes` field
- Log indexed to OpenSearch: `wazuh-ad-log-volume-*` index

### 3. Historical data ingestion (initial setup, see LARC-027)
- `run-radar.sh` executes `wazuh_ingest.py`
- Generates 240 minutes of baseline data (720 points)
- Realistic time series with monotonic growth
- Bulk indexed to OpenSearch

### 4. Detector creation (see LARC-022)
- `run-radar.sh` executes `detector.py`
- Creates OpenSearch AD detector with:

    - Feature: `max(data.log_bytes)`
    - Category field: `agent.name` (per-endpoint baselines)
    - Shingle size: 8 (temporal sequence)
    - Detection interval: 5 minutes
    - Window delay: 1 minute
- Starts detector

### 5. Real-time anomaly detection
**OpenSearch RCF detector runs every 5 minutes:**

- Query index for recent data points per agent
- Extract feature values: max log bytes in interval
- Apply RCF model to detect outliers
- Compute anomaly grade (0-1) and confidence (0-1)
- Write results to `opensearch-ad-plugin-result-log-volume` index

### 6. Monitor evaluation (see LARC-023)
**OpenSearch monitor runs every 5 minutes:**

- Query detector result index
- Evaluate trigger condition:
  ```
  anomaly_grade > 0.3 AND confidence > 0.3
  ```
- If condition met, trigger webhook action

### 7. Webhook notification
- Monitor POSTs JSON payload to webhook endpoint: `http://manager:8080/notify`
- Payload includes: monitor name, trigger name, entity (agent name), period start/end times

### 8. Webhook service processing
- Flask service (`ad_alerts_webhook.py`) receives POST request
- Extracts alert details from payload
- Formats as syslog message
- Writes to `/var/log/ad_alerts.log`:
  ```
  Feb 16 10:30:15 wazuh-manager opensearch_ad: LogVolume-Growth-Detected entity=edge.vm grade=0.85 confidence=0.92
  ```

### 9. Wazuh rule matching
**Rule 100300**: Generic OpenSearch AD alert

- Decoder: `opensearch_ad` extracts fields
- Rule level: 5
- Matches any AD alert

**Rule 100309**: Log Volume Growth specific

- Parent: Rule 100300
- Condition: `trigger.name = "LogVolume-Growth-Detected"`
- Level: 12
- Groups: `log_volume`, `anomaly`

### 10. Active response trigger
- Rule 100309 match triggers `radar-ar` active response
- Alert JSON passed to `radar_ar.py` via stdin

### 11. Active response processing (see LARC-026)
- Scenario identification: Maps rule ID 100309 → `log_volume` scenario
- Time window: Last 10 minutes (delta_ad_minutes)
- Context collection: Query correlated events from all agents (high-cardinality)
- Extract AD scores: anomaly_grade, confidence from alert data
- CTI enrichment: Check for malicious activity indicators
- Risk calculation: Primarily AD-based (w_ad = 0.6, w_sig = 0.2, w_cti = 0.2)
  ```
  A = grade × confidence = 0.85 × 0.92 = 0.782
  S = likelihood × impact = 0.5 × 0.6 = 0.3
  T = CTI aggregation (varies)
  R = 0.6 * 0.782 + 0.2 * 0.3 + 0.2 * T
  ```
- Tier determination: Based on R value
- Action execution:
    - **Low tier (R < 0.3)**: Email only
    - **Medium tier (0.3 ≤ R < 0.7)**: Email + Flowintel case
    - **High tier (R ≥ 0.7)**: Email + case + investigation escalation

### 12. Audit logging
- Decision recorded with full context: scenario, risk score, tier, actions, anomaly details

## Configuration

**config.yaml**:
```yaml
log_volume:
  index_prefix: "wazuh-ad-log-volume-*"
  result_index: "opensearch-ad-plugin-result-log-volume"
  time_field: "@timestamp"
  categorical_field: "agent.name"
  detector_interval: 5
  delay_minutes: 1
  shingle_size: 8
  anomaly_grade_threshold: 0.3
  confidence_threshold: 0.3
  features:
    - feature_name: "log_volume_max"
      feature_enabled: true
      aggregation_query:
        log_volume_max:
          max:
            field: "data.log_bytes"
```

**ar.yaml**:
```yaml
log_volume:
  rules:
    ad: ["100309"]
  detection_params:
    delta_ad_minutes: 10
  risk_params:
    likelihood: 0.5
    impact: 0.6
    weights: {w_ad: 0.6, w_sig: 0.2, w_cti: 0.2}
  tier_thresholds: {low: 0.3, high: 0.7}
  actions:
    email_enabled: true
    case_creation_enabled: true
    mitigation_enabled: false
```

## Key characteristics

- **Adaptive**: Learns normal patterns per endpoint
- **High-cardinality**: Separate baselines per agent prevent statistical masking
- **Streaming**: Real-time detection without batch retraining
- **Configurable sensitivity**: Threshold tuning balances false positives vs. detection rate
- **Multi-stage pipeline**: Decouples detection (OpenSearch) from response (Wazuh)

## Implementation reference

See implementation details:

- [docs/manual/radar_docs/radar-scenarios/log_volume_explained.md](../../manual/radar_docs/radar-scenarios/log_volume_explained.md) - Detailed documentation
- [radar/scenarios/decoders/log_volume/](../../../radar/scenarios/decoders/log_volume/) - Decoder implementations
- [radar/scenarios/rules/log_volume/](../../../radar/scenarios/rules/log_volume/) - Rule definitions
- [radar/scenarios/ingest_scripts/log_volume/](../../../radar/scenarios/ingest_scripts/log_volume/) - Data ingestion