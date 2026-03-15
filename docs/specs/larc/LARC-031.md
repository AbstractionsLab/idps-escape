---
active: true
derived: false
level: 2.15
links:
- HARC-015: PQXdsGT7q_k4sii3GFMsEo3ZImBTWmQCQFfDbMmKB9E=
- LARC-022: tH9LfjIxzDfssQPvlDYNSMqEW06cLQf9ts3l08QvrXI=
normative: true
ref: ''
release: Alpha
reviewed: 6QJfJ3XSuhmzfyw6vYk3vDoSbX763o43b1dtApkmaUU=
version: '0.1'
---

# RADAR adversarial defense implementation flow

The diagram below depicts the implementation flow for adversarial ML defense mechanisms in RADAR, protecting anomaly detection systems against data poisoning, evasion attacks, and model tampering.

## Defense layers

### Layer 1: Baseline initialization with clean data

**Implementation**:

- **Clean period identification**: Analyze historical data for known-clean periods (pre-incident, honeypot-free)
- **Gold-standard datasets**: Use verified attack-free data for initial training
- **Digital clean room**: Temporary system lockdown to capture pristine baselines
- **Exclusion filtering**: Remove time segments with suspected attacker presence

**Configuration**:
```yaml
baseline_init:
  use_gold_standard: true
  clean_period_start: "2026-01-01T00:00:00Z"
  clean_period_end: "2026-01-15T00:00:00Z"
  excluded_hosts: ["suspected-compromised-01"]
```

### Layer 2: Concept drift detection

**Implementation**:

- **Baseline shift monitoring**: Track mean, variance, and distribution shape changes
- **Velocity thresholds**: Alert when baseline shift rate exceeds historical norms
- **Correlation analysis**: Flag simultaneous shifts across multiple features
- **Automated gating**: Freeze model updates when anomalous drift detected

**Algorithm**:
```
Algorithm: Detect abnormal baseline shifts
  Input: current_stats, historical_stats, threshold (default: 0.2)

  // Calculate relative changes
  mean_shift ← |current_stats.mean - historical_stats.mean| / historical_stats.mean
  std_shift ← |current_stats.std - historical_stats.std| / historical_stats.std

  // Check correlation across features
  correlated_shifts ← count_features_with_simultaneous_shifts(current_stats, historical_stats)

  // Determine if drift is anomalous
  drift_detected ← (mean_shift > threshold) OR
                     (std_shift > threshold) OR
                     (correlated_shifts ≥ 3)

  drift_metrics ← {
    mean_shift: mean_shift,
    std_shift: std_shift,
    correlated_features: correlated_shifts
  }

  Output: drift_detected (boolean), drift_metrics (dictionary)
```

**Configuration**:
```yaml
drift_detection:
  enabled: true
  check_interval_hours: 24
  threshold_percent: 20
  correlation_threshold: 3
  freeze_on_drift: true
  require_analyst_approval: true
```

### Layer 3: Multi-layer validation (defense in depth)

**Implementation**: RADAR already implements this via hybrid detection:

- **Signature-based** (Wazuh, Suricata): Fast, deterministic, resistant to ML poisoning
- **Multivariate AD** (SONAR MVAD): Complex patterns, correlation-aware
- **Streaming AD** (OpenSearch RRCF): Real-time, distinct algorithm
- **Cross-layer correlation**: Flag events detected by multiple layers as high confidence

**Validation algorithm**:
```
Algorithm: Validate alert across detection layers
  Input: alert

  layers_triggered ← empty_list

  if signature_detection_fired(alert):
    append 'signature' to layers_triggered

  if mvad_detection_fired(alert):
    append 'mvad' to layers_triggered

  if rrcf_detection_fired(alert):
    append 'rrcf' to layers_triggered

  // Multi-layer agreement increases confidence
  confidence_boost ← count(layers_triggered) × 0.15
  high_confidence ← count(layers_triggered) ≥ 2

  Output: {
    layers: layers_triggered,
    confidence_boost: confidence_boost,
    high_confidence: high_confidence
  }
```

### Layer 4: Human-in-the-loop (HITL) oversight

**Implementation**:

- **Transparent reasoning**: Expose model decisions (which points anomalous, why)
- **Analyst review workflows**: Dashboard for reviewing flagged baseline changes
- **Feedback loops**: Analysts flag incorrect classifications
- **Approval gates**: Model updates require manual approval when drift detected

**Workflow**:

1. System detects concept drift or baseline shift
2. Generate alert to SOC dashboard
3. Analyst reviews:
   - Shift magnitude and velocity
   - Affecting features and entities
   - Timeline correlation with known events
4. Analyst decision:
   - **Approve**: Legitimate change (new application, infrastructure update)
   - **Reject**: Suspected poisoning, freeze baseline
   - **Investigate**: Escalate to incident response

### Layer 5: System hardening

**Implementation**:

**Log integrity**:
```
Process: Cryptographic hashing of log files
  1. Generate SHA-256 hash of log file
     Command: sha256sum /var/log/wazuh/alerts.json > /var/log/wazuh/alerts.json.sha256

  2. Enable append-only logging (immutable storage)
     Command: chattr +a /var/log/wazuh/alerts.json

  3. Forward-secure audit logs
     Mechanism: Time-stamped cryptographic signatures preventing retroactive tampering
```

**Model security**:
```
Process: Secure model file storage and versioning
  1. Set restrictive permissions
     Permissions: read-only for radar-ml group (mode 440)
     Owner: root:radar-ml

  2. Model versioning and integrity
     Version control: Git repository for model files
     Integrity: SHA-256 checksums for all model files

  3. Audit logging
     Log all model updates with: timestamp, user, model version
```

**Access control specification**:
See RBAC configuration in YAML section below for role definitions and approval requirements.

## Integration with RADAR workflows

### Detector creation (LARC-022)
- Before training: Validate data cleanliness
- Contamination parameter: Configure RCF contamination tolerance
- Baseline documentation: Record training period and data sources

### Monitor evaluation (LARC-023)
- Drift detection: Monitor checks for baseline shift before evaluating anomalies
- Multi-layer correlation: Cross-reference with signature-based rules
- Confidence adjustment: Boost detection confidence when multiple layers agree

### Active response (LARC-026)
- Risk calculation: Include drift detection status in context
- Action planning: Require higher confidence when drift suspected
- Audit logging: Record all defense layer activations

## Configuration (adversarial_defense.yaml)

```yaml
adversarial_defense:
  baseline_initialization:
    use_verified_clean_data: true
    gold_standard_dataset: "/opt/radar/baseline/gold_standard.json"
    clean_period:
      start: "2026-01-01T00:00:00Z"
      end: "2026-01-15T00:00:00Z"

  drift_detection:
    enabled: true
    check_interval_hours: 24
    mean_shift_threshold: 0.20
    std_shift_threshold: 0.25
    correlation_threshold: 3
    freeze_on_drift: true

  multi_layer_validation:
    enabled: true
    require_layers: 2  # Minimum layers for high confidence
    confidence_boost_per_layer: 0.15

  hitl_oversight:
    enabled: true
    require_approval_for:
      - model_retraining
      - baseline_reset
      - significant_drift
    dashboard_url: "https://radar.example.com/oversight"

  system_hardening:
    log_integrity:
      enable_hashing: true
      hash_algorithm: "sha256"
      append_only_logs: true
    model_security:
      enable_versioning: true
      enable_checksums: true
      restrict_access: true
    access_control:
      enable_rbac: true
      roles:
        radar_viewer:
          permissions: [view_alerts, view_detectors]
        radar_operator:
          permissions: [view_alerts, view_detectors, create_detectors, create_monitors]
        radar_admin:
          permissions: ["*", model_training, model_deployment]
      approval_required:
        - model_training       # Requires radar_admin role
        - baseline_reset       # Requires radar_admin role + security_approval
        - model_deployment     # Requires radar_admin role + change_control
      audit_all_operations: true
```

## Monitoring and alerting

**Drift detection alerts**:

- Email to SOC when drift exceeds threshold
- Dashboard visualization of baseline trends
- Automated freeze of model updates

- **Access control alerts**:

  - Failed authentication attempts to model files
  - Unauthorized model update attempts
  - Suspicious baseline reset requests

## Adversarial Defense Implementation Flow

```plantuml
@startuml
!define BASELINE #d4edff
!define DRIFT #d4ffd4
!define VALIDATION #fff3cd
!define HITL #e8daff
!define HARDENING #ffd4d4

start

:Continuous ML Operation;

:Monitoring Phase;

partition "Layer 1: Baseline Protection" #BASELINE {
  if (Gold-standard dataset exists?) then (no)
    :Initialize clean baseline;
    :Identify clean period:\nPre-incident, verified attack-free;
    :Manual audit of period\nReview logs, incidents;
    :Extract data from clean period;
    :Store as gold-standard dataset;
    :Train initial model on gold data;
  else (yes)
    :Use gold-standard dataset;
    :Train initial model on gold data;
  endif

  :Baseline established;
}

partition "Layer 2: Concept Drift Detection" #DRIFT {
  :Collect runtime data;
  :Compute statistics:\nmean, std, distribution;
  :Compare to baseline stats;

  :Calculate mean shift:\nΔμ = |μ_current - μ_baseline| / μ_baseline;
  :Calculate std shift:\nΔσ = |σ_current - σ_baseline| / σ_baseline;
  :Check correlated feature shifts;

  if (Drift detected?\nΔμ > 20% OR\nΔσ > 20% OR\ncorrelated >= 3) then (yes)
    :Generate drift alert;
    :Freeze model updates;
    :Notify analyst via dashboard;
    :Manual approval gate;

    if (Analyst decision) then (approve)
      :Update baseline\nLegitimate change;
    else if (reject)
      :Maintain baseline\nSuspected poisoning;
    else (investigate)
      :Escalate to IR team;
      stop
    endif
  else (no)
    :Continue normal operations;
  endif
}

partition "Layer 3: Multi-Layer Validation" #VALIDATION {
  :Collect alerts from all layers;

  fork
    :Signature-Based Detection:\nWazuh rules, Suricata IDS;
  fork again
    :Multivariate AD:\nSONAR MVAD, ADBox MTAD-GAT;
  fork again
    :Streaming AD:\nOpenSearch RRCF;
  end fork

  :Alert Fusion Engine;
  :Count layers triggered;

  if (Agreement level?) then (1 layer)
    :Low confidence alert;
  else if (2 layers)
    :Medium confidence alert\nBoost confidence +0.15;
  else (3 layers)
    :High confidence alert\nBoost confidence +0.30;
  endif
}

partition "Layer 4: Human-in-the-Loop Oversight" #HITL {
  :HITL Review Workflow;

  :Expose model reasoning;
  fork
    :Feature importance:\nTop contributing features;
  fork again
    :SHAP values:\nGame-theoretic attribution;
  fork again
    :Attention visualization:\nMTAD-GAT graph focus;
  end fork

  :Anomaly review queue;
  :Prioritize by risk score;

  if (Analyst assessment) then (True Positive)
    :Label: True attack;
  else if (False Positive)
    :Label: Benign;
  else if (Novel Attack)
    :Label: New attack type;
  else (Evasion Attempt)
    :Label: Evasion detected;
  endif

  :Feedback loop;

  if (Model update needed?) then (yes)
    :Retrain with labeled data;
  else (no)
    :Create new detection rule;
  endif
}

partition "Layer 5: System Hardening" #HARDENING {
  :Model/Rule Update Request;

  :Log integrity verification;
  :Verify SHA-256 hashes;
  :Chain of custody check;

  :Validate access permissions;
  :Check model file ACLs;
  :Verify training pipeline auth;

  if (All security checks pass?) then (yes)
    :Apply update;
    :Version in Git;
    :Log operation;
    :Update operational metrics;
  else (no)
    #ERROR:Security check failed;
    :Block update;
    :Alert security team;
    stop
  endif
}

:Continue monitoring;

note right
  **Multi-layer agreement metrics**:
  - Track % of alerts confirmed by multiple layers
  - Low agreement rate may indicate evasion attempts

  **Access control alerts**:
  - Failed authentication attempts to model files
  - Unauthorized model update attempts
  - Suspicious baseline reset requests
end note

stop

@enduml
```

## Implementation reference

See [docs/manual/radar_docs/adversarial-ml-guidance.md](../../manual/radar_docs/adversarial-ml-guidance.md) for comprehensive defense guidance.

## See also
- HARC-015 for overall adversarial defense architecture