---
active: true
derived: false
level: 2.9
links:
- MRS-007: hXM-PkC-g29wtz-Qe3MbM2viHIYzarGh2jFtSD-7N18=
- MRS-019: XwUNC5T2_yICrRsWY8ZyWYFBtvAbrxSEja1ZwL0TB3Q=
normative: true
ref: ''
reviewed: q2Wt6-_Fzp1ajQ-SRyGtHSXzXXxWTPRXz8_nYxd3xN4=
---

# RADAR adversarial ML defense architecture

The diagram below depicts the defense-in-depth architecture for protecting RADAR's anomaly detection systems against adversarial machine learning attacks.

The architecture implements multiple defensive layers:

**Layer 1: Baseline Protection**

- Clean data initialization from verified periods
- Gold-standard training dataset management
- Digital clean room exercises for pristine baselines

**Layer 2: Concept Drift Detection**

- Baseline shift velocity monitoring
- Automated alerts on sudden baseline changes
- Manual approval gates for model updates

**Layer 3: Multi-Layer Validation**

- Signature-based detection (Wazuh, Suricata)
- Multivariate AD (SONAR MVAD, ADBox MTAD-GAT)
- Streaming AD (OpenSearch RRCF)
- Cross-layer anomaly correlation

**Layer 4: Human-in-the-Loop (HITL)**

- Transparent model reasoning exposure
- Analyst review workflows
- Feedback loops for model improvement
- Alert fusion and enrichment

**Layer 5: System Hardening**

- Cryptographic log integrity (SHA-256 hashing)
- Model file access controls and versioning
- Training pipeline authentication
- Audit logging of all model operations

## Defense Architecture Diagram

```plantuml
@startuml

package "Attack Surface" <<Cloud>> {
  component [Data Poisoning\nGradual baseline shift] as poison #ffcccc
  component [Evasion Attacks\nAdversarial examples] as evasion #ffcccc
  component [Backdoor Attacks\nTrigger patterns] as backdoor #ffcccc
  component [Model Stealing\nQuery probing] as model_steal #ffcccc
}

package "Defense Layer 1: Baseline Protection" <<Rectangle>> {
  component [Clean Data Initialization\nVerified training period] as clean_init #d4edff
  component [Gold-Standard Dataset\nKnown-good reference] as gold_standard #d4edff
  component [Digital Clean Room\nIsolated training env] as clean_room #d4edff

  clean_init --> gold_standard
  gold_standard --> clean_room
}

package "Defense Layer 2: Concept Drift Detection" <<Rectangle>> {
  component [Baseline Shift Monitor\nTrack mean/variance changes] as baseline_monitor #d4ffd4
  component [Velocity Threshold\nAlert on sudden shifts] as velocity_check #d4ffd4
  component [Manual Approval Gate\nHuman review required] as approval_gate #d4ffd4

  baseline_monitor --> velocity_check
  velocity_check --> approval_gate : Threshold\nexceeded
}

package "Defense Layer 3: Multi-Layer Validation" <<Rectangle>> {
  package "Signature-Based (Layer 1)" {
    component [Wazuh Rules\nKnown patterns] as wazuh_rules #fff3cd
    component [Suricata IDS\nNetwork signatures] as suricata #fff3cd
  }

  package "Multivariate AD (Layer 2)" {
    component [SONAR MVAD\nMicrosoft MVAD engine] as sonar #fff3cd
    component [ADBox v1\nMTAD-GAT (legacy)] as adbox #fff3cd
  }

  package "Streaming AD (Layer 3)" {
    component [OpenSearch AD\nRRCF algorithm] as opensearch_ad #fff3cd
  }

  component [Alert Fusion Engine\nAggregate detections] as alert_fusion #ffe4cc

  wazuh_rules --> alert_fusion
  suricata --> alert_fusion
  sonar --> alert_fusion
  adbox --> alert_fusion
  opensearch_ad --> alert_fusion
}

package "Defense Layer 4: Human-in-the-Loop" <<Rectangle>> {
  package "Transparency Mechanisms" {
    component [Feature Importance\nExplain decisions] as feature_importance #e8daff
    component [SHAP Values\nModel explainability] as shap #e8daff
    component [Attention Visualization\nMTAD-GAT focus] as attention_viz #e8daff
  }

  package "Analyst Workflows" {
    component [Anomaly Review Queue\nPrioritized alerts] as review_queue #e8daff
    component [Feedback Loop\nAnalyst labels] as feedback #e8daff
    component [Model Update Pipeline\nIncorporate feedback] as model_update #e8daff
  }

  feature_importance --> review_queue
  shap --> review_queue
  attention_viz --> review_queue
  review_queue --> feedback
  feedback --> model_update
}

package "Defense Layer 5: System Hardening" <<Rectangle>> {
  package "Data Integrity" {
    component [Cryptographic Log Integrity\nSHA-256 hashing] as log_hash #ffd4d4
    component [Chain of Custody\nAudit trail] as chain_verify #ffd4d4
  }

  package "Model Security" {
    component [Model File ACLs\nRead-only access] as model_acl #ffd4d4
    component [Model Versioning\nGit-tracked artifacts] as model_version #ffd4d4
    component [Training Pipeline Auth\nAPI keys, RBAC] as train_auth #ffd4d4
  }

  package "Audit & Monitoring" {
    component [Model Operations Log\nAll changes tracked] as model_ops_log #ffd4d4
    component [Drift Alert System\nAnomaly in anomalies] as drift_alert #ffd4d4
  }

  log_hash --> chain_verify
  model_acl --> model_version
  model_version --> train_auth
  train_auth --> model_ops_log
  model_ops_log --> drift_alert
}

poison ..> clean_init : Attempts
poison ..> baseline_monitor : Blocked by
evasion ..> wazuh_rules : Attempts
evasion ..> alert_fusion : Detected by
backdoor ..> gold_standard : Attempts
backdoor ..> review_queue : Flagged by
model_steal ..> train_auth : Attempts
model_steal ..> model_ops_log : Logged by

alert_fusion --> review_queue
approval_gate --> model_update
model_update --> model_version
drift_alert --> velocity_check

@enduml
```