---
active: true
derived: false
level: 2.6
links:
- MRS-007: hXM-PkC-g29wtz-Qe3MbM2viHIYzarGh2jFtSD-7N18=
normative: true
ref: ''
reviewed: 88TKuV1od4B9HzKWUeRqD-A6YEEuNNw8oa2kdI5rT7Y=
---

# RADAR risk engine architecture

The diagram below depicts the high-level architecture of the RADAR risk engine component, which calculates risk scores by combining anomaly detection outputs, signature-based detection data, and CTI (Cyber Threat Intelligence) indicators.

The risk engine receives three input streams:

- **Anomaly intensity (A)**: Computed from OpenSearch RCF detector outputs (anomaly grade × confidence) or SONAR MVAD results
- **Signature risk (S)**: Calculated from rule-based detection (likelihood × impact values from scenario configuration)
- **CTI score (T)**: Aggregated from threat intelligence indicators (IP blacklists, malicious hashes, domain reputation)

The weighted combination produces a normalized risk score $R \in [0,1]$, which drives tier-based response actions:

- Low tier (0.0-0.33): Email notification only
- Medium tier (0.33-0.66): Email + case creation + light mitigation
- High tier (0.66-1.0): Full response + strong containment actions

## Architecture Diagram

```plantuml
@startuml
!define DETECTION #d4edff
!define RISKENGINE #ffd4d4
!define RESPONSE #d4ffd4
!define EXTERNAL #ffe4cc

package "Detection Sources" {
  component [Wazuh Rules\nSignature-based\nSeverity: 0-15] as WR
  component [OpenSearch AD\nRCF Detector\nAnomaly: 0-1.0] as OS
  component [Threat Intelligence\nEnrichment\nScore: 0-100] as TI
}

package "Risk Engine Core" {
  component [Risk Input Handler\nExtract & Validate] as RI DETECTION
  component [Normalization Module\nScale to 0-1] as NM DETECTION
  component [Risk Calculator\nR = w_A·A + w_S·S + w_T·T] as RC RISKENGINE
  component [Tier Classifier\nLOW/MEDIUM/HIGH] as TC RISKENGINE
  component [Risk Logger\nOpenSearch .radar-risk] as RL DETECTION
}

database "config.yaml\nWeights & Thresholds" as CF

package "Active Response" {
  component [Active Response Script\nradar_ar.py] as AR RESPONSE
  component [Scenario Identifier] as SI RESPONSE
  component [Action Executor] as AC RESPONSE
}

package "External Integrations" {
  component [Flowintel\nCase Management] as FL EXTERNAL
  component [SONAR\nMVAD Anomalies] as SO EXTERNAL
}

WR -down-> RI : Rule Level
OS -down-> RI : Anomaly Grade
TI -down-> RI : Threat Score

RI -down-> NM
NM -down-> RC
CF ..> RC : Weights
RC -down-> TC
CF ..> TC : Thresholds
TC -down-> RL

TC -right-> AR : RiskScore
AR -down-> SI
SI -down-> AC

TC ..> FL : HIGH Risk
SO ..> RI : Anomaly Context

note right of RC
  **Risk Calculation Example**
  Input:
  - Anomaly grade: 0.85
  - Rule level: 8
  - Threat score: 60

  Normalization:
  - A = 0.85
  - S = 8/15 = 0.533
  - T = 60/100 = 0.6

  Calculation:
  R = 0.4 × 0.85 + 0.35 × 0.533 + 0.25 × 0.6
  R = 0.34 + 0.187 + 0.15 = 0.677

  Tier: HIGH (R ≥ 0.66)
end note

@enduml
```