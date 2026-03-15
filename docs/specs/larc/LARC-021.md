---
active: true
derived: false
level: 2.5
links:
- HARC-012: o2Y9AfLKV6ykBEdZL8dBJOq8rhub_75vzXmnybYz1cw=
- SRS-050: f1fx4EzuMUZpkPuPmI8RJXj5-ASOsNLfOUx5pm81PWc=
- SRS-051: L_FEEgh5sx0eJ_B6mZtm3kp_90KxFJLwar48ZeSHzbk=
- SRS-052: rnH2AeVu4U2ZbCOXkatJeqKiv_ziq90iRQZJjU1fHKc=
- SRS-053: aIVPh1BEuDyoOpv2yR1RAxt5nMznURf8bTNnM1Zwe2k=
- SRS-054: uHphWVv4JHHTXBdflib0T4RzyaE1uE6O42VzOVJgulg=
- SRS-055: ysWB5SJEBNrXmKQYG-xHmAiWmgdyjAcTkOqrg1qRW4g=
- SRS-056: xKvRTfbWPnFhLmrKkVnKcrA1gfDRFhhKwc6tXbXmnJw=
- SRS-057: JivcDcF2rEyW0tBRCHpcSHr0mkLA2rOlZVAj4Cn853A=
- SRS-058: dNct9JYsSzidxOBMDTP9zCYJcVYSSUn3odqzwW1I204=
normative: true
ref: ''
release: Alpha
reviewed: OlXcjjdwxlVBu6NCaAMwdxLLXGuZkKdeupHqGVUcjvs=
version: '0.1'
---

# RADAR risk engine calculation flow

The diagram below depicts the risk calculation flow implemented in the RADAR active response system. This flow combines three detection paradigms into a unified, normalized risk score that drives automated response actions.

## Mathematical foundation

The risk calculation follows the formula:

$$R = w_A \cdot A + w_S \cdot S + w_T \cdot T$$

Where:

- **A** (Anomaly intensity) = $G \cdot C$, where G is anomaly grade and C is confidence from OpenSearch RCF or SONAR MVAD
- **S** (Signature risk) = $L \cdot I$, where L is likelihood and I is impact from rule-based detection
- **T** (CTI score) = $1 − \prod_i^n(1 − \omega_i)$, aggregated over CTI indicator weights

Default weights (configurable in ar.yaml):

- $\omega_a = 0.4$ (behavioral → high information value)
- $\omega_s = 0.4$ (signature → high precision)
- $\omega_T = 0.2$ (CTI → confirmatory)

## Tier determination

Risk scores map to response tiers:

- **Low** (0.0 ≤ R < 0.33): Email notification only
- **Medium** (0.33 ≤ R < 0.66): Email + case creation + light mitigation
- **High** (0.66 ≤ R ≤ 1.0): Full notification + case + strong containment

## Flow sequence

1. **Input collection**: Extract AD outputs (G, C), signature values (L, I), CTI flags
2. **Component calculation**: Compute A, S, T from inputs
3. **Weighted combination**: Apply weights to compute R
4. **Tier assignment**: Map R to Low/Medium/High based on thresholds
5. **Action selection**: Determine response actions based on tier and scenario configuration

See also: `/radar/scenarios/active_responses/ar.yaml` for configuration schema and `/docs/manual/radar_docs/radar-risk-math.md` for detailed mathematical specification.