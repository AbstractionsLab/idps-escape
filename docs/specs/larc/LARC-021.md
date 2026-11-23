---
active: true
derived: false
level: 2.5
links:
- SRS-051: JDdUY4DriBtQaTfMP1I6lcvrhc_qqAUkkjUIGds6Hzw=
- SRS-055: Hm7JBBZfnHwAw8aqU35M6JZid7yQicBJjWCT0oqUEFI=
- SRS-056: cPHoeLEAeLaaZ8tCLEz_E724FHEVIvO-aLO0IBU7EMQ=
- SRS-061: C6p6pgxTJv4q1MmFzYEc1346f8VAZhXnz7ghvPNrlgw=
normative: true
ref: ''
release: Alpha
reviewed: Aed5NbO-dSPra_w0jkOJ8fUuDGOhAdZmKCoyrBI631w=
version: '0.1'
---

# RADAR risk engine calculation flow

This item describes the risk calculation flow of the RADAR active response (`radar/scenarios/active_responses/radar_ar.py`, class `RiskEngine`, with `FusionCorrelator`). The flow combines anomaly, signature and threat-intelligence evidence into one normalised risk score that selects the response tier.

## Mathematical foundation

The risk calculation follows the formula, clamped to [0, 1]:

$$R = w_A \cdot A + w_S \cdot S + w_T \cdot T$$

Where:

- **A** (anomaly intensity) = $G \cdot C$, the anomaly grade and confidence carried by the alert (`data.anomaly_grade`, `data.anomaly_confidence`). Only alerts matched by a scenario's `ad.rule_ids` carry them: today the OpenSearch AD alerts relayed by the RADAR webhook.
- **S** (signature risk) = $L \cdot I$, with $I$ the scenario's `signature_impact` and $L$ the `signature_likelihood` of the alert's rule (a per-rule or per-group list, or one scalar). An alert matched only as an anomaly alert has $S = 0$.
- **T** (CTI score) = `cti_score_T`, the normalised score returned by the DECIPHER analyze endpoint (SWD-038), clamped to [0, 1]. Scenarios without a DECIPHER analyze endpoint always have $T = 0$. RADAR does not aggregate CTI indicators locally.
- **Fusion** (opt-in per scenario, SRS-061 requirement 7): the term an alert cannot carry itself is raised to the strongest time-discounted score of an alert of the other kind for the same entity. It never lowers a term.

The weights are set per scenario in `ar.yaml`; a weight left unset is 0. Shipped values:

| Scenario | $w_A$ | $w_S$ | $w_T$ |
|---|---|---|---|
| `default`, `scanning_detection` | 0.0 | 0.7 | 0.3 |
| `geoip_detection` | 0.0 | 1.0 | 0.0 |
| `suspicious_login` | 0.3 | 0.4 | 0.3 |
| `log_volume`, `linux_resource_utilization` | 0.9 | 0.0 | 0.1 |

## Tier determination

Risk scores map to four response tiers via the scenario's `tier1_min`/`tier1_max`/`tier2_max` boundaries in `ar.yaml` (built-in defaults 0.0/0.33/0.66); see SRS-061 for the normative response semantics of each tier:

- **Tier 0** (R < tier1_min): logged only, no notification
- **Tier 1** (tier1_min ≤ R < tier1_max): email notification + Flowintel case creation
- **Tier 2** (tier1_max ≤ R < tier2_max): Tier 1 actions + `mitigations_tier2` (if `allow_mitigation`)
- **Tier 3** (R ≥ tier2_max): Tier 1 actions + `mitigations_tier3` (if `allow_mitigation`)

## Flow sequence

1. **Input collection**: the alert's AD grade and confidence (anomaly alerts), the rule's likelihood and the scenario's impact (signature alerts), and the CTI score returned by DECIPHER.
2. **Component calculation**: compute A, S, T.
3. **Fusion**: if the scenario enables it, raise A or S with the strongest discounted counterpart alert.
4. **Weighted combination**: apply the scenario's weights and clamp R to [0, 1].
5. **Tier assignment**: map R to Tier 0–3 with the scenario's boundaries.
6. **Action selection**: plan the tier's actions, gated by `allow_mitigation` (LARC-026).

See also: `radar/scenarios/active_responses/ar.yaml` for the per-scenario values, SWD-026 for the normative design and algorithm, and docs/manual/radar_docs/radar-tuning.md for reachable tiers per scenario.

Related: HARC-012.