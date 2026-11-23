---
active: true
derived: false
level: 2.6
links:
- MRS-007: T_irYXTjWbTLRStypNV_lJ0NrCpz_1UXPGaQK7pMs2k=
- MRS-024: F5zql4yq0eMIzrjrbif-XN_lAXfJIRoxxIyeNzDcK9k=
normative: true
ref: ''
reviewed: 5PK_8WgWRjNRs3O4ARBok51yJQODZLA4pXaZUPhjudk=
---

# RADAR risk engine architecture

The RADAR risk engine is part of the active response `radar_ar.py` (`radar/scenarios/active_responses/radar_ar.py`), which the Wazuh manager runs for every alert bound to a RADAR scenario. It combines anomaly detection outputs, signature-based detection data and a CTI score into one risk score, maps the score to a tier, and drives the tier's actions.

The risk engine has three inputs:

- **Anomaly intensity (A)**: $A = G \times C$, from the alert's `data.anomaly_grade` and `data.anomaly_confidence`. These come from an OpenSearch RCF detector through the monitor and webhook, or are fixed values for the off-hours rule mode of `suspicious_login`. Only alerts whose rule is listed under the scenario's `ad.rule_ids` carry A, and only if they come from the webhook agent's log.
- **Signature risk (S)**: $S = L \times I$, where the likelihood $L$ is looked up in the scenario's `signature_likelihood` table (by rule ID or rule group) and the impact $I$ is the scenario's `signature_impact`. An anomaly-only alert has $S = 0$.
- **CTI score (T)**: the `severity` returned by DECIPHER's analyze endpoint for the scenario (SWD-038), clamped to [0, 1]. It is 0 when DECIPHER is not configured or unreachable, or when no analyze endpoint exists for the scenario.

For a scenario with a `fusion` block, the term an alert cannot carry itself is filled with the strongest alert of the other kind for the same entity within the fusion window, discounted linearly by the time gap; fusion can only raise A or S.

The weighted combination $R = w_{ad} A + w_{sig} S + w_{cti} T$, clamped to [0, 1], drives tier-based response actions. Weights are set per scenario in `ar.yaml`. Four tiers are delimited by the three configurable boundaries `tier1_min`, `tier1_max` and `tier2_max`; the normative tier semantics are specified in SRS-061.

- **Tier 0** (`R < tier1_min`, default boundary 0.0): the decision is logged; no notification, case or mitigation
- **Tier 1** (`tier1_min ≤ R < tier1_max`, default boundary 0.33): email notification and, when DECIPHER is reachable, Flowintel case creation
- **Tier 2** (`tier1_max ≤ R < tier2_max`, default boundary 0.66): tier 1 actions plus the scenario's `mitigations_tier2`, subject to `allow_mitigation`
- **Tier 3** (`R ≥ tier2_max`): tier 1 actions plus the scenario's `mitigations_tier3`, subject to `allow_mitigation`; in the shipped `ar.yaml` this list repeats the tier 2 mitigations and adds the stronger containment actions

Every decision, including withheld mitigations and the reason they were withheld, is written to the manager's `active-responses.log`.

## Architecture diagram

```plantuml
@startuml
!define DETECTION #d4edff
!define RISKENGINE #ffd4d4
!define RESPONSE #d4ffd4
!define EXTERNAL #ffe4cc

package "Alert sources (Wazuh manager)" {
  component [Signature rules\nRADAR and stock Wazuh rules] as WR
  component [AD trigger rules\nwebhook log lines from\nOpenSearch AD monitors] as ADR
}

database "ar.yaml\nweights, likelihoods, tiers,\nfusion, mitigations" as CF

package "radar_ar.py" {
  component [ScenarioIdentifier\nrule ID, then rule group] as SI DETECTION
  component [AdAlertOrigin\nwebhook agent and log only] as AO DETECTION
  component [Scenario strategy\ncontext events and IOCs] as ST DETECTION
  component [DecipherClient\nanalyze / create_incident] as DC DETECTION
  component [FusionCorrelator\ncounterpart alert lookup] as FC DETECTION
  component [RiskEngine\nR = w_ad·A + w_sig·S + w_cti·T\ntier 0-3] as RE RISKENGINE
  component [ActionPlanner\nallow_mitigation gate] as AP RESPONSE
  component [ActionExecutor\nallowlists, target checks] as AE RESPONSE
  component [EmailNotifier] as EN RESPONSE
}

package "Wazuh indexer" {
  database "wazuh-alerts-*\nwazuh-archives-*" as IDX
}

package "External integrations" {
  component [DECIPHER\nCTI analysis] as DEC EXTERNAL
  component [Flowintel\ncase management] as FL EXTERNAL
  component [SMTP server] as SMTP EXTERNAL
}

component [Wazuh API\nPUT /active-response] as WAPI RESPONSE
component [Wazuh agent\nfirewall-drop, lock_user_linux.sh,\nterminate_service.sh] as AG RESPONSE

WR -down-> SI : alert
ADR -down-> SI : alert
CF ..> SI
SI -down-> AO : ad / hybrid
SI -down-> ST
ST -down-> IDX : context window
ST -down-> DC : analyze payload
DC -right-> DEC : POST analyze
DEC ..> DC : severity = T
AO -down-> RE : A = G × C
ST -down-> RE : S = L × I
DC -down-> RE : T
FC -down-> IDX : other kind of alert\nfor the same entity
FC -down-> RE : fused A or S
CF ..> RE : weights, tiers
RE -down-> AP : risk, tier
CF ..> AP : mitigations
RE -down-> DC : tier ≥ 1
DC ..> DEC : POST incident
DEC ..> FL : case
AP -down-> AE
AE -down-> WAPI : tier 2/3 mitigations
WAPI -down-> AG
AP -down-> EN : tier ≥ 1
EN -right-> SMTP

note right of RE
  **Example** (suspicious_login:
  w_ad 0.3, w_sig 0.4, w_cti 0.3,
  tier1_min 0.15, tier1_max 0.33, tier2_max 0.55)

  Signature alert 210013: L = 0.6, I = 0.7
  S = 0.42, sig component = 0.168
  DECIPHER severity T = 0.5, cti component = 0.15
  R = 0.318  -> tier 1

  Same alert fused with an off-hours alert
  (A = 0.9 after decay): ad component = 0.27
  R = 0.588  -> tier 3
end note

@enduml
```