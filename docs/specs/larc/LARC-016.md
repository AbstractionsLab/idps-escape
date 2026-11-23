---
active: true
derived: false
level: 2.2
links:
- SRS-026: 00UvIiz77brOK0US9z_yIQFIpWSpkLYW5riTRmdC6M4=
- SRS-051: JDdUY4DriBtQaTfMP1I6lcvrhc_qqAUkkjUIGds6Hzw=
- SRS-055: Hm7JBBZfnHwAw8aqU35M6JZid7yQicBJjWCT0oqUEFI=
- SRS-056: cPHoeLEAeLaaZ8tCLEz_E724FHEVIvO-aLO0IBU7EMQ=
- SRS-061: C6p6pgxTJv4q1MmFzYEc1346f8VAZhXnz7ghvPNrlgw=
- SRS-062: umq1jJ6JmmUdM9cRbOX6I9iDoL3ADz0MdwhUZP0blw4=
- SRS-066: tQ00aWRJjAWdGnoqmNQ-24V94vrUQZjD7wLkVPaSnF8=
- SRS-071: ZHNgKjI-5h3aLRPBushyk3-rGXZlaZGed2XtpPWs0Gg=
normative: true
ref: ''
release: Alpha
reviewed: yggx1-YyTCa5_Co6FEkmRIGNryJ-VZogPjzT_zmunKY=
version: '0.4'
---

# RADAR active response flow

Every RADAR scenario ends in the same active response, `radar_ar.py` (`radar/scenarios/active_responses/radar_ar.py`), which the Wazuh manager runs on the manager itself (`<location>server</location>`) for each alert whose rule is bound to it in the scenario's `ossec.conf` snippet (`radar/scenarios/ossec/`).

1. **Alert.** A signature rule fires on a decoded event, or an anomaly trigger rule fires on the log line the webhook wrote for an OpenSearch monitor notification (`/var/log/ad_alerts.log` in the webhook container, forwarded by that container's Wazuh agent).
2. **Scenario and trust.** `radar_ar.py` maps the alert to a scenario in `ar.yaml` by rule ID, then by rule group. An anomaly alert that does not come from the webhook agent's log is dropped without scoring.
3. **Context and CTI.** It collects the scenario's context events from the indexer for a window that ends at the alert's timestamp (`delta_signature_minutes` or `delta_ad_minutes`), extracts IOCs, and, when DECIPHER is reachable, asks DECIPHER's analyze endpoint for a CTI score (SWD-038).
4. **Risk and tier.** It computes the risk score from the anomaly, signature and CTI terms, fused with a counterpart alert where the scenario enables fusion, and maps it to tier 0 to 3 (HARC-012, SRS-061).
5. **Actions.** From tier 1: a Flowintel case through DECIPHER's incident endpoint (when reachable) and an email notification. At tiers 2 and 3, and only when the scenario's `allow_mitigation` is true: the tier's mitigations (`firewall-drop`, `lock_user_linux.sh`, `terminate_service.sh`), sent through the Wazuh API to the affected endpoint's agent (for a per-agent anomaly, the agent the anomaly names), after allowlist and target checks.
6. **Record.** Every step and decision, including withheld mitigations, is written to `/var/ossec/logs/active-responses.log`.

The detailed decision pipeline is specified in LARC-026 and SWD-027.

The diagram below summarises this flow.

```mermaid
%% radar/scenarios/active_responses/radar_ar.py, ar.yaml
flowchart TB
  A["1. Alert: signature rule, or anomaly trigger rule<br/>on a webhook ad_alert line"]
  A --> B["2. radar_ar.py maps the alert to an ar.yaml scenario<br/>(rule ID, then rule group)"]
  B --> TRUST{"Anomaly alert from the<br/>webhook agent's log?"}
  TRUST -->|"no (anomaly alert)"| DROP["Dropped without scoring"]
  TRUST -->|"yes, or signature alert"| C["3. Collect context events from the indexer<br/>(delta_signature_minutes or delta_ad_minutes),<br/>extract IOCs"]
  C --> DQ{"DECIPHER reachable?"}
  DQ -->|yes| CTI["DECIPHER analyze endpoint: CTI score"]
  DQ -->|no| RISK
  CTI --> RISK["4. Risk score from anomaly, signature and CTI terms,<br/>fused where enabled; tier 0 to 3"]
  RISK --> T1{"Tier ≥ 1?"}
  T1 -->|yes| NOTIFY["5. Flowintel case via DECIPHER incident endpoint<br/>(when reachable) and email notification"]
  NOTIFY --> T2{"Tier 2 or 3 and<br/>allow_mitigation true?"}
  T2 -->|yes| CHECK["Allowlist and target checks"]
  CHECK --> MIT["Tier mitigations: firewall-drop, lock_user_linux.sh,<br/>terminate_service.sh, sent via Wazuh API<br/>to the endpoint's agent"]
  T1 -->|no| LOG
  T2 -->|no| LOG
  DROP --> LOG
  MIT --> LOG["6. Record every step and decision<br/>in /var/ossec/logs/active-responses.log"]
```
{width="50%"}

Related: HARC-004, HARC-005.