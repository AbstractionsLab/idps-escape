---
active: true
derived: false
level: 2.1
links:
- SRS-054: eN2_O6eCMqDbMTrHaMjDKt-t7Arv-tjqT4d6btdcy2c=
- SRS-067: K7Av1b3_rMMG3_W7gTKr1I_mXwuuo2-MagLLcUEQZzs=
- SRS-069: vMOJ_kIdjLXiTyqpLIiR4EZzv1RRm7P0-z-h4JQwxDQ=
normative: true
ref: ''
release: Alpha
reviewed: 2HORmTNDQ5nIe8eltMJclMbWeauBqbNonp4AkeV6yzM=
version: '0.4'
---

# RADAR scenario setup flow

Setting up a RADAR scenario takes the following steps, in this order. Each one can be run from the command line or from the GUI's Deployment page.

1. **Deploy the scenario on the manager** (`build-radar.sh <scenario>`, GUI Scenario Management). Bring up the core stack if no manager is running, build and enroll the webhook, harden enrollment, then place the manager-side files (risk engine `radar_ar.py`, `ar.yaml`, enrichment integrations, Filebeat pipeline changes) and deploy, through the Wazuh API, the scenario's agent-group configuration, decoders, rules, CDB lists and `ossec.conf` blocks, including the active-response commands.
2. **Onboard endpoints** (`radar.sh mint-token` or GUI Agent Management, then `radar-agent/bootstrap-agent.sh` on the endpoint). Install and enroll the Wazuh agent into `default`, the scenario's group and, for shared scenarios, `radar_shared`. Install the active-response scripts listed in `radar-agent/ar-scripts.yaml` and the scenario's metric collector, if it has one. Already-enrolled agents are assigned to the scenario's groups from the manager instead (GUI Group Management).
3. **Create the anomaly detection pipeline**, only for scenarios that use the OpenSearch AD plugin (`run-radar.sh <scenario> [--ingest true]`, GUI Anomaly Detector). Optionally seed the indices with synthetic history, then create and start the detector and create the monitor that posts to the webhook. For `suspicious_login`, `off_hours.py` deploys the off-hours pipeline, backfills it and creates the rule-mode monitor or the model-mode detector and monitor instead.

The thresholds that trigger the monitors come from `radar/config.yaml`, and the risk tiers and mitigations that decide the response come from `radar/scenarios/active_responses/ar.yaml`.

```mermaid
flowchart TB
  subgraph s1["1. Deploy the scenario on the manager"]
    B["build-radar.sh #lt;scenario#gt;<br/>or GUI Scenario Management"]
    CORE["Core stack if no manager runs,<br/>webhook built and enrolled,<br/>enrollment hardened"]
    MF["Manager-side files: radar_ar.py, ar.yaml,<br/>enrichment integrations, Filebeat pipeline"]
    API["Wazuh API: agent-group configuration,<br/>decoders, rules, CDB lists,<br/>ossec.conf blocks incl. AR commands"]
    B --> CORE --> MF --> API
  end

  subgraph s2["2. Onboard endpoints"]
    TOK["radar.sh mint-token<br/>or GUI Agent Management"]
    BS["bootstrap-agent.sh on the endpoint:<br/>enroll into default, scenario group,<br/>radar_shared"]
    ARC["Install AR scripts (ar-scripts.yaml)<br/>and metric collector"]
    GRP["Already-enrolled agents:<br/>GUI Group Management"]
    TOK --> BS --> ARC
  end

  subgraph s3["3. Anomaly detection pipeline"]
    RUN["run-radar.sh #lt;scenario#gt; [--ingest true]<br/>or GUI Anomaly Detector"]
    SL{"suspicious_login?"}
    ING1["Optional: seed history"]
    DET["detector.py: create and start detector"]
    MON["monitor.py: monitor posting to webhook"]
    OHD["off_hours.py deploy:<br/>radar-off-hours pipeline"]
    ING2["Optional: seed history"]
    OHB["off_hours.py backfill"]
    OHM["off_hours.py monitors: rule-mode monitor<br/>or model-mode detector and monitor"]
    RUN --> SL
    SL -->|no| ING1 --> DET --> MON
    SL -->|yes| OHD --> ING2 --> OHB --> OHM
  end

  API --> TOK
  API --> GRP
  ARC --> ADQ{"Uses OpenSearch AD?"}
  GRP --> ADQ
  ADQ -->|yes| RUN
  ADQ -->|no| READY(["Scenario ready"])
```
{width="60%"}

Related: HARC-004, HARC-005.