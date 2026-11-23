---
active: true
derived: false
level: 2.3
links:
- SRS-056: cPHoeLEAeLaaZ8tCLEz_E724FHEVIvO-aLO0IBU7EMQ=
- SRS-062: umq1jJ6JmmUdM9cRbOX6I9iDoL3ADz0MdwhUZP0blw4=
- SRS-071: ZHNgKjI-5h3aLRPBushyk3-rGXZlaZGed2XtpPWs0Gg=
normative: true
ref: ''
release: Alpha
reviewed: uJzZ1btJWfyvF-qPqBWl5vRWnvNgo0cFX1Lg8TEnKB4=
version: '0.4'
---

# RADAR integration with OpenSearch modules

RADAR uses two OpenSearch plugins shipped with the Wazuh indexer: Anomaly Detection, which runs a random cut forest (RCF) detector per scenario, and Alerting, which runs the monitor that reports anomalies to RADAR.

- **Configuration.** `run-radar.sh` runs `detector.py` and `monitor.py` (or, for `suspicious_login`, `off_hours.py`) in the throwaway `radar-cli` container. They create the detector from the scenario's features, `categorical_field`, `shingle_size`, `detector_interval` and `delay_minutes` in `radar/config.yaml`, and a monitor with the scenario's `anomaly_grade_threshold` and `confidence_threshold`.
- **Input indices.** `log_volume` reads `wazuh-ad-log-volume-*`, filled through the patched Filebeat archives pipeline. `linux_resource_utilization` reads `wazuh-archives-*`. The off-hours model mode of `suspicious_login` reads `wazuh-archives-*` events flagged by the `radar-off-hours` ingest pipeline.
- **Output path.** When the monitor's trigger condition holds, it POSTs to the `ad-webhook` container at `/notify` on port 8080. The webhook writes one `ad_alert` line per anomalous entity to a log file read by its own Wazuh agent. The manager decodes the line with the `opensearch_ad` decoder, matches the scenario's AD rules, and runs `radar_ar.py`.

See: `docs/manual/radar_docs/radar-run-ad.md`.

```mermaid
%% radar/run-radar.sh, radar/anomaly_detector/, radar/webhook/ad_alerts_webhook.py
flowchart LR
  subgraph cli["radar-cli container (run-radar.sh)"]
    DPY["detector.py"]
    MPY["monitor.py"]
    OPY["off_hours.py<br/>(suspicious_login)"]
  end

  ARCH["Manager archives<br/>(Filebeat archives pipeline)"]

  subgraph idx["Wazuh indexer (OpenSearch)"]
    PIPE["radar-off-hours<br/>ingest pipeline"]
    LV[("wazuh-ad-log-volume-*")]
    AR[("wazuh-archives-*")]
    subgraph adp["Anomaly Detection plugin"]
      DET["RCF detector per scenario"]
    end
    subgraph alp["Alerting plugin"]
      MON["Monitor<br/>(anomaly_grade_threshold,<br/>confidence_threshold)"]
      QM["Off-hours query monitor<br/>(rule mode)"]
    end
  end

  subgraph whc["ad-webhook container"]
    WH["Webhook /notify :8080"]
    WAG["Wazuh agent<br/>(/var/log/ad_alerts.log)"]
  end

  MGR["Wazuh manager:<br/>opensearch_ad decoder, AD rules"]
  RAR["radar_ar.py"]

  ARCH -->|log_volume metrics| LV
  ARCH -->|other events| AR
  ARCH -->|suspicious_login| PIPE
  PIPE -->|flagged events| AR
  DPY -->|"features, categorical_field, shingle_size,<br/>detector_interval, delay_minutes"| DET
  MPY -->|thresholds| MON
  OPY -->|"deploy, backfill"| PIPE
  OPY -->|"rule-mode monitor,<br/>model-mode detector and monitor"| QM
  LV --> DET
  AR --> DET
  AR -->|flagged events| QM
  DET -->|anomaly results| MON
  MON -->|POST| WH
  QM -->|POST| WH
  WH -->|ad_alert line per entity| WAG
  WAG --> MGR
  MGR --> RAR
```
{width="90%"}

Related: HARC-004, HARC-005.