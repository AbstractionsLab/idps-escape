---
active: true
derived: false
level: 2.13
links:
- SRS-056: cPHoeLEAeLaaZ8tCLEz_E724FHEVIvO-aLO0IBU7EMQ=
normative: true
ref: ''
release: Alpha
reviewed: 82ysUrs9SmfQOQKp7MnuLzc51h3lPrYCMCYq8wBuqes=
version: '0.1'
---

# RADAR log volume detection scenario flow

This item describes the end-to-end flow of the `log_volume` scenario (SRS-056), which uses **behaviour-based anomaly detection** (OpenSearch RCF) to identify abnormal growth of the logs on an endpoint, a possible sign of log flooding, malware error loops or other abnormal activity.

## Scenario overview

- Measures the size of `/var/log` on each endpoint.
- Per-endpoint baselines through a detector with a categorical field (`agent.name`).
- Anomalies reach Wazuh through the OpenSearch monitor and the RADAR webhook.
- The RADAR active response scores the anomaly and applies the tier's actions.

## Flow stages

### 1. Collection on the endpoint
- `bootstrap-agent.sh` installs the `log_volume` collector (`radar/radar-agent/collectors/log_volume/`) as a systemd timer that runs every 30 seconds.
- Each run appends `<timestamp> <hostname> log_volume_metric: /var/log <bytes>` (from `du -sb /var/log`) to `/var/log/radar/log_volume_metric.log`.
- The `log_volume` agent group reads this file (`log_format` syslog).

### 2. Decoding and indexing on the manager
- Decoders `log_volume_metric` / `log_volume_metric_fields` (`radar/scenarios/decoders/log_volume/0001-log-volume.xml`) extract `data.log_path` and `data.log_bytes`.
- A `date_index_name` step added to the Filebeat archives pipeline (`radar/scenarios/pipelines/log_volume/radar-pipeline.txt`) routes these events to `wazuh-ad-log-volume-YYYY.MM.DD`; the `radar-log-volume` index template (`radar/scenarios/templates/log_volume/radar-template.json`) maps `data.log_bytes` as long and `agent.name` as keyword.

### 3. Optional history seeding (LARC-027)
- `run-radar.sh log_volume --ingest true` runs `radar/scenarios/ingest_scripts/log_volume/wazuh_ingest.py`, which writes a synthetic history (by default 240 minutes at 20-second steps, settings under `scenarios.log_volume.ingest` in `config.yaml`) for the configured agent (`ingest.agent_name`), continuing the growth of its latest indexed values, or from the configured seed when there are none.

### 4. Detector creation (LARC-022)
- `run-radar.sh log_volume` creates and starts `LOG_VOLUME_DETECTOR`: feature `log_volume_max` = max of `data.log_bytes`, category field `agent.name`, shingle size 8, interval 1 minute, window delay 1 minute, rules that ignore deviations too small to matter.

### 5. Anomaly detection
- Every interval the detector scores each agent's value against that agent's model and writes the anomaly grade and confidence to `opensearch-ad-plugin-result-log-volume`.

### 6. Monitor and webhook (LARC-023)
- `LogVolume-Monitor` runs every interval and, when grade and confidence reach the thresholds (shipped 0.01 / 0.01), posts up to 5 anomalous agents to the webhook with trigger `LogVolume-Growth-Detected`.
- The webhook writes one line per agent to `/var/log/ad_alerts.log`, for example:
  ```
  Feb 16 10:30:15 <host> ad_alert: OpenSearchAD LogVolume-Growth-Detected: entity="edge.vm", start="…", end="…", anomaly_grade="0.85", anomaly_confidence="0.92" data_start="…", data_end="…"
  ```

### 7. Wazuh rule matching
- The webhook container's agent ships the line; the `opensearch_ad` decoder extracts the entity, period, grade, confidence and data window.
- **100300** (level 5): AD catch-all for lines from `/var/log/ad_alerts.log`, group `radar_ad_received`.
- **100309** (level 12): `if_group radar_ad_received` and the trigger name.

### 8. Active response (LARC-026)
- 100309 invokes `radar_ar_log_volume` (`radar_ar.py`) on the manager; scenario `log_volume`, detection `ad`.
- Context: the anomalous agent's (`entity_keyword`) events in the monitor period, capped at `delta_ad_minutes` (10).
- Risk: $A$ = grade × confidence, $R = 0.9 \cdot A + 0.1 \cdot T$, with $T = 0$ (no DECIPHER analysis endpoint). Example: grade 0.85, confidence 0.92 gives $A = 0.782$ and $R = 0.704$, Tier 3.
- Tier 1 and above: email and, if DECIPHER is reachable, a Flowintel case. Tier 3: `terminate_service.sh` when `allow_mitigation` is true, only for a context service listed in `terminable_services` and on the agent.

### 9. Logging
- The decision is recorded in `/var/ossec/logs/active-responses.log` (SRS-061).

## Configuration

- `config.yaml`, `scenarios.log_volume`: index pattern, result index, feature, category field, interval, delay, shingle size, thresholds, monitor and trigger names, ingest settings.
- `ar.yaml`, `log_volume`: `ad.rule_ids: ["100309"]`, `w_ad` 0.9, `w_cti` 0.1, tiers 0.0 / 0.33 / 0.66, `mitigations_tier3: [terminate_service.sh]`, `terminable_services: []`, `allow_mitigation: true`.

## Key characteristics

- **Adaptive**: learns normal growth per endpoint.
- **Per entity**: separate baselines per agent avoid one busy host masking another.
- **Streaming**: detection runs continuously, without batch retraining.
- **Decoupled**: detection runs in OpenSearch, response in Wazuh and `radar_ar.py`.

## Implementation reference

- [docs/manual/radar_docs/radar-scenarios/log_volume_explained.md](../../manual/radar_docs/radar-scenarios/log_volume_explained.md) - operator documentation
- [radar/radar-agent/collectors/log_volume/](../../../radar/radar-agent/collectors/log_volume/) - collector
- [radar/scenarios/decoders/log_volume/](../../../radar/scenarios/decoders/log_volume/) - decoders
- [radar/scenarios/rules/log_volume/](../../../radar/scenarios/rules/log_volume/) - rules
- [radar/scenarios/ingest_scripts/log_volume/](../../../radar/scenarios/ingest_scripts/log_volume/) - history seeding

Related: HARC-004, LARC-022, LARC-023, LARC-026.