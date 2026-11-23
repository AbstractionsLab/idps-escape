---
active: true
derived: false
level: 2.7
links:
- SRS-056: cPHoeLEAeLaaZ8tCLEz_E724FHEVIvO-aLO0IBU7EMQ=
- SRS-062: umq1jJ6JmmUdM9cRbOX6I9iDoL3ADz0MdwhUZP0blw4=
- SRS-071: ZHNgKjI-5h3aLRPBushyk3-rGXZlaZGed2XtpPWs0Gg=
- SRS-089: -2y47C-Pd178im0LQo0uCWdw1eMlrk1nUtAzUD0JsIQ=
normative: true
ref: ''
release: Alpha
reviewed: 9PVU2BGLJ4_uupeigJpYUkBRpOpIJEX5tyMSga2Wrqg=
version: '0.1'
---

# RADAR monitor and webhook workflow

The diagram below depicts how `radar/anomaly_detector/monitor.py` and `radar/anomaly_detector/webhook.py` create the OpenSearch notification channel and alerting monitor for an anomaly detector, and how the monitor's notifications then reach Wazuh through the RADAR webhook service (`radar/webhook/ad_alerts_webhook.py`). `run-radar.sh` runs `monitor.py` after `detector.py` (LARC-022) for `log_volume` and `linux_resource_utilization`; the `suspicious_login` off-hours monitors are created by `off_hours.py` through the same channel and webhook.

## Workflow stages

### 1. Notification channel (idempotent)
`ensure_webhook()` in `webhook.py`:

- `GET /_plugins/_notifications/configs` and look for a `webhook` channel with the configured name (`webhook.name` in `config.yaml`, else `WEBHOOK_NAME`, default "RADAR Webhook") and URL (`webhook.url`, else `WEBHOOK_URL`).
- If found, update it when its shared-secret header differs; otherwise `POST /_plugins/_notifications/configs` to create it.
- The channel sends the header `X-RADAR-Webhook-Token` with `WEBHOOK_SHARED_SECRET`.

### 2. Monitor specification
`monitor_payload()` builds a query-level monitor named `monitor_name`:

- **Schedule**: every `monitor_interval`, else `detector_interval`, minutes.
- **Input**: search of the detector's `result_index` for results of this detector in the last interval with anomaly grade and confidence at or above `anomaly_grade_threshold` and `confidence_threshold`, highest grade first, at most `monitor_max_entities` (default 5) hits.
- **Trigger** `trigger_name`: a Painless condition on the maximum grade and the top hit's confidence.
- **Action**: POST to the channel with the message template of SWD-029: the top hit's keys plus an `anomalies` list with one entry per hit, each with entity, grade, confidence and the anomaly's own data window.
- A SHA-256 fingerprint of the payload is stored in the monitor's `ui_metadata`.

### 3. Monitor creation or update
- `POST /_plugins/_alerting/monitors/_search` by monitor name.
- If it exists and its detector ID or payload fingerprint differs, `PUT` the new payload; if it matches, leave it. Otherwise `POST /_plugins/_alerting/monitors`.
- Print the monitor ID.

### 4. Runtime delivery
- Each run with a hit posts to the webhook (`POST /notify`, port `WEBHOOK_INTERNAL_PORT`, default 8080).
- The webhook checks the token, validates each entry, and writes one line per entity to `/var/log/ad_alerts.log` (format in SWD-035).
- The Wazuh agent in the webhook container ships the file to the manager, where the `opensearch_ad` decoder, an AD catch-all rule (`radar_ad_received` group) and the scenario's trigger rule invoke `radar_ar.py`.

## Monitor and webhook sequence

```plantuml
@startuml
participant "run-radar.sh" as CLI
participant "monitor.py" as Monitor
participant "webhook.py" as Webhook
participant "Notifications\nPlugin" as NotifPlugin
participant "Alerting\nPlugin" as AlertPlugin
participant "Detector\nResult Index" as DetectorIndex
participant "RADAR webhook\n(ad_alerts_webhook.py)" as WebhookSvc
participant "Wazuh agent\n(webhook container)" as Agent
participant "Wazuh manager" as Manager

CLI -> Monitor: docker run radar-cli python monitor.py <scenario> <detector_id>

group 1. Ensure notification channel
  Monitor -> Webhook: ensure_webhook(name, url, token header)
  Webhook -> NotifPlugin: GET /_plugins/_notifications/configs
  NotifPlugin --> Webhook: channels
  alt Channel exists
    opt Token header differs
      Webhook -> NotifPlugin: PUT /_plugins/_notifications/configs/{id}
    end
  else Channel missing
    Webhook -> NotifPlugin: POST /_plugins/_notifications/configs
  end
  Webhook --> Monitor: destination_id
end

group 2. Build payload
  Monitor -> Monitor: monitor_payload(scenario, detector_id, destination_id)
  note right of Monitor
    query: last interval, this detector,
    grade and confidence >= thresholds,
    top monitor_max_entities by grade
    action: top-hit keys + anomalies list
    ui_metadata: payload sha256
  end note
end

group 3. Create or update
  Monitor -> AlertPlugin: POST /_plugins/_alerting/monitors/_search (name)
  AlertPlugin --> Monitor: existing monitor, if any
  alt Missing
    Monitor -> AlertPlugin: POST /_plugins/_alerting/monitors
  else Detector or fingerprint differs
    Monitor -> AlertPlugin: PUT /_plugins/_alerting/monitors/{id}
  else Up to date
    note over Monitor: no change
  end
  Monitor --> CLI: monitor_id (stdout)
end

group 4. Runtime, every interval
  AlertPlugin -> DetectorIndex: query recent results
  DetectorIndex --> AlertPlugin: anomalous entities
  opt Trigger condition true
    AlertPlugin -> WebhookSvc: POST /notify\nX-RADAR-Webhook-Token
    WebhookSvc -> WebhookSvc: check token, validate entries
    WebhookSvc -> WebhookSvc: append one line per entity\nto /var/log/ad_alerts.log
    WebhookSvc --> AlertPlugin: 200 {"status": "written", "lines": n}
    Agent -> Manager: ship /var/log/ad_alerts.log lines
    Manager -> Manager: opensearch_ad decoder,\ncatch-all + trigger rule,\nradar_ar.py
  end
end

@enduml
```

## Implementation reference

- [radar/anomaly_detector/monitor.py](../../../radar/anomaly_detector/monitor.py) - monitor creation and update
- [radar/anomaly_detector/webhook.py](../../../radar/anomaly_detector/webhook.py) - notification channel management
- [radar/webhook/ad_alerts_webhook.py](../../../radar/webhook/ad_alerts_webhook.py) - webhook service

Related: HARC-004, HARC-012, LARC-022.