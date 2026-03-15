---
active: true
derived: false
level: 2.7
links:
- HARC-004: B-4i2SClF5iGbeV-cWw9l0nDiMns0PHC2fNuaqSQAmo=
- HARC-012: ilKIUnLMG0LmoIUP781vdTvx8oRCMLZHrRM5puzgbGU=
- LARC-022: tH9LfjIxzDfssQPvlDYNSMqEW06cLQf9ts3l08QvrXI=
- SRS-050: f1fx4EzuMUZpkPuPmI8RJXj5-ASOsNLfOUx5pm81PWc=
- SRS-051: L_FEEgh5sx0eJ_B6mZtm3kp_90KxFJLwar48ZeSHzbk=
- SRS-052: rnH2AeVu4U2ZbCOXkatJeqKiv_ziq90iRQZJjU1fHKc=
- SRS-056: xKvRTfbWPnFhLmrKkVnKcrA1gfDRFhhKwc6tXbXmnJw=
normative: true
ref: ''
release: Alpha
reviewed: zipSVvmSX3ZDxzf71r69dtVLRWVy5Hbh4tB40WaOaSs=
version: '0.1'
---

# RADAR monitor and webhook workflow

The diagram below depicts the sequence for creating OpenSearch monitors and webhook notification channels via `monitor.py` and `webhook.py` modules.

## Workflow overview

The monitor workflow ensures anomaly detection results trigger automated responses when thresholds are exceeded. Monitors continuously evaluate detector outputs and send structured notifications to a webhook endpoint, which integrates with Wazuh's rule engine.

## Workflow stages

### 1. Webhook destination setup
Execute `ensure_webhook()` from webhook.py:

- Query existing notification destinations: `GET /_plugins/_notifications/configs`
- Search for webhook by name pattern
- If not found, create new webhook destination:

    - Endpoint: `POST /_plugins/_notifications/configs`
    - Configuration: Custom webhook type, POST method, webhook URL from environment
    - Return webhook destination ID

### 2. Monitor existence check
- Query existing monitors: `GET /_plugins/_alerting/monitors/_search`
- Search by name pattern: `{scenario}_Monitor`
- If found, return existing monitor ID (idempotent operation)

### 3. Monitor specification building
Construct monitor JSON including:

- **Schedule**: Evaluation frequency (defaults to detector_interval if monitor_interval not specified)
- **Inputs**: Query detector's result index for recent anomalies
- **Triggers**: Condition evaluating anomaly scores
- **Actions**: Webhook notification when triggered

### 4. Trigger condition configuration
Default trigger logic:
```
anomaly_grade > threshold AND confidence > threshold
```

Where thresholds are defined in scenario configuration (typical values: 0.3-0.5 for balanced sensitivity/precision).

### 5. Webhook action specification
Notification payload includes:
```json
{
  "monitor": {"name": "{{ctx.monitor.name}}"},
  "trigger": {"name": "{{ctx.trigger.name}}"},
  "entity": "{{ctx.results.0.hits.hits.0._source.entity.0.value}}",
  "periodStart": "{{ctx.periodStart}}",
  "periodEnd": "{{ctx.periodEnd}}"
}
```

### 6. Monitor creation
- Create monitor via OpenSearch Alerting API
- Endpoint: `POST /_plugins/_alerting/monitors`
- Monitor begins evaluating detector results at configured intervals

### 7. Output
- Return monitor ID to stdout
- Monitor continuously watches detector and triggers webhook on anomalies

## Key functions

```python
# webhook.py
notif_find_id(webhook_name: str) -> str | None
notif_create(webhook_url: str) -> str
ensure_webhook() -> str

# monitor.py
find_monitor_id(monitor_name: str) -> str | None
monitor_payload(detector_id: str, webhook_id: str, config: dict) -> dict
create_monitor(payload: dict) -> str
```

## Integration flow

Monitor → Detector Results → Evaluate Threshold → Webhook POST → `/var/log/ad_alerts.log` → Wazuh Rules → Active Response

## Monitor and Webhook Sequence

```plantuml
@startuml
participant "run-radar.sh" as CLI
participant "radar-cli\nContainer" as Docker
participant "webhook.py" as Webhook
participant "monitor.py" as Monitor
participant "OpenSearch\nAPI" as OS
participant "Notifications\nPlugin" as NotifPlugin
participant "Alerting\nPlugin" as AlertPlugin
participant "Detector\nResult Index" as DetectorIndex
participant "Webhook\nService" as WebhookSvc

note over CLI,WebhookSvc: Monitor and Webhook Workflow

group Phase 1: Ensure webhook destination (idempotent)
  CLI -> Docker: docker run radar-cli monitor.py
  Docker -> Webhook: ensure_webhook()

  Webhook -> NotifPlugin: GET /_plugins/_notifications/configs
  note over Webhook,NotifPlugin: Search for existing webhook
  NotifPlugin --> Webhook: Webhook list

  alt Webhook exists
    Webhook --> Monitor: Return existing webhook_id
  else Webhook not found
    Webhook -> NotifPlugin: POST /_plugins/_notifications/configs
    note over Webhook,NotifPlugin
      Create webhook destination
      config_type: webhook
      name: {scenario}_webhook
      url: http://manager:8080/notify
      method: POST
    end note
    NotifPlugin --> Webhook: webhook_id
    Webhook --> Monitor: Return new webhook_id
  end
end

group Phase 2: Check for existing monitor (idempotent)
  Monitor -> AlertPlugin: GET /_plugins/_alerting/monitors/_search
  note over Monitor,AlertPlugin: Search by name: "{scenario}_Monitor"
  AlertPlugin --> Monitor: Monitor list

  alt Monitor exists
    Monitor --> CLI: Return existing monitor_id
    note over Monitor: Exit early (idempotent)
  else Monitor not found
    note over Monitor: Proceed to creation
  end
end

group Phase 3: Build monitor specification
  Monitor -> Monitor: Load scenario config
  note right of Monitor
    Schedule: Every 5 minutes
    Input: Query detector result index
    Trigger: anomaly_grade > threshold
    Action: Webhook notification
  end note

  Monitor -> Monitor: monitor_payload(detector_id, webhook_id)
  note right of Monitor
    name: {scenario}_Monitor
    schedule: {period: {interval: 5, unit: MINUTES}}
    inputs: [search detector result index]
    triggers: [AnomalyTrigger condition]
    actions: [webhook notification]
  end note
end

group Phase 4: Create monitor via API
  Monitor -> AlertPlugin: POST /_plugins/_alerting/monitors
  AlertPlugin -> DetectorIndex: Validate query against result index
  DetectorIndex --> AlertPlugin: Query valid
  AlertPlugin --> Monitor: monitor_id, status: "ACTIVE"
end

group Phase 5: Continuous anomaly monitoring
  loop Every 5 minutes
    AlertPlugin -> DetectorIndex: Query for recent anomalies
    DetectorIndex --> AlertPlugin: Anomaly results

    alt Anomaly detected (grade > threshold)
      AlertPlugin -> AlertPlugin: Evaluate trigger condition
      note over AlertPlugin
        anomaly_grade > 0.3 AND
        confidence > 0.3
      end note

      AlertPlugin -> WebhookSvc: POST /notify
      note over AlertPlugin,WebhookSvc
        Webhook payload:
        monitor: {name: "log_volume_Monitor"}
        trigger: {name: "AnomalyTrigger"}
        entity: "edge.vm"
        anomaly_grade: 0.85
        confidence: 0.92
        periodStart: "2026-02-16T10:00:00Z"
        periodEnd: "2026-02-16T10:05:00Z"
      end note

      WebhookSvc --> AlertPlugin: 200 OK
      note over WebhookSvc: Write to /var/log/ad_alerts.log
    else No anomaly
      note over AlertPlugin: No action
    end
  end
end

Monitor --> Docker: monitor_id (stdout)
Docker --> CLI: monitor_id
note over CLI: Monitoring active

note over AlertPlugin,WebhookSvc: Monitor runs continuously until deleted/disabled

@enduml
```

## Implementation reference

See implementation details:

- [radar/anomaly_detector/monitor.py](../../../radar/anomaly_detector/monitor.py) - Monitor creation
- [radar/anomaly_detector/webhook.py](../../../radar/anomaly_detector/webhook.py) - Webhook management
- [radar/webhook/ad_alerts_webhook.py](../../../radar/webhook/ad_alerts_webhook.py) - Webhook service implementation