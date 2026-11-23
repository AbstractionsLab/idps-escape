# Wazuh anomaly detection webhook

A small Flask service that receives anomaly alerts from the OpenSearch AD monitors that RADAR creates, and writes one line per anomalous entity to `/var/log/ad_alerts.log`. A Wazuh agent in the same container ships that file to the manager, where the `opensearch_ad` decoders and the AD scenario rules (100309, 100321, 210040, 210041) turn each line into an alert.

RADAR builds, enrols and starts this container itself (`docker-compose.webhook.yml`, container `ad-webhook`), and `run-radar.sh` creates the monitors and the notification channel that call it. You don't need to configure anything by hand.

## Request

`POST /notify` with the header `X-RADAR-Webhook-Token: <WEBHOOK_SHARED_SECRET>`. Requests without the right token get `401`.

The body is the JSON that `message_template()` in [monitor.py](../anomaly_detector/monitor.py) renders:

- `trigger.name`, `periodStart` and `periodEnd`: the trigger and the monitor run window.
- `anomalies`: one entry per anomalous entity (up to `monitor_max_entities` in `config.yaml`, default 5), each with `entity`, `anomaly_grade`, `anomaly_confidence`, `dataStart` and `dataEnd`. The last two are the anomaly's own data window, in epoch milliseconds. The list ends with `null`.
- `entity`, `anomaly_grade`, `anomaly_confidence`, `dataStart`, `dataEnd` at the top level: the highest-graded entry, kept for older webhooks.

A body without `anomalies`, as sent by monitors created before RADAR 2.2.0, is still accepted and gives one line.

The off-hours rule-mode monitor (`off_hours.py`, trigger `SuspiciousLogin-OffHours-Rule-Detected`) sends the same body, with `dataStart`/`dataEnd` as ISO times (first and last off-hours event) and two more keys per entry: `off_hours_count` (an integer) and `schedule_group`. They are written after the data window, and only when both are valid:

```
Nov 21 10:30:02 ad-webhook ad_alert: OpenSearchAD SuspiciousLogin-OffHours-Rule-Detected: entity="arash", start="2026-11-21T10:20:00Z", end="2026-11-21T10:30:00Z", anomaly_grade="1.0", anomaly_confidence="1.0" data_start="2026-11-21T10:21:03.100Z", data_end="2026-11-21T10:24:00.721Z" off_hours_count="21", schedule_group="synthetic_day"
```

The `opensearch_ad_detector` sibling decoder in `0001-ad-common.xml` reads them into `data.off_hours_count` and `data.schedule_group`.

## Output

One line per entity, highest grade first, at most one per entity:

```
Nov 20 07:06:12 ad-webhook ad_alert: OpenSearchAD LinuxResourceUtilization-Anomaly-Detected: entity="edge.vm", start="2026-11-20T07:05:00Z", end="2026-11-20T07:06:00Z", anomaly_grade="0.82", anomaly_confidence="0.91" data_start="2026-11-20T07:00:00.000Z", data_end="2026-11-20T07:01:00.000Z"
```

`data_start`/`data_end` are appended in UTC only when the monitor sent a usable data window. Entries that fail validation are skipped; the request is rejected with `400` only when no entry is usable. The response reports how many lines were written.

## Settings

Environment variables of the container:

| Variable | Default | Purpose |
|---|---|---|
| `WEBHOOK_SHARED_SECRET` | none (required) | Token every request must carry |
| `WEBHOOK_INTERNAL_PORT` | `8080` | Listening port |
| `AD_ALERTS_LOG` | `/var/log/ad_alerts.log` | Output file |
| `WEBHOOK_AGENT_NAME` | `ad-webhook` | Name the container's Wazuh agent enrols with |

RADAR trusts anomaly alerts only when they come from this file on this agent. See [Firewall rules to enforce](../README.md#firewall-rules-to-enforce) for the firewall rule that limits port 8080 to the indexer.
