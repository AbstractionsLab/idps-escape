# Wazuh Anomaly Detection Webhook

Here we describe a small Flask webhook service that receives anomaly alerts from an OpenSearch AD Monitor and writes concise, timestamped lines to a local log file. These entries can then be ingested by Wazuh (via a `localfile` block) for decoding, rule matching, and active response.

## Features

- **HTTP endpoint** (`POST /notify`) for OpenSearch alert callbacks  
- **Timezone conversion**: converts the AD monitor’s UTC `periodStart` / `periodEnd` into your local time  
- **Simple, human-readable log format** written to `/var/log/ad_alerts.log`  
- **Lightweight**: pure Python + Flask, no external dependencies beyond Flask  

## Prerequisites

- **Python 3.8+**  
- **Flask**   
- Write permissions to `/var/log/ad_alerts.log`

## Installation

1. **Clone or copy** `ad_alerts_webhook.py` onto your webhook host (e.g. the Wazuh manager or a separate app server).  
2. **Install dependencies (ideally in a virtual environment)**:
    ```bash
    pip3 install flask
    ```
3. **Ensure log file exists** and is writable by the webhook process:
    ```bash
    sudo touch /var/log/ad_alerts.log
    sudo chmod 664 /var/log/ad_alerts.log
    ```

## Configuration

Edit the top of `ad_alerts_webhook.py` if you need to change:

- `LOG_FILE` — path to the log file  
- `HOST` / `PORT` — which interface and port Flask should bind to  

By default, the script runs on `0.0.0.0:8888`.

## Running the Webhook
```bash
python3 ad_alerts_webhook.py
```

## Wazuh Monitor configuration

In your OpenSearch AD Monitor, configure a Webhook action with:

- URL: http://<webhook-host>:8080/notify
- Payload: 
```
{
  "monitor": {
    "name": "{{ctx.monitor.name}}"
  },
  "trigger": {
    "name": "{{ctx.trigger.name}}"
  },
  "entity": "{{ctx.results.0.hits.hits.0._source.entity.0.value}}",
  "periodStart": "{{ctx.periodStart}}",
  "periodEnd":   "{{ctx.periodEnd}}",
  "anomaly_grade": "{{ctx.results.0.hits.hits.0._source.anomaly_grade}}", 
  "anomaly_confidence": "{{ctx.results.0.hits.hits.0._source.confidence}}"
}
```
When the Monitor fires, OpenSearch will send exactly that JSON to your webhook.