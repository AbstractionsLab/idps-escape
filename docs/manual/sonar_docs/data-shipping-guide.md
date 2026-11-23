# SONAR anomaly output guide

This guide explains where SONAR delivers the anomalies it detects: the **sinks**, how to choose them, the event SONAR sends to the Wazuh manager, the optional data stream in the Wazuh Indexer, and how delivery is kept free of duplicates.

For the deployment steps on the Wazuh side (rules, `<localfile>`, API user), see [Wazuh integration](./setup-guide.md#wazuh-integration) in the setup guide.

## Table of contents

1. [Sinks](#sinks)
2. [Choosing the sinks](#choosing-the-sinks)
3. [The wazuh sink](#the-wazuh-sink)
4. [SONAR event format](#sonar-event-format)
5. [The datastream sink](#the-datastream-sink)
6. [The index sink](#the-index-sink)
7. [The jsonl and stdout sinks](#the-jsonl-and-stdout-sinks)
8. [Delivery, fallback and exit status](#delivery-fallback-and-exit-status)
9. [Troubleshooting](#troubleshooting)

---

## Sinks

Every anomalous time bucket becomes one anomaly document (built by `MVADPostProcessor` in `sonar/pipeline.py`). Each configured sink receives every document:

| Sink | Destination | What it receives | Duplicate protection |
|------|-------------|------------------|----------------------|
| `wazuh` (default) | Wazuh manager, which decodes the event, matches SONAR's rules (100500–100519) and raises a Wazuh alert | [SONAR event](#sonar-event-format) | Per-sink watermark only; the manager cannot recognise a duplicate |
| `datastream` | Wazuh Indexer data stream `sonar_anomalies_mvad_<scenario_id>`, for dashboards and history | Full anomaly document | Watermark, and create-only writes under `anomaly_id` |
| `index` | Wazuh Indexer index `wazuh.anomalies_index` (`wazuh-anomalies-mvad`), the legacy destination | Full anomaly document | Watermark, and create-only writes under `anomaly_id` |
| `jsonl` | Local file `output.jsonl_path` (default `anomalies.jsonl` in the SONAR home, `sonar/anomalies.jsonl` in a checkout), appended | SONAR event, one per line | Watermark |
| `stdout` | Standard output | SONAR event, one per line | Watermark (none in debug runs) |

The `wazuh` sink is what makes SONAR anomalies visible to Wazuh: they become ordinary alerts in `wazuh-alerts-*`, on the dashboards, and available to rules, active responses and integrations. Documents written by the `datastream` and `index` sinks go straight to the indexer and bypass the manager, so no Wazuh rule or active response fires on them.

---

## Choosing the sinks

The `output:` section of the config file (or of a scenario) selects the sinks:

```yaml
output:
  sinks: [wazuh]           # wazuh, datastream, index, jsonl, stdout
  fallback: none           # none, datastream or index: takes what a sink rejected
  debug_sinks: [stdout]    # used instead of sinks with --debug or debug.enabled: true
  jsonl_path: null         # null = anomalies.jsonl in the SONAR home; relative = relative to this file
  state_dir: null          # delivery watermarks; null = <models_dir>/state
  wazuh:
    transport: file        # file (SONAR on the manager host) or api (dedicated host)
    file_path: /var/log/sonar/anomalies.json
    max_file_bytes: 10485760
    backup_count: 5
    api_url: https://localhost:55000
    api_username: sonar
    api_password: ""       # empty: read SONAR_WAZUH_API_PASSWORD
    verify_ssl: false
    timeout_seconds: 30
    severity_medium: 0.5
    severity_high: 0.8
```

| Key | Default | Description |
|-----|---------|-------------|
| `sinks` | `[wazuh]` | Sinks every anomaly goes to |
| `fallback` | `none` | Sink that stores the anomalies a configured sink rejected: `none`, `datastream` or `index`. See [Fallback](#fallback) |
| `debug_sinks` | `[stdout]` | Sinks used instead of `sinks` in debug runs: any sink but `index`, for example `[wazuh]` to send the anomalies of the bundled test data to a lab manager |
| `jsonl_path` | `null` (`<SONAR home>/anomalies.jsonl`) | File of the `jsonl` sink |
| `state_dir` | `null` | Directory of the delivery watermarks; `null` means `<models_dir>/state` |
| `wazuh.*` | see [The wazuh sink](#the-wazuh-sink) | Settings of the `wazuh` sink |

Which sinks a detection run uses:

| Run | Sinks | Fallback | Watermark |
|-----|-------|----------|-----------|
| Normal run | `output.sinks`, plus `datastream` when `--ship` or `shipping.enabled: true` is set | `output.fallback` | Read and advanced |
| `--debug`, or `debug.enabled: true` in YAML | `output.debug_sinks` (stdout by default) | None | Not used |
| `--dry-run` (or `detection.dry_run: true`) | `jsonl` writing to `<payload_dir>/anomalies.jsonl` (`--payload-dir`, else the scenario's `detection.payload_dir`, else `<SONAR home>/payloads`) | None | Not used |
| Any of the above with `--print-payloads` | `stdout` added | – | – |

- `--debug` (and `debug.enabled: true`) takes precedence over `--dry-run`.
- `debug.enabled: true` in YAML switches to the debug sinks but, unlike `--debug`, still reads alerts from the Wazuh Indexer.
- Debug runs use no watermark, so a debug sink receives every anomaly of every run. With `debug_sinks: [wazuh]`, each debug run raises the same alerts again; point it only at a lab manager.
- Training with `--debug` never installs the data stream templates.
- In debug runs the SONAR events go to standard output, one JSON object per line, while the logs go to standard error, so `sonar ... --debug > events.jsonl` captures only the events.
- `--ship` and `shipping.enabled` are kept for compatibility: they add the `datastream` sink. Listing `datastream` in `output.sinks` does the same.
- An unknown sink, fallback or transport name is an error when detection starts: SONAR logs it and exits with status 1 before reading any alerts (`sonar scenario` checks the names before its training phase).
- The `index` sink cannot be a debug sink with `--debug` (there is no indexer client); with `debug.enabled: true` in YAML it works like any other sink.

At start-up SONAR logs the sinks it uses, for example `Anomaly sinks: wazuh, datastream (fallback index)`.

---

## The wazuh sink

The `wazuh` sink sends each anomaly to the Wazuh manager as a [SONAR event](#sonar-event-format). SONAR runs on the Wazuh manager host or on a dedicated machine, never on the monitored endpoints, whose resources may be limited. No Wazuh agent is needed on the SONAR host. The topology decides the transport:

| Topology | `transport` | How events reach the manager | Setup |
|----------|-------------|------------------------------|-------|
| SONAR on the manager host, or in a container sharing a volume with the manager container | `file` | SONAR appends one JSON line per anomaly to `file_path`; the manager reads the file through a `<localfile>` block with `log_format json` | [SONAR on the manager host](./setup-guide.md#sonar-on-the-manager-host) |
| SONAR on a dedicated host | `api` | SONAR posts the events to the Wazuh server API (`POST /events`, Wazuh 4.6 and later) | [SONAR on a dedicated host](./setup-guide.md#sonar-on-a-dedicated-host) |

### File transport

- Each run appends its events to `file_path` (default `/var/log/sonar/anomalies.json`) in a single write, flushed and synced to disk (`fsync`) before the run counts them as delivered. A write either succeeds for the whole batch or fails for the whole batch.
- The file is rotated by size: when a write would make it larger than `max_file_bytes` (default 10 MiB), `anomalies.json` is renamed to `anomalies.json.1`, older copies shift up, and copies beyond `backup_count` (default 5) are deleted. With `backup_count: 0` the file is deleted instead of renamed.
- `file_path` is the path as SONAR sees it. The manager's `<localfile>` `location` must be the same file as the manager sees it, which differs when SONAR runs in a container (see [SONAR in Docker next to the manager](./setup-guide.md#sonar-in-docker-next-to-the-manager)).
- SONAR creates the parent directory if it can; the SONAR user needs write access to it.

### API transport

- SONAR authenticates with `POST /security/user/authenticate` (HTTP basic authentication with `api_username` and the password), and sends the JWT it receives as a bearer token. It renews the token every 850 seconds (the API's default token lifetime is 900 s) and once more if a request is answered with HTTP 401.
- Events go to `POST /events` as `{"events": ["<event line>", ...]}`, at most 100 events per request. A response with failed items stops the batch: the events before the failing request count as delivered, the rest are offered again on the next run.
- HTTP 429 (rate limit) is retried up to three times, waiting as long as the `Retry-After` header says, or 2, 4 and 8 seconds without one (at most 60 s).
- `verify_ssl` controls the API certificate check: `false` (default, no check), `true` (system trust store) or the path of the CA bundle that issued the API certificate.
- The password is `api_password`, or the environment variable `SONAR_WAZUH_API_PASSWORD` when `api_password` is empty. Prefer the environment variable, so the password stays out of config files.
- Use a dedicated API user whose role allows only `event:ingest`; see [Create the event:ingest API user](./setup-guide.md#create-the-eventingest-api-user).

How the manager decodes events received through the API (their location, and whether the JSON decoder applies exactly as for the file transport) is verified on Wazuh 4.14.1 in lab test [TST-068](../../specs/tst/TST-068.md).

### Wazuh sink settings

| Key | Default | Transport | Description |
|-----|---------|-----------|-------------|
| `transport` | `file` | – | `file` or `api` |
| `file_path` | `/var/log/sonar/anomalies.json` | file | File the manager's `<localfile>` reads |
| `max_file_bytes` | `10485760` (10 MiB) | file | Rotate when a write would exceed this size |
| `backup_count` | `5` | file | Rotated files kept (`anomalies.json.1` …) |
| `api_url` | `https://localhost:55000` | api | Wazuh server API URL |
| `api_username` | `sonar` | api | API user, ideally one allowed only `event:ingest` |
| `api_password` | `""` | api | API password; empty reads `SONAR_WAZUH_API_PASSWORD` |
| `verify_ssl` | `false` | api | `false`, `true` or a CA bundle path |
| `timeout_seconds` | `30` | api | Timeout per request |
| `severity_medium` | `0.5` | both | Lowest severity of the `medium` band |
| `severity_high` | `0.8` | both | Lowest severity of the `high` band |

### Rules

The manager raises an alert for a SONAR event only when SONAR's rules are installed. They ship as [`sonar/wazuh/rules/sonar_rules.xml`](../../../sonar/wazuh/rules/sonar_rules.xml) and use the rule ID range 100500–100519, in the rule groups `sonar` and `anomaly`:

| Rule ID | Level | Matches |
|---------|-------|---------|
| 100500 | 3 | Any SONAR event: decoded as JSON and `integration` is `sonar` |
| 100501 | 3 | `sonar.severity_band` is `low` |
| 100502 | 7 | `sonar.severity_band` is `medium` |
| 100503 | 10 | `sonar.severity_band` is `high` |
| 100510–100519 | – | Free for your own per-scenario rules |

Install them with `sonar wazuh install-rules` or by copying the file to the manager; see [Install the rules](./setup-guide.md#install-the-rules).

A per-scenario rule refines a band rule, for example to raise high-severity brute-force anomalies to level 12:

```xml
<group name="sonar,anomaly,">
  <rule id="100510" level="12">
    <if_sid>100503</if_sid>
    <field name="sonar.scenario">^brute_force$</field>
    <description>SONAR: high-severity brute-force anomaly (severity $(sonar.severity))</description>
    <options>no_full_log</options>
  </rule>
</group>
```

Keep such rules in a file of their own, for example `/var/ossec/etc/rules/sonar_local_rules.xml`, so that `sonar wazuh install-rules` does not overwrite them.

### Severity bands

Wazuh rules match strings and cannot compare numbers, so SONAR puts each anomaly's severity into a band:

| Band | Severity | Rule |
|------|----------|------|
| `low` | below `severity_medium` (0.5) | 100501, level 3 |
| `medium` | from `severity_medium` (0.5) to below `severity_high` (0.8) | 100502, level 7 |
| `high` | `severity_high` (0.8) and above | 100503, level 10 |

The bands are configurable and should be tuned per deployment. The defaults are not calibrated: the anomalies of the bundled resource-monitoring scenario reach a severity of about 0.45, so they arrive as rule 100501 (low) until the bands are lowered. A scenario's `detection.threshold` only decides which buckets are reported; it does not change their severity or band.

### Anomaly confidence

Every event carries `anomaly_confidence` (0–1), how far the scenario's anomalies can be trusted. It comes from the scenario's [`detection.anomaly_confidence`](./scenario-guide.md#anomaly_confidence), which should be set to the scenario's measured precision. When it is not set, SONAR sends 0.5 and logs at start-up:

```
detection.anomaly_confidence is not set: Wazuh events carry anomaly_confidence 0.5, which is not a measured value. Set it to the scenario's precision.
```

---

## SONAR event format

The `wazuh`, `jsonl` and `stdout` sinks emit the same event: one JSON object per anomalous bucket, on a single line. Shown indented here:

```json
{
  "integration": "sonar",
  "anomaly_grade": 0.62,
  "anomaly_confidence": 0.73,
  "sonar": {
    "anomaly_id": "5e0f6c2a…",
    "scenario": "brute_force",
    "model": "brute_force_detection",
    "bucket_start": "2026-01-06T15:30:00Z",
    "bucket_minutes": 5,
    "severity": 0.62,
    "severity_band": "medium",
    "score": 1.07,
    "top_contributors": [
      {"variable": "is_auth_failure", "contribution": 0.71, "value": 38.0},
      {"variable": "alert_count", "contribution": 0.18, "value": 52.0},
      {"variable": "rule.groups__authentication_failed", "contribution": 0.07, "value": 36.0}
    ]
  }
}
```

| Field | Description |
|-------|-------------|
| `integration` | Always `sonar`; rule 100500 matches on it |
| `anomaly_grade` | Severity of the bucket, 0–1 (MVAD's, or the `pca` or `ewma` backend's) |
| `anomaly_confidence` | The scenario's `detection.anomaly_confidence`, or 0.5 when it is not set |
| `sonar.anomaly_id` | Identity of the anomaly (scenario and bucket); the same id as in the data stream document |
| `sonar.scenario` | Scenario ID (`shipping.scenario_id`, or the model name in lower case) |
| `sonar.model` | Model name |
| `sonar.bucket_start` | Start of the anomalous bucket, UTC |
| `sonar.bucket_minutes` | Bucket size |
| `sonar.severity` | Same value as `anomaly_grade` |
| `sonar.severity_band` | `low`, `medium` or `high`, see [Severity bands](#severity-bands) |
| `sonar.score` | The backend's raw score (`mvad`: 0 to about 1.72; `pca` and `ewma`: a robust z-score) |
| `sonar.top_contributors` | Up to three variables that contributed most, with their contribution and their value in the bucket (`null` if unavailable); empty when MVAD returns no interpretation |

`NaN` values are written as `null`, because the manager's JSON decoder rejects `NaN`.

### The event in a Wazuh alert

Wazuh's JSON decoder places the event's fields under `data.*`, so an alert raised by rule 100503 looks like this in `wazuh-alerts-*` (abridged):

```json
{
  "rule": {"id": "100503", "level": 10, "groups": ["sonar", "anomaly"],
           "description": "SONAR: high-severity anomaly in scenario brute_force (severity 0.86)"},
  "decoder": {"name": "json"},
  "data": {
    "integration": "sonar",
    "anomaly_grade": "0.86",
    "anomaly_confidence": "0.73",
    "sonar": {"scenario": "brute_force", "severity_band": "high", "...": "..."}
  }
}
```

The decoder stores scalar values as strings, as for any JSON log. `data.anomaly_grade` and `data.anomaly_confidence` are the fields RADAR reads (it converts them to numbers) for anomaly-detection scenarios, so a SONAR alert can drive a RADAR active response through RADAR's `ar.yaml` alone, without code changes. That wiring is not part of SONAR's configuration.

### Feedback-loop guard

SONAR's own alerts land in `wazuh-alerts-*`, the indices SONAR learns from. To keep it from training on or detecting its own output, every alert search leaves out alerts whose `rule.groups` contain one of `wazuh.exclude_rule_groups` (default `["sonar"]`, the group of rules 100500–100519). Keep your per-scenario rules in the `sonar` group so they are excluded too. `exclude_rule_groups: []` disables the guard.

---

## The datastream sink

The `datastream` sink writes the full anomaly document to the scenario's data stream in the Wazuh Indexer, for dashboards, history and OpenSearch alerting monitors. It uses the same `wazuh:` connection settings as alert search (`base_url`, credentials, `verify_ssl`, `timeout_seconds`).

Enable it with `output.sinks: [wazuh, datastream]`, or with `--ship` / `shipping.enabled: true`, which add it to the configured sinks.

### Stream name

The stream is `sonar_anomalies_mvad_<scenario_id>`, whatever the detector backend. The scenario ID is `shipping.scenario_id` when set, otherwise the model name in lower case with characters outside `[a-z0-9_-]` replaced by `_`, which changes whenever the model name does. Set `shipping.scenario_id` for a stable name (the bundled scenarios do); see [The scenario ID](./model-naming-guide.md#the-scenario-id). With `--agent NAME`, the scenario ID (explicit or derived) gets the suffix `-<agent>` (the agent name, made safe the same way), so each host has its own stream, watermarks and anomaly IDs.

### Templates and retention

Train once with the data stream enabled before the first detection run: after training, SONAR installs (when `shipping.install_templates` is true) the index templates and the ISM policy, and creates the scenario's template. OpenSearch creates the stream itself when the first anomaly is written.

```
sonar_stream_template                     priority 1, pattern sonar_anomalies_*
sonar_stream_template_mvad                priority 2, pattern sonar_anomalies_*
  └── composed of component_template_sonar_mvad
sonar_stream_template_mvad_<scenario_id>  priority 3, pattern sonar_anomalies_mvad_<scenario_id>
  └── composed of component_template_sonar_mvad
```

OpenSearch applies the highest-priority template whose pattern matches. The scenario template's pattern is the exact stream name, so the scenario's stream gets it; a stream without one gets `sonar_stream_template_mvad`. The MVAD component is re-installed every time the templates are installed, and mapping changes apply from the next backing index of an existing stream.

The ISM policy `sonar_anomalies_policy` attaches itself, through its `ism_template`, to every new backing index of a SONAR stream (`.ds-sonar_anomalies_*`). It rolls the write index over after `shipping.rollover_days` (default 7) and deletes backing indices after `shipping.retention_days` (default 30):

```yaml
shipping:
  install_templates: true
  scenario_id: "brute_force"
  rollover_days: 7
  retention_days: 30
```

An existing policy is left unchanged, so changing these settings later has no effect until you delete the policy (`DELETE _plugins/_ism/policies/sonar_anomalies_policy`) and train again. Backing indices created before the policy existed are not managed by it; attach the policy to them by hand if needed.

### Document structure

Each document is created with a bulk `create` action under its `anomaly_id`, so a document the stream already holds is refused (HTTP 409) and counted as delivered. A document from a `sonar scenario` run:

```json
{
  "anomaly_id": "5e0f6c2a…",
  "@timestamp": "2026-01-06T15:30:00+00:00",
  "timestamp": "2026-01-06T15:30:00+00:00",
  "is_anomaly": true,
  "anomaly_score": 0.62,
  "anomaly_confidence": 0.73,
  "threshold": 0.2,
  "scenario_name": "brute_force",
  "model_name": "brute_force_detection",
  "detection_timestamp": "2026-01-06T15:35:00+00:00",
  "alert_count": 450,
  "feature_count": 28,
  "mvad_score": 1.07,
  "mvad_severity": 0.62,
  "mvad_threshold": 0.2,
  "sliding_window": 200,
  "bucket_minutes": 5,
  "context": {
    "model_path": "/home/alab/soar/sonar/models/brute_force_detection",
    "feature_names": ["alert_count", "rule.level", "is_auth_failure", "…", "agent.id__other"],
    "training_samples": 2400
  },
  "data": {
    "mvad_score": 1.07,
    "mvad_severity": 0.62,
    "mvad_threshold": 0.2,
    "bucket_minutes": 5,
    "lookback_minutes": 1440
  },
  "mvad_interpretation": [
    {"variable": "is_auth_failure", "contribution": 0.71, "value": 38.0},
    {"variable": "alert_count", "contribution": 0.18, "value": 52.0},
    {"variable": "rule.groups__authentication_failed", "contribution": 0.07, "value": 36.0}
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `anomaly_id` | keyword | SHA-256 hex of `<scenario_id>\|<bucket start as UTC ISO 8601>`: the same scenario and bucket always give the same id |
| `@timestamp`, `timestamp` | date | Start of the anomalous bucket (the data stream uses `timestamp`) |
| `is_anomaly` | boolean | Always `true` |
| `anomaly_score` | float | Severity, 0–1 (same value as `mvad_severity`) |
| `anomaly_confidence` | float | The scenario's `detection.anomaly_confidence`, or 0.5 when it is not set |
| `threshold` | float or null | The scenario's minimum severity; `null` when none is set |
| `scenario_name` | keyword | The scenario ID |
| `model_name` | keyword | Model name (the model is `<models_dir>/<model_name>/`) |
| `detection_timestamp` | date | When detection ran |
| `alert_count` | integer | Alerts fetched for the run (scored window plus context) |
| `feature_count` | integer | Number of model feature columns |
| `mvad_score`, `mvad_severity`, `mvad_threshold` | float | The backend's raw score and severity, and the same value as `threshold`. For `mvad`: raw score 0 to about 1.72, severity = score / (e − 1). For `pca`: the robust z-score of the window's distance; for `ewma`: the bucket's largest robust z-score; severity as in [backend](./scenario-guide.md#backend). The names date from when MVAD was the only backend |
| `sliding_window`, `bucket_minutes` | integer | From the loaded model (`sliding_window` is 0 for `pca` and `ewma`) |
| `context` | object | `model_path` (the model directory), `feature_names` (all model columns), `training_samples` |
| `data` | object | Copies of the MVAD values plus `bucket_minutes` and `lookback_minutes` |
| `mvad_interpretation` | array | Present only when the backend reports contributors: the top three `{variable, contribution, value}` entries |

With the `mvad` backend, `mvad_score` is a mean over all feature columns, so columns that do not move dilute it. Apart from the values of the top contributors, documents carry no per-feature values.

### Querying the stream

```json
GET /sonar_anomalies_mvad_*/_search
{
  "query": {"range": {"anomaly_score": {"gte": 0.8}}},
  "sort": [{"timestamp": "desc"}]
}
```

`GET /sonar_anomalies_mvad_brute_force/_search` reads one scenario; `DELETE /_data_stream/sonar_anomalies_mvad_brute_force` deletes a stream and all its documents.

---

## The index sink

The `index` sink writes the full anomaly document to the plain index `wazuh.anomalies_index` (default `wazuh-anomalies-mvad`), the destination older SONAR versions used by default. Each document is created under its `anomaly_id` (`PUT /<index>/_create/<anomaly_id>`); a document already there counts as delivered. The sink stops at the first document the indexer rejects. Use it only if something still reads that index; for new deployments prefer `datastream`, which has templates and a retention policy.

---

## The jsonl and stdout sinks

`jsonl` appends the SONAR events to `output.jsonl_path` (default `anomalies.jsonl` in the SONAR home); `stdout` prints them. Both emit exactly the lines the `wazuh` sink sends, which makes them useful to check the events before connecting a manager:

```bash
# Debug run on local data: events on stdout, logs on stderr
poetry run sonar scenario --use-case sonar/scenarios/linux_resource_monitoring.yaml --debug > events.jsonl

# Dry run against the indexer: events in sonar/payloads/anomalies.jsonl (<SONAR home>/payloads), nothing delivered
poetry run sonar detect --scenario sonar/scenarios/brute_force_detection.yaml --dry-run
```

To keep a local copy in production, add `jsonl` to `output.sinks`: it has its own watermark like any other sink.

---

## Delivery, fallback and exit status

Each sink has its own delivery watermark per scenario, so every anomalous bucket reaches every sink once, even though overlapping detection windows find it again and again. A sink that failed receives the missed anomalies on the next run, while the sinks that accepted them are not sent them again. See [Delivery and the watermark](./scenario-guide.md#delivery-and-the-watermark) for the details and for how to re-deliver anomalies.

### Fallback

`output.fallback` (`datastream` or `index`) stores the anomalies a configured sink did not accept, so they are kept somewhere while that sink is down. For example, with the manager unreachable:

```yaml
output:
  sinks: [wazuh]
  fallback: datastream
```

- The fallback receives only rejected anomalies, and only when it is not one of the configured sinks itself.
- It has no watermark of its own; it relies on `anomaly_id` to store each anomaly once.
- The failed sink keeps its watermark and is offered the same anomalies on the next run, so they still reach the manager once it is back.
- The default is `none`. Earlier versions fell back to the plain anomalies index on their own; now nothing is written anywhere unless a fallback is configured.

### Exit status

A one-shot detection run (`sonar detect`, `sonar scenario` in `historical` or `batch` mode) exits with:

| Status | When |
|--------|------|
| 0 | The window was scored, and every sink that had anomalies accepted them, or at least one did (the failed sinks retry on the next run, with a warning naming them) |
| 1 | Every sink that had anomalies failed and no fallback took them all; or an error such as an unknown sink name, a missing model or a lost connection |
| 2 | Too little data to score anything |

In realtime mode a poll counts as failed under the conditions of status 1, and SONAR stops after `max_consecutive_failures` failed polls in a row.

---

## Troubleshooting

### No SONAR alerts in Wazuh

Work along the path an event takes:

1. **Did SONAR deliver?** Look for `wazuh: delivered N anomalies; watermark ...` in the log. `Found N anomalies.` followed by `... were delivered by an earlier run; skipping them` means the watermark says the buckets were already delivered.
2. **File transport: did the file grow?** `tail -n 1 /var/log/sonar/anomalies.json` on the manager (or the path the manager sees). Check that the `<localfile>` block is in `ossec.conf` with the manager's path, and that the manager was restarted after adding it. `grep sonar /var/ossec/logs/ossec.log` shows whether logcollector analyses the file.
3. **API transport: was the event accepted?** Errors such as `Wazuh API error (HTTP 401)` or `(HTTP 403)` point to the user or its role; see [Create the event:ingest API user](./setup-guide.md#create-the-eventingest-api-user).
4. **Do the rules exist?** `grep -l 100500 /var/ossec/etc/rules/*.xml` on the manager, or `GET /rules?rule_ids=100500` through the API. Without them the event is decoded but raises no alert.
5. **Is the alert written?** Rules 100500 and 100501 have level 3, the default `log_alert_level` of the manager. If your manager raises `log_alert_level`, low-band anomalies are not written to `alerts.json`. Check `/var/ossec/logs/alerts/alerts.json` for `"integration":"sonar"`.
6. **Test the decoding.** Paste one line of `anomalies.json` into `/var/ossec/bin/wazuh-logtest` on the manager: phase 2 should show the `json` decoder and phase 3 rule 100500 or one of its children.

### Every SONAR alert is "low"

Expected with the default bands for scenarios whose anomalies stay below 0.5, such as the bundled resource-monitoring scenario (about 0.45). Lower `output.wazuh.severity_medium` and `severity_high` to match your scenarios' severities. Raising a scenario's `detection.threshold` drops low-severity buckets but does not move the others into a higher band.

### Duplicate SONAR alerts

The manager cannot recognise a duplicate event; only the watermark prevents them. Duplicates appear when the watermark file was deleted or is unreadable (a warning says so), or when two SONAR processes run the same scenario with different `state_dir`s. Run one SONAR process per scenario, with a `state_dir` that survives restarts.

### Nothing in the data stream

- Check that `datastream` is among the sinks: the start-up line `Anomaly sinks: ...` lists them. Dry runs never write to it, and debug runs only when `datastream` is listed in `debug_sinks`.
- Check that the templates were installed: `GET /_index_template/sonar_stream_template_mvad_*`. Without a matching template, OpenSearch cannot create the data stream on the first write; train once with the data stream enabled.
- Check that training and detection use the same scenario ID (set `shipping.scenario_id`).
- `datastream: N of M anomalies not delivered (data stream unavailable: ...)` means the indexer could not be reached or refused the request; the connection uses the `wazuh:` settings, see [TLS certificate verification](./setup-guide.md#tls-certificate-verification).

See also [troubleshooting.md](./troubleshooting.md#delivery-issues).
