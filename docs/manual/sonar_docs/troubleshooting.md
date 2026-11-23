# SONAR troubleshooting guide

Solutions for common issues and errors in SONAR.

## Quick diagnostics

```bash
# 1. Check Wazuh connection
poetry run sonar check

# 2. Verify Python environment
poetry run python --version  # Should be 3.10.12

# 3. Check dependencies
poetry install --with sonar

# 4. Test with debug mode (packaged test data; works from any directory)
poetry run sonar scenario --use-case linux_resource_monitoring --debug
```

## Connection issues

### Error: Connection refused

```
ERROR: Failed to connect to Wazuh Indexer.
```

Every command pings the indexer before it reads anything. The ping returns false on any connection, TLS or authentication error, so `train`, `detect`, `scenario` and `export` log only this line, and `sonar check` logs `✗ Connection failed.`. The opensearch-py exception that names the cause is logged at debug level, which the CLI does not show: run the `curl` commands below to see it. An error after the connection was established (for example in a later realtime poll) is logged with its `opensearchpy.exceptions` traceback.

**Causes:**
- Wazuh/OpenSearch not running
- Incorrect URL in configuration
- Network/firewall issues

**Solutions:**

```bash
# 1. Check Wazuh is running
curl -u admin:admin https://localhost:9200/_cluster/health

# 2. Verify configuration
grep base_url sonar/default_config.yaml

# 3. Use debug mode for development (local test data)
poetry run sonar train --debug
```

### Error: SSL verification failed

```
ERROR: Failed to connect to Wazuh Indexer.
```

The same line as for [Connection refused](#error-connection-refused). `curl --cacert /path/to/root-ca.pem -u admin https://<indexer host>:9200/` shows the certificate error.

**Causes:**
- `verify_ssl: true` checks against the system trust store, which does not contain the Wazuh indexer's self-signed CA
- The CA bundle path in `verify_ssl` is not the CA that issued the indexer's certificate
- The host in `base_url` does not match the certificate: hostname verification is on whenever certificates are verified. Wazuh's default indexer certificate is issued for the indexer node's name, so connecting by IP address with verification on may fail

**Solutions:**

```yaml
wazuh:
  # 1. Verify against the Wazuh root CA (applies to alert search and the datastream and index sinks)
  verify_ssl: /path/to/root-ca.pem
  # 2. Use a host name the certificate was issued for
  base_url: "https://wazuh.indexer:9200"
```

For a lab indexer with a self-signed certificate you can turn verification off instead (`verify_ssl: false`, the default). See [TLS certificate verification](./setup-guide.md#tls-certificate-verification). The Wazuh server API (the `wazuh` sink's `api` transport) has its own setting, `output.wazuh.verify_ssl`.

### Error: Authentication failed

```
ERROR: Failed to connect to Wazuh Indexer.
```

The same line as for [Connection refused](#error-connection-refused); `curl` with the configured credentials returns HTTP 401.

**Solutions:**

```bash
# 1. Check credentials
grep -A2 "username" sonar/default_config.yaml

# 2. Test with curl
curl -u admin:admin https://localhost:9200/

# 3. Update configuration
vim my_config.yaml  # copy of sonar/default_config.yaml; pass it with --config
```

### Error: 403 on point-in-time

An `opensearchpy.exceptions.AuthorizationException` (403) whose reason names `indices:data/read/point_in_time/create` (or `.../delete`).

**Cause:** alert search pages through the alerts with a point-in-time, which the indexer user must be allowed to create and delete. Wazuh's `admin` user has these permissions; a restricted read-only role may not.

**Solution:** add `indices:data/read/point_in_time/create` and `indices:data/read/point_in_time/delete` to the role of the user in `wazuh.username`, on the `wazuh-alerts-*` indices (or your `alerts_index_pattern`).

## Training issues

### Error: No alerts found

```
ERROR: No alerts with a valid timestamp in the training window; nothing to train on.
```

**Causes:**
- Time range too narrow
- Query filter too restrictive
- No matching alerts in Wazuh

**Solutions:**

```bash
# 1. Extend lookback period
poetry run sonar train --lookback-hours 336  # 2 weeks instead of the default 168 h

# 2. Check alert count in Wazuh
curl -u admin:admin "https://localhost:9200/wazuh-alerts-*/_count"

# 3. Remove or adjust alert_filter under training: in scenario
```

**Scenario fix:**

```yaml
training:
  lookback_hours: 168  # Increase from 24
  # Remove or simplify restrictive alert_filter temporarily
```

### Error: MVAD cannot train on N time buckets

```
ERROR: MVAD cannot train on 288 time buckets with sliding_window=200: 13 training windows (stride interval=10) fill no batch of batch_size=128; the validation split is shorter than the input window (100 buckets). At least 1725 buckets are needed with these settings. Increase lookback_hours, decrease bucket_minutes or sliding_window, or lower batch_size/interval in extra_params.
```

**Cause:** With these settings the MVAD library would not perform a single training update (or would have no validation data to pick a checkpoint with), so it would save a random network. SONAR refuses to train, saves nothing and exits with status 1.

**Solutions** (see [Training data size](./scenario-guide.md#training-data-size)):

```yaml
training:
  extra_params:
    interval: 1        # 10x more training windows from the same data
  lookback_hours: 168  # Cover more buckets
  # OR
  sliding_window: 96   # Smaller windows need less data
```

### Warning: only N gradient steps

```
WARNING: MVAD will perform only 100 gradient steps (1 batches/epoch x 100 epochs), below min_gradient_steps=500.
```

**Cause:** Training runs, but with few updates the model may be undertrained. Apply the same solutions as above, or lower `min_gradient_steps` if you accept it.

### Warning: Model records 0 gradient steps

```
WARNING: Model /home/alab/soar/sonar/models/x records 0 gradient steps: it is untrained. Retrain it.
```

The MVAD model never received a training update, so its scores mean nothing. Retrain it with more history (see [Error: MVAD cannot train on N time buckets](#error-mvad-cannot-train-on-n-time-buckets)).

### Warning: Insufficient data for detection

```
WARNING: Insufficient data for detection: 150 time buckets, the model needs at least 200 (sliding_window 200). The alerts start too late in the window.
```

Nothing is scored, and a one-shot run (`sonar detect`, or `sonar scenario` in `historical` or `batch` mode) exits with status 2; realtime mode keeps polling. `No alerts in the detection window` has the same effect.

`lookback_minutes` only sets the window to score; SONAR fetches the `input_size + threshold_window − 1` buckets of context the model needs before it on its own. Against a live indexer, the feature grid covers the whole fetched range, and buckets without alerts count as silence, so this warning is rare there; a fresh installation with little history is scored against a mostly empty context instead. In `--debug` mode the time range is ignored, and the message means the local detection file is shorter than the model needs: at least `input_size + threshold_window` buckets (200 for `sliding_window: 200`).

### Error: model built with feature schema N

```
ERROR: Model /home/alab/soar/sonar/models/brute_force was built with feature schema 1, but this SONAR builds schema 2 features. Retrain the model with SONAR <version> or later.
```

`<version>` is the installed SONAR's version.

**Cause:** the model was trained by an older SONAR whose features (columns and their meaning) differ. Applying it to today's features would give meaningless scores, so SONAR refuses to load it. A model directory with another `format_version` is refused the same way.

**Solution:** retrain with the current SONAR, for example `poetry run sonar train --scenario my_scenario.yaml`, or `sonar scenario` with a `training:` section.

### Error: model in the old pickle format

```
ERROR: /home/alab/soar/sonar/models/brute_force_v1.pkl is a model in the old pickle format, which SONAR <version> no longer loads (unpickling can run code). Retrain the model; it will be saved as /home/alab/soar/sonar/models/brute_force_v1/.
```

`<version>` is the installed SONAR's version.

**Cause:** models are now directories holding JSON and plain tensor files (see [Model file format](./model-naming-guide.md#model-file-format)). SONAR does not unpickle or convert the old single-file models.

**Solution:** retrain under the same name with the current SONAR, then delete the `.pkl` file.

### Warning: feature settings differ from those the model was trained with

```
WARNING: Feature settings ['categorical_fields'] differ from those model /home/alab/soar/sonar/models/x was trained with; detection uses the model's. Retrain to apply the new settings.
```

**Cause:** the scenario's `training:` feature settings changed after the model was trained. Detection always builds the features the model was trained on, from the settings and categorical vocabulary stored in the model.

**Solution:** retrain to apply the new settings, or ignore the warning to keep using the model as trained.

### Error: Detection features do not match the model's training columns

**Cause:** a bug, because detection builds its features from the model's stored settings and vocabulary. Report it with the log, which names the missing and extra columns.

### Issue: Query filter returns no results

```
INFO: Fetched 0 of 0 matching alerts.
INFO: Retrieved 0 alerts.
ERROR: No alerts with a valid timestamp in the training window; nothing to train on.
```

Detection logs `WARNING: No alerts in the detection window; nothing to score.` instead of the last line.

**Cause**: OpenSearch `alert_filter` in scenario's `training:` section (or `features:` in a `--config` file) is too restrictive. `--debug` runs ignore it.

**Solutions**:

```yaml
# 1. Test the query filter directly in OpenSearch
# Use Wazuh Dev Tools or curl:
GET wazuh-alerts-*/_search
{
  "query": {
    "bool": {
      "must": [{"match": {"rule.groups": "authentication"}}]
    }
  },
  "size": 0
}
# Check "hits.total.value" - should be > 0

# 2. Simplify filter temporarily
training:
  alert_filter:
    match_all: {}  # Remove all filters to test

# 3. Use should instead of must for broader matching
training:
  alert_filter:
    bool:
      should:  # At least one must match (OR logic)
        - match: {"rule.groups": "authentication"}
        - match: {"rule.groups": "sudo"}
      minimum_should_match: 1

# 4. Check field names match your alert structure
# View sample alert:
GET wazuh-alerts-*/_search
{"size": 1, "sort": [{"@timestamp": "desc"}]}
```

### Warning: only the most recent alerts were fetched

```
WARNING: The alert search matched 2500000 alerts; only the 2000000 most recent were fetched (wazuh.max_alerts). Shorten the lookback or raise max_alerts.
```

**Cause:** the window holds more alerts than `wazuh.max_alerts` (default 2,000,000). SONAR keeps the most recent ones, so the oldest part of the window is missing from the features: training then learns from a shorter period than `lookback_hours`.

**Solutions:**
- Shorten the lookback
- Narrow the alerts with `alert_filter`
- Raise `wazuh.max_alerts`: every fetched alert is held in memory, although only the fields the features read are fetched

### Error: Memory exhausted

```
MemoryError: Unable to allocate array
```

**Causes:**
- Too many features (high cardinality categorical fields)
- Large sliding window with high-frequency buckets

**Solutions:**

```yaml
training:
  # Reduce categorical feature cardinality
  categorical_top_k: 5  # Reduce from 10

  # Use fewer categorical fields
  categorical_fields:
    - "agent.id"  # Remove others temporarily

  # Increase bucket size
  bucket_minutes: 10  # Increase from 5

  # Reduce sliding window
  sliding_window: 100  # Reduce from 200
```

### Issue: Training replaced an existing model

**Intended.** A model is the directory `<models_dir>/<model_name>/`, and a scenario without `model_name` always uses the same name (its `name` in lower case), so training again replaces the model. The new model is written to a staging directory first and swapped in only when complete, so a failed training run keeps the old one.

To keep previous versions, train under a new name:

```yaml
# In the scenario
model_name: "my_model_v2"

# Or per environment
model_name: "brute_force_production"
```

or pass `--model-name my_model_v2` to `sonar train`. Set `shipping.scenario_id` as well, so that a new model name does not start new watermarks (see [The scenario ID](./model-naming-guide.md#the-scenario-id)).

### Issue: A debug run sends nothing to Wazuh

**Cause**: Intended. With `--debug`, or `debug.enabled: true` in YAML, anomalies go to `output.debug_sinks` (by default `stdout`) instead of the configured sinks, and the delivery watermarks are neither read nor moved. The SONAR events appear on standard output, one JSON object per line; the logs go to standard error. `--ship` has no effect in debug runs, and training with `--debug` does not install the data stream templates. To send a debug run's anomalies to a lab manager, set `output.debug_sinks: [wazuh]` (any sink but `index` is allowed); without a watermark, every debug run sends them again.

**Solutions**:

```bash
# 1. To deliver to Wazuh, run without --debug (and without debug.enabled: true)
poetry run sonar scenario --use-case sonar/scenarios/my_scenario.yaml

# 2. To inspect the events of a real run without delivering them, use a dry run:
#    the events go to <payload-dir>/anomalies.jsonl (default sonar/payloads/) and the watermarks are not used
poetry run sonar detect --scenario sonar/scenarios/my_scenario.yaml --dry-run --payload-dir ./payloads
```

`--dry-run` does not affect training: `train --ship` still connects to the indexer and installs the index templates.

### Info: Fewer feature columns than expected (derived_features)

Every configured column is always present, so the column count depends only on the configuration and the categorical vocabulary. The `Feature matrix:` log line breaks it down:

```
INFO: Feature matrix: 2016 buckets x 24 columns (1 numeric, 0 max, 6 derived, 16 categorical), 310 empty buckets
```

**Possible causes**:
1. `derived_features` is `false` or a short list. In a scenario it belongs in the `training:` section; in a `--config` file, under `features:`.
2. A categorical field had few distinct values in the training alerts, so its vocabulary is small. Each field always has a `<field>__other` column.

A derived feature whose condition never holds is a column of zeros. Derived features count alerts per bucket (for example `is_brute_force` counts alerts whose `rule.groups` contain `brute_force`).

```bash
poetry run sonar scenario --use-case my_scenario.yaml 2>&1 | grep -i "feature matrix"
```

## Detection issues

### Error: Model not found

```
ERROR: Model not found at /home/alab/soar/sonar/models/sonar. Train first, or add a training section to the scenario.
```

**Cause:** Detection requires a trained model, at `<models_dir>/<model_name>/` (the path in the message).

**Solutions:**

```bash
# 1. Train model first
poetry run sonar train --lookback-hours 168

# 2. Or use scenario with training section
poetry run sonar scenario --use-case sonar/scenarios/brute_force_detection.yaml

# 3. Check which models exist (each is a directory with a metadata.json)
ls -l sonar/models/
```

Training and detection find the same model when they use the same model name and models directory: the same scenario (its `model_name`, else its `name`), or configuration files with the same `model_name` and `models_dir`, and the same `SONAR_HOME`. A model trained with `sonar train --model-name NAME` is found by `detect` only through a scenario or configuration that names it `NAME`. See [Model names](./model-naming-guide.md#model-names).

The same holds for `--agent HOST`: a model trained with it is `<model name>-HOST`, so detect with the same `--agent`, and a fleet-wide model is not found by a run with `--agent`.

### Error: No anomalies detected

```
INFO: No anomalies detected.
```

**Not an error** - means no anomalous patterns detected.

**If unexpected:**

- Check the exit status and the log: status 2 with an `Insufficient data for detection` or `No alerts in the detection window` warning means nothing was scored (see above).
- Check `threshold` and `min_consecutive`: a bucket is reported only if MVAD flags it, its severity (0–1) is at least `threshold` when one is set, and it belongs to a run of at least `min_consecutive` flagged buckets. Set `threshold: null` and lower `min_consecutive` to report every bucket MVAD flags.
- Check the feature list: MVAD's raw score is a mean over all feature columns, so many columns unrelated to the attack dilute it. Focus `numeric_fields` and `derived_features` on the use case.

```yaml
detection:
  lookback_minutes: 1440  # window to score; context is fetched automatically
  threshold: null
  min_consecutive: 1
```

### Issue: All or most buckets reported as anomalies

`Found N anomalies.` reports nearly every scored bucket.

**Causes:**
- Model not properly trained
- Data distribution mismatch (for example, the environment changed since training: retrain on recent history)

**Solutions:**

```bash
# 1. Retrain with more data
poetry run sonar train --lookback-hours 168

# 2. Check the pipeline with known-good test data
poetry run sonar scenario --use-case linux_resource_monitoring --debug
```

If the model itself looks sound, raise `threshold` or `min_consecutive` in the scenario's `detection:` section to report only stronger or sustained anomalies. Plain `sonar detect` without `--scenario` applies neither.

### Error: Detection failed N times in a row; stopping

```
WARNING: Detection poll failed (1 of 5 allowed in a row); retrying in 10 seconds.
ERROR: Detection failed 5 times in a row; stopping.
```

Realtime mode retries a failed poll after 10 s, doubling the wait per failure up to one bucket, and exits with status 1 after `max_consecutive_failures` failures in a row. Look at the errors logged before these lines for the cause. A poll with too little data is not a failure. See [Realtime mode](scenario-guide.md#realtime-mode).

## Delivery issues

See also the troubleshooting section of the [anomaly output guide](./data-shipping-guide.md#troubleshooting).

### Error: unknown sink

```
ValueError: unknown sink 'wazhu'; choose from wazuh, datastream, index, jsonl, stdout
```

An unknown name in `output.sinks` or `output.debug_sinks`, an `output.fallback` other than `none`, `datastream` or `index`, or an `output.wazuh.transport` other than `file` or `api` stops detection with status 1 when it starts, before it reads any alerts; `sonar scenario` checks the names before its training phase. Fix the name in the config or scenario.

### Info: Anomalies found but not delivered again

```
INFO: Found 3 anomalies.
INFO: wazuh: 3 anomalies at or before 2026-01-25T10:15:00+00:00 were delivered by an earlier run; skipping them.
```

**Not an error.** An earlier run already delivered these buckets to that sink, and the scenario's watermark file (`<state_dir>/<scenario_id>.json`) records it. To deliver them again, delete the file, or remove that sink's entry from it. See [Delivery and the watermark](scenario-guide.md#delivery-and-the-watermark).

### Error: anomalies not delivered

```
ERROR: wazuh: 3 of 3 anomalies not delivered (cannot write /var/log/sonar/anomalies.json: [Errno 13] Permission denied: ...); the next run offers them again.
WARNING: Sinks wazuh failed; the others accepted the anomalies.
```

A sink did not accept some anomalies. Its watermark stays at the last anomaly it accepted, so the next run (or realtime poll) offers it the rest; the sinks that accepted them are not sent them again. When at least one sink accepted, the run exits with status 0 and logs the warning. When every sink that had anomalies failed, and no fallback stored them, it logs `No sink accepted the anomalies (...)` and exits with status 1.

The text in parentheses gives the cause:

| Message | Cause | Solution |
|---------|-------|----------|
| `cannot write /var/log/sonar/anomalies.json: ... Permission denied` | The SONAR user cannot write the `file` transport's directory | `sudo install -d -o <sonar user> -g <sonar group> /var/log/sonar`; in Docker, `/srv/sonar/anomalies` owned by uid 1000 |
| `cannot write ...: No such file or directory` / `Read-only file system` | The directory cannot be created or is mounted read-only in the SONAR container | Mount the anomaly directory read-write into SONAR (read-only only into the manager) |
| `Wazuh API error (HTTP 0): cannot reach ...` | The API is not reachable | Check `output.wazuh.api_url`, port 55000 and firewalls |
| `Wazuh API error (HTTP 401): authentication of user 'sonar' failed` | Wrong user or password | Check `api_username` and `SONAR_WAZUH_API_PASSWORD` (or `api_password`) |
| `Wazuh API error (HTTP 403): ...` | The user's role does not allow `event:ingest` | See [Create the event:ingest API user](./setup-guide.md#create-the-eventingest-api-user) |
| `Wazuh API error (HTTP 429): ...` | Rate limit still exceeded after three retries | The next run retries; raise the API's request limit if it persists |
| `the manager rejected N of M events: ...` | `POST /events` reported failed items | See the listed failures; the events before them were accepted |
| `data stream unavailable: ...` | The indexer could not be reached or refused the bulk request | Check the `wazuh:` connection settings |
| `anomalies index: ...` | The indexer refused a document of the `index` sink | Check the indexer connection, permissions and disk space |

A warning `No Wazuh API password: set output.wazuh.api_password or SONAR_WAZUH_API_PASSWORD.` at start-up announces the 401 errors.

SSL errors from the API transport (`certificate verify failed`) mean `output.wazuh.verify_ssl` does not point at the CA that issued the API certificate; the manager's default API certificate is self-signed.

### Warning: anomaly_confidence is not set

```
WARNING: detection.anomaly_confidence is not set: Wazuh events carry anomaly_confidence 0.5, which is not a measured value. Set it to the scenario's precision.
```

The scenario has no `detection.anomaly_confidence`, so the events carry 0.5. Set it to the scenario's measured precision once you have one; see [anomaly_confidence](./scenario-guide.md#anomaly_confidence).

### Issue: No SONAR alerts in Wazuh although SONAR delivered

SONAR logs `wazuh: delivered N anomalies`, but no alert with rule group `sonar` appears. Check, on the manager:

- The rules are installed (`grep -l 100500 /var/ossec/etc/rules/*.xml`) and the manager was restarted afterwards.
- `file` transport: the `<localfile>` block is in `ossec.conf` with the path the manager sees, and `grep anomalies.json /var/ossec/logs/ossec.log` shows logcollector analysing the file. Logcollector reads lines added after it opened the file; events appended while the manager was stopped may not be read, depending on the `<localfile>` options of your Wazuh version.
- The event decodes: paste a line of the file into `/var/ossec/bin/wazuh-logtest`.
- `log_alert_level` in `ossec.conf` is at most 3, or low-band anomalies (rule 100501, level 3) are not written as alerts.

See [No SONAR alerts in Wazuh](./data-shipping-guide.md#no-sonar-alerts-in-wazuh) for the full checklist.

### Error: Installing the rules failed

```
ERROR: Installing the rules failed: Wazuh API error (HTTP 403): ...
```

`sonar wazuh install-rules` needs a user allowed `rules:update` (and `manager:restart` with `--restart`), such as `wazuh-wui`; the `event:ingest` user is not. Pass `--user` and give its password in `SONAR_WAZUH_ADMIN_PASSWORD` or at the prompt. HTTP 400 usually means the manager rejected the file; check `/var/ossec/logs/ossec.log`.

### Issue: SONAR alerts used as training data

SONAR leaves out alerts in the rule groups of `wazuh.exclude_rule_groups` (default `["sonar"]`). If your own SONAR rules use other groups, or `exclude_rule_groups` is `[]`, SONAR can learn from and detect on its own alerts. Keep every SONAR rule in the `sonar` group.

## Export and comparison issues

### Warning: The window holds no alerts (sonar export)

```
WARNING: The window holds no alerts: check the scenario's index (wazuh.alerts_index_pattern), alert_filter and --agent.
```

`sonar export` exits with 2 and writes empty files.

**Causes and solutions:**

- **RADAR's resource events are not indexed.** `radar_linux_resource_utilization` reads `wazuh-archives-*`. The collector's events match no rule, so they are only there when the manager logs every event (`logall_json`) and Filebeat ships the archives; RADAR's scenario deployment turns both on. Check in Discover for `predecoder.program_name: resource_usage_metric`.
- **The agent name is wrong.** `--agent` must equal the alert's `agent.name` exactly (case included).
- **The window is before the data.** `--start` and `--end` without an offset are UTC.

### Issue: radar_results.json is empty

- The result index pattern does not match: RADAR's `linux_resource_utilization` detector writes to `opensearch-ad-plugin-result-linux-resource-utilization`; pass it with a trailing `*` to include its rolled-over indices.
- RADAR's detector was not running over the window: its results start once it has initialised.
- With `--agent`, the results are filtered on the plugin's `entity` field, a `nested` list of `{name, value}`. If your result index maps `entity` otherwise (`flatten_custom_result_index`), export without `--agent` and filter the results by hand.
- The indexer user needs read access to the result index.

See the [RADAR comparison guide](./radar-comparison-guide.md).

## Data quality issues

### Issue: Timestamps without a timezone

Timestamps without timezone information (for example `2025-12-29T10:00:00`) are accepted and treated as UTC. If your source writes local time without an offset, buckets will be shifted. Prefer ISO 8601 with an explicit offset:

```json
{"timestamp": "2025-12-29T10:00:00.000Z"}
```

Note that alerts must carry the `timestamp` field (not only `@timestamp`).

For test data, use proper format:

```python
from datetime import datetime, timezone
timestamp = datetime.now(timezone.utc).isoformat()
```

### Issue: Numeric field missing from some alerts

**Not an error**, and nothing is logged. A numeric field is averaged only over the alerts in the bucket that carry it, so alerts without it do not pull the mean towards 0. In a bucket where no alert carries the field, the column holds the [`numeric_fill`](./scenario-guide.md#numeric_fill) value:

```yaml
training:
  numeric_fields:
    - "data.cpu_usage_%"
  numeric_fill: ffill  # gauge metrics: carry the last reading forward ("zero", the default, writes 0)
```

### Issue: Text field listed as numeric

**Cause:** a field in `numeric_fields` holds text (for example `rule.description`). No error is raised: values that are not numbers are read as missing, so the column holds only the `numeric_fill` value (0 by default) and carries no information.

**Solution:**

```yaml
training:
  numeric_fields:
    - "rule.level"  # Numeric
    # - "rule.description"  # Remove - this is text

  categorical_fields:
    - "rule.description"  # Use as categorical instead (if needed)
```

## Configuration issues

### Error: Configuration file not found

```
FileNotFoundError: [Errno 2] No such file or directory: 'my_config.yaml'
ValueError: Use case file not found: my_scenario.yaml
```

The first line ends the traceback of a missing `--config` file, the second one of a missing `--scenario` or `--use-case` file (a name that is neither a file nor a [packaged example](./scenario-guide.md#overview)). A `--config`, `--scenario` or `--use-case` path on the command line is relative to the current directory. Paths inside those files are relative to the file itself.

**Solutions:**

```bash
# 1. Check working directory
pwd

# 2. Use absolute path
poetry run sonar train --config /home/alab/soar/sonar/default_config.yaml

# 3. Create configuration
cp sonar/default_config.yaml my_config.yaml
```

### Error: Invalid YAML syntax

```
yaml.scanner.ScannerError: mapping values are not allowed here
```

**Cause:** YAML syntax error.

**Common mistakes:**

```yaml
# Incorrect indentation
training:
numeric_fields:
  - "rule.level"

# Correct indentation
training:
  numeric_fields:
    - "rule.level"

# Missing quotes around special characters
training:
  alert_filter:
    match: {rule.groups: web}

# Quotes around field names
training:
  alert_filter:
    match: {"rule.groups": "web"}
```

**Validation:**

```bash
# Check YAML syntax
poetry run python -c "import yaml; yaml.safe_load(open('scenario.yaml'))"
```

### Issue: Scenario fields ignored

`name` and `description` are optional (defaults `unnamed_scenario` and empty). Unknown keys are ignored with a warning such as `unknown key 'min_samples' in training section is ignored`, so check the log and the spelling against [scenario-guide.md](./scenario-guide.md). An unknown key in `extra_params` is an error.

**Minimal valid scenario:**

```yaml
name: "My Scenario"
model_name: "my_scenario"  # optional: defaults to the name, slugged (my_scenario)
training:
  lookback_hours: 168
```

## Performance issues

### Issue: Training takes too long

**Causes:**
- Large sliding window
- Many features
- Large dataset

**Solutions:**

```yaml
training:
  sliding_window: 100  # Reduce from 300
  bucket_minutes: 10   # Increase from 5
  categorical_top_k: 5  # Reduce from 10
```

**Benchmark:** Training should complete in < 5 minutes for typical workloads.

### Issue: High memory usage

See [Error: Memory exhausted](#error-memory-exhausted) for parameter tuning.

**Monitor:**

```bash
# Watch memory during training
watch -n 1 'ps aux | grep sonar'
```

## Debug mode issues

### Error: Test data file not found

```
ERROR: Failed to load local data: Data file does not exist: /home/alab/soar/sonar/test_data/synthetic_alerts/normal_baseline.json
```

A missing directory gives `Data directory does not exist: <data_dir>` instead.

**Solutions:**

```bash
# 1. Check file exists
ls sonar/test_data/synthetic_alerts/

# 2. Restore the packaged files (they are committed, not generated)
git checkout -- sonar/test_data/synthetic_alerts/

# 3. Fix debug.data_dir: a relative value is relative to the scenario or
#    config file that sets it, e.g. for a scenario in sonar/scenarios/:
#    debug:
#      data_dir: "../test_data/synthetic_alerts"
#    Without data_dir, SONAR reads the packaged sonar/test_data/synthetic_alerts.
```

The error names the full path SONAR tried. A copy of `default_config.yaml` placed in another directory keeps the line `data_dir: "test_data/synthetic_alerts"`, which is then relative to the copy: remove it.

### Error: Test data has wrong format

```
ERROR: Failed to parse JSON in /path/to/test_data.json: Expecting value: line 1 column 1 (char 0)
WARNING: Unexpected JSON type in /path/to/test_data.json: <class 'str'>
```

**Cause:** Invalid JSON, or a JSON value that is neither an object nor an array. SONAR skips the file and continues with the other files, so the run then usually stops for lack of alerts.

`LocalDataProvider` supports three formats automatically:

```json
// Format 1: JSON array (recommended)
[
  {"timestamp": "...", "rule": {...}},
  {"timestamp": "...", "rule": {...}}
]

// Format 2: Single object — also supported natively
{"timestamp": "...", "rule": {...}}

// Format 3: OpenSearch API response
{"hits": {"hits": [{"_source": {"timestamp": "...", "rule": {...}}}]}}
```

**Fix**: check the file's syntax and structure:

```bash
# 1. Validate JSON syntax
jq . test_data.json  # Should pretty-print without errors

# 2. Inspect the structure
cat test_data.json | python3 -c "import json,sys; d=json.load(sys.stdin); print(type(d))"
```

## Getting help

### Logging level

The `sonar` CLI logs at a fixed `INFO` level. There is no `--verbose` flag or `LOG_LEVEL` environment variable. Capture the full output to a file instead:

```bash
poetry run sonar train --lookback-hours 168 2>&1 | tee sonar.log
```

### Collect diagnostic information

```bash
# 1. System info
python --version
poetry --version
uname -a

# 2. SONAR version
cd /home/alab/soar
git log -1 --oneline sonar/

# 3. Configuration (redact the password before sharing)
cat sonar/default_config.yaml

# 4. Recent errors (debug mode)
poetry run sonar scenario --use-case linux_resource_monitoring --debug 2>&1 | tee debug.log
```

### Check test suite

```bash
# Run all tests
poetry run pytest tests/sonartests/ -v

# Run specific test
poetry run pytest tests/sonartests/test_engine_and_features.py -v

# Check for regressions
poetry run pytest tests/sonartests/ --tb=short
```

### Common log messages

**Normal:**
```
INFO: Retrieved 1234 alerts.
INFO: Feature matrix: 2016 buckets x 24 columns (1 numeric, 0 max, 6 derived, 16 categorical), 310 empty buckets
INFO: Fitting MVAD on 2016 time buckets: 1512 training windows, 11 batches/epoch x 100 epochs = 1100 gradient steps, 101 validation windows
INFO: ✓ Model trained and saved to <models_dir>/<model_name>
INFO: Scored 288 buckets.
INFO: Found 3 anomalies.
INFO: wazuh: delivered 3 anomalies; watermark 2026-01-25T10:15:00+00:00.
INFO: No anomalies detected.
```

**Warning (non-fatal):**
```
WARNING: <file>: unknown key 'min_samples' in training section is ignored
WARNING: MVAD will perform only 100 gradient steps (1 batches/epoch x 100 epochs), below min_gradient_steps=500. ...
WARNING: detection.anomaly_confidence is not set: Wazuh events carry anomaly_confidence 0.5, which is not a measured value. Set it to the scenario's precision.
WARNING: No alerts in the detection window; nothing to score.
WARNING: Insufficient data for detection: 150 time buckets, the model needs at least 200 (sliding_window 200). ...
```

**Error (requires action):**
```
ERROR: Failed to connect to Wazuh Indexer.
ERROR: No alerts with a valid timestamp in the training window; nothing to train on.
ERROR: Model not found at <models_dir>/<model_name>. Train first, or add a training section to the scenario.
ERROR: No sink accepted the anomalies (wazuh).
```

## Still stuck?

1. Check [setup-guide.md](./setup-guide.md) for installation verification
2. Review [scenario-guide.md](./scenario-guide.md) for usage patterns
3. See [architecture.md](./architecture.md) for system design
4. Examine test files in `tests/` for working examples
5. Run with debug mode: `--debug` flag uses local test data

## Known limitations

1. **Python version**: Requires exactly 3.10.12 (specified in pyproject.toml)
2. **MVAD device**: CPU only (GPU support available but not tested)
3. **Time bucket alignment**: Buckets aligned to epoch, not query time
4. **Categorical encoding**: High cardinality fields can cause memory issues
5. **Realtime mode**: Polling-based, not push-based; by default one poll per bucket, `ingest_delay_seconds` after the bucket ends. A fixed `polling_interval_seconds` has no enforced minimum
6. **Thresholds**: `threshold` and `min_consecutive` only filter the backend's own anomalies; they cannot flag a bucket the backend did not flag

## Error reference

| Error | Cause | Solution |
|-------|-------|----------|
| `Failed to connect to Wazuh Indexer.` (curl: connection refused) | Wazuh not running | Start Wazuh or use `--debug` |
| `Failed to connect to Wazuh Indexer.` (curl: 401 Unauthorized) | Wrong credentials | Update config credentials |
| `Failed to connect to Wazuh Indexer.` (curl: certificate error) | Self-signed cert, wrong CA, or `base_url` host not in the certificate | Set `verify_ssl` to the Wazuh root CA path and connect by the certificate's host name, or `verify_ssl: false` in a lab |
| 403 on `point_in_time` | Indexer role cannot create or delete a point-in-time | Grant `indices:data/read/point_in_time/create` and `/delete` |
| Only the N most recent alerts were fetched | More alerts than `wazuh.max_alerts` | Shorten the lookback or raise `max_alerts` |
| No alerts found | Empty time range | Extend `lookback_hours` |
| Model not found | No model at `<models_dir>/<model_name>/` | Train first, with the same model name and `SONAR_HOME` |
| Model built with feature schema N | Model trained by an older SONAR | Retrain |
| Model in the old pickle format | `.pkl` model from an older SONAR | Retrain |
| Feature settings differ warning | Scenario changed after training | Retrain to apply them |
| Unknown sink, fallback or transport (exit 1 before training or detection) | Typo in `output` | Use the names listed in the error |
| `N of M anomalies not delivered` | A sink is unreachable or refused them | See [Delivery issues](#delivery-issues); the sink retries on the next run |
| HTTP 401 / 403 from the Wazuh API | Wrong password, or the role lacks `event:ingest` | Fix the user; see [Create the event:ingest API user](./setup-guide.md#create-the-eventingest-api-user) |
| Insufficient data for detection (exit 2) | Fewer buckets than the model needs (usually a short `--debug` data file) | Use a longer data file, or a model with a smaller `sliding_window` |
| Memory error | Too many features | Reduce `categorical_top_k` |
| Shifted buckets | Timestamps without timezone (read as UTC) | Use ISO 8601 with an offset |
| YAML syntax error | Malformed YAML | Check indentation |
