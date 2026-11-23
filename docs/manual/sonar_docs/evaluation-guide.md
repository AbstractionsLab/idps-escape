# Evaluating detection quality

`sonar evaluate` measures how well a scenario detects labelled anomalies, compares its backends with each other and with other detectors, and calibrates the scenario's decision rule (`detection.threshold`, `detection.min_consecutive`) and its `anomaly_confidence`.

Implements [SRS-080](../../specs/srs/SRS-080.md). Verified by [TST-070](../../specs/tst/TST-070.md) and [TST-071](../../specs/tst/TST-071.md).

## What it measures

The unit is the **event**: an attack or fault with a type and a time interval, listed in a label file. Reported buckets that touch each other form one **alarm**, the unit an analyst sees.

| Metric | Definition |
|--------|------------|
| Recall | Detected events / labelled events. An event is detected when an alarm overlaps its interval, widened by the tolerance on both sides. |
| Precision | True alarms / all alarms. A true alarm overlaps a (widened) labelled event; a false alarm overlaps none. |
| F1 | Harmonic mean of precision and recall (0 when either is 0 or undefined). |
| Mean delay | From an event's start to the end of the first reported bucket in its window: the earliest moment the detector could have reported it. Never below 0; it is 0 only when that bucket ends before the event starts, which the tolerance allows. |
| False alarms per day | False alarms / days of evaluated data. |

Only the time the detector scored, within the label file's `span`, counts. Events outside it are not counted; their number is reported as `unscored_events`. With `--event-types`, only events of those types count; an alarm on an event of another type is neither true nor false. A brute-force scenario is not penalised for also flagging lateral movement, and gets no credit for it either.

The decision rule is the one `sonar detect` applies: a bucket is reported when the backend flags it, its severity reaches `threshold`, and it belongs to a run of at least `min_consecutive` such buckets.

## Label files

```json
{
  "format": "sonar-labels/1",
  "dataset": "resource_monitoring test split",
  "span": {"start": "2024-12-13T00:00:00Z", "end": "2024-12-15T00:00:00Z"},
  "events": [
    {"id": "cpu_spike_1", "type": "cpu_spike", "start": "2024-12-13T03:24:00Z", "end": "2024-12-13T04:05:00Z"}
  ]
}
```

`span` is the time the alert file covers. Times are UTC; an event's interval is `[start, end)`. Write one label file per alert file.

## Labelled synthetic data

Both data generators write labelled splits with `--evaluation`. Each split is a training file of normal data plus a validation and a test file, each starting with normal context (what the detector needs before it scores) followed by events at random, non-overlapping times. The seed makes the files reproducible, so they are generated, not committed:

```bash
# Resource metrics: 24 h of training, two splits of 2 h context + 46 h with four CPU spikes,
# four memory leaks and four fork bombs each
poetry run python sonar/test_data/generate_resource_data.py --evaluation --output-dir eval/resource

# Authentication: 14 days of training, two splits of 48 h context + 192 h with four brute
# force attacks, password sprays, lateral movements and privilege escalations each
poetry run python sonar/test_data/generate_attack_data.py --evaluation --output-dir eval/auth
```

Each directory then holds `training.json`, `validation.json`, `validation_labels.json`, `test.json` and `test_labels.json`. `--seed` (default 42) changes the data and the event times.

## Evaluating a scenario

```bash
poetry run sonar evaluate --scenario linux_resource_monitoring \
  --train-file eval/resource/training.json \
  --validation-file eval/resource/validation.json --validation-labels eval/resource/validation_labels.json \
  --test-file eval/resource/test.json --test-labels eval/resource/test_labels.json \
  --tolerance-minutes 1 --output-dir eval/reports
```

`sonar evaluate`:

1. trains the scenario's backend (`--backend` overrides it) on the last `training.lookback_hours` of the training file, with the training pre-flight check of `sonar train`; the model is not saved;
2. scores each split with the scenario's features;
3. reports the test split with the scenario's own `threshold` and `min_consecutive` (`test (configured)`);
4. with a validation split, calibrates the decision rule on it and reports both splits with the calibrated values.

It writes `<scenario_id>-<backend>.json` (the full record, including each event's outcome) and `<scenario_id>-<backend>.md` (a summary, also printed) to `--output-dir`; `--name` changes the file name.

| Option | Meaning |
|--------|---------|
| `--event-types a,b` | Count only these label types (default: all) |
| `--tolerance-minutes N` | Widen every event by N minutes on both sides (default 0). One bucket is a fair choice: a short event can end before the bucket that shows it does. |
| `--max-false-alarms-per-day N` | Calibration budget (default 5) |
| `--agent NAME` | Only this host's alerts (`agent.name`) from the files; the model and the report are named after it, like `sonar train --agent` |

## Calibration

Calibration tries every `threshold` in {none, 0.05, 0.10, …, 0.95} with every `min_consecutive` from 1 to 5 on the validation split, and keeps the pair with the best F1 among those within the false-alarm budget. Ties go to fewer false alarms, then the shorter delay, then the less filtering. If no pair stays within the budget, the report says so and gives the pair with the fewest false alarms.

The calibrated pair is then applied to the test split, which played no part in choosing it. Its test precision is the scenario's measured `anomaly_confidence`: the share of SONAR alarms of this scenario that were real. Copy the three values into the scenario:

```yaml
detection:
  threshold: 0.6
  min_consecutive: 3
  anomaly_confidence: 0.8
```

Calibrate on data that looks like the deployment's. A value calibrated on synthetic data is only a starting point; recalibrate on a labelled capture of your own environment (see [Recording a lab capture](#recording-a-lab-capture)).

## Comparing with another detector

`--detections` scores another detector's results instead of training SONAR. It reads a JSON array, JSON lines or an OpenSearch `_search` response of either:

- OpenSearch anomaly detection plugin results (`data_start_time`, `data_end_time`, `anomaly_grade`; a grade above 0 is an anomaly, the grade is the severity); or
- generic records: `start`, `end`, `severity` (0-1) and optionally `is_anomaly`.

```bash
poetry run sonar evaluate --detections ad-test.json --validation-detections ad-validation.json \
  --detector-name opensearch-ad-brute-force \
  --test-labels eval/auth/test_labels.json --validation-labels eval/auth/validation_labels.json \
  --event-types brute_force,password_spray --tolerance-minutes 5 --output-dir eval/reports
```

Detections outside the label file's span (a detector's own training period, for example) are ignored.

Against a live deployment, `sonar export` writes a window's alerts, a label file and the results of a RADAR detector, ready for both kinds of evaluation. The [RADAR comparison guide](./radar-comparison-guide.md) walks through it for RADAR's resource-utilization scenario.

### The OpenSearch anomaly detection plugin baseline

The Wazuh indexer bundles the OpenSearch anomaly detection plugin, which RADAR uses for its `log_volume` scenario. To compare it with SONAR on the same data:

1. **Replay the labelled data** into a lab indexer at its own timestamps, so that the label files stay valid:

   ```bash
   for f in training validation test; do
     poetry run python sonar/test_data/inject_wazuh_data.py --config lab.yaml --source eval/auth/$f.json --keep-timestamps
   done
   ```

2. **Create a detector per scenario** whose features mirror the scenario's as closely as the plugin allows. The plugin takes at most five features, each a single-value aggregation, and one filter for the whole detector. Use the scenario's bucket size as the interval. For the brute-force scenario:

   ```bash
   curl -sk -u admin:"$INDEXER_PASSWORD" -X POST "https://indexer:9200/_plugins/_anomaly_detection/detectors" \
     -H 'Content-Type: application/json' -d '{
     "name": "baseline-brute-force",
     "time_field": "timestamp",
     "indices": ["wazuh-alerts-*"],
     "filter_query": {"bool": {"filter": [{"terms": {"rule.groups": ["authentication_failed", "authentication_success", "sshd", "brute_force"]}}]}},
     "detection_interval": {"period": {"interval": 5, "unit": "Minutes"}},
     "window_delay": {"period": {"interval": 1, "unit": "Minutes"}},
     "feature_attributes": [
       {"feature_name": "alerts", "feature_enabled": true, "aggregation_query": {"alerts": {"value_count": {"field": "rule.id"}}}},
       {"feature_name": "max_level", "feature_enabled": true, "aggregation_query": {"max_level": {"max": {"field": "rule.level"}}}},
       {"feature_name": "hosts", "feature_enabled": true, "aggregation_query": {"hosts": {"cardinality": {"field": "agent.id"}}}},
       {"feature_name": "users", "feature_enabled": true, "aggregation_query": {"users": {"cardinality": {"field": "data.srcuser"}}}}
     ]
   }'
   ```

   | Scenario | Interval | Filter (`rule.groups`) | Features |
   |----------|----------|------------------------|----------|
   | `brute_force_detection` | 5 min | authentication groups, as above | alert count, max `rule.level`, distinct `agent.id`, distinct `data.srcuser` |
   | `lateral_movement_detection` | 10 min | `authentication_success`, `authentication_failed`, `sudo` | alert count, distinct `agent.id`, distinct `data.srcuser`, max `rule.level` |
   | `privilege_escalation_detection` | 15 min | `sudo`, `privilege_escalation`, `account_changed`, `user_management` | alert count, max `rule.level`, distinct `agent.id` |
   | `linux_resource_monitoring` | 1 min | `performance_metric` (or no filter on replayed synthetic data) | max and average `data.cpu_usage_%`, max and average `data.memory_usage_%`, alert count |

   RADAR's own `linux_resource_utilization` detector is already such a detector, for the `radar_linux_resource_utilization` scenario: see the [RADAR comparison guide](./radar-comparison-guide.md).

3. **Run a historical analysis** from the start of the training file to the end of the test file, in epoch milliseconds (here the authentication splits: 2024-12-01 to 2025-01-11). The plugin trains on the beginning of the range:

   ```bash
   curl -sk -u admin:"$INDEXER_PASSWORD" -X POST "https://indexer:9200/_plugins/_anomaly_detection/detectors/$DETECTOR_ID/_start" \
     -H 'Content-Type: application/json' -d '{"start_time": 1733011200000, "end_time": 1736553600000}'
   ```

4. **Export the results** once the task has finished, all of them, in time order. One search returns at most 10,000 results, fewer than a 5-minute detector produces over the authentication splits, so page through them with `search_after` (a detector without a category field has one result per interval, so `data_start_time` is a unique sort key):

   ```bash
   search_after=""
   : > ad-results.jsonl
   while :; do
     page=$(curl -sk -u admin:"$INDEXER_PASSWORD" -X POST "https://indexer:9200/_plugins/_anomaly_detection/detectors/results/_search" \
       -H 'Content-Type: application/json' -d '{
       "size": 5000, "sort": [{"data_start_time": "asc"}], '"$search_after"'
       "query": {"bool": {"filter": [{"term": {"detector_id": "'"$DETECTOR_ID"'"}}, {"term": {"task_id": "'"$TASK_ID"'"}}]}}
     }')
     [ "$(echo "$page" | jq '.hits.hits | length')" -eq 0 ] && break
     echo "$page" | jq -c '.hits.hits[]._source' >> ad-results.jsonl
     search_after="\"search_after\": $(echo "$page" | jq -c '.hits.hits[-1].sort'),"
   done
   ```

   The same file (JSON lines) serves as `--detections` and `--validation-detections`: each label file's span selects its part.

5. **Evaluate** with the same event types and tolerance as the scenario. Keep the detector definitions and the exported results with the report.

## Recording a lab capture

Synthetic data shows that the pipeline works; only a capture of a real stack shows how SONAR behaves on real alert streams. To record one on the lab stack (Wazuh 4.14.1):

1. Let the stack run with its usual agents for at least the scenario's `training.lookback_hours` plus two days, without scripted activity: training and validation context.
2. Run the scripted red-team activity (for example the brute force, privilege escalation and resource abuse of the RADAR test scenarios), several times each, at times you note in UTC. Keep at least an hour between runs.
3. Export the alerts of the whole period with the indexer's `_search` API or the scroll in `inject_wazuh_data.py`'s format (a JSON array of `_source` documents). `sonar evaluate` also reads a raw `_search` response, but `inject_wazuh_data.py` does not, so keep the array form if the capture will be replayed.
4. Write the label file from the noted times: one event per run, with its type and interval.
5. Split the export by time into training (normal only), validation and test files, each split with its label file.
6. Anonymise before storing it: replace host names, user names, IP addresses and `full_log` contents consistently (the same value always maps to the same placeholder), and drop credentials, tokens and anything under `data` that the scenarios do not read. Never store files from `adbox/assets/secrets/` or `.env` files with it.
7. Document the replay: the stack version, agents, scripts and the commands of each run.

## Reading the results

- A scenario with low precision at its configured values but a good calibrated F1 needs the calibrated decision rule; a scenario that stays outside the false-alarm budget after calibration needs other features, not another threshold.
- Compare backends on the same splits. When `pca` or the `ewma` baseline matches `mvad`, the simpler backend is the better choice for that scenario: no torch, and training in under a second instead of minutes.
- Read the per-event outcomes in the JSON report: a type that is never detected points at a missing feature (a memory leak needs a memory column, a new attack type needs a categorical field that reveals it).
