# Comparing SONAR with RADAR on resource utilization

RADAR's `linux_resource_utilization` scenario detects unusual CPU and memory use with the OpenSearch anomaly detection plugin, a random cut forest per host. The packaged SONAR scenario `radar_linux_resource_utilization` reads the same events with the same features. This guide shows how to run SONAR next to RADAR on one Wazuh deployment and how to score both detectors on the same labelled window.

Implements [SRS-081](../../specs/srs/SRS-081.md). For the metrics and the label format, see the [evaluation guide](./evaluation-guide.md).

## What the two scenarios share

| | RADAR (`radar/config.yaml`) | SONAR (`sonar/scenarios/radar_linux_resource_utilization.yaml`) |
|---|---|---|
| Events | `resource_usage_metric: cpu=… mem=…` from RADAR's collector, every 30 s | the same events |
| Index | `wazuh-archives-*` | `wazuh.alerts_index_pattern: wazuh-archives-*` |
| Filter | events with `data.mem_usage_pct` | the same, without RADAR's seeded history (`radar_seed: true`) |
| Features | mean and maximum of `data.cpu_usage_pct` and `data.mem_usage_pct` | the same four columns, plus `alert_count` (SONAR always has it) |
| Interval | 1 minute | `bucket_minutes: 1` |
| Empty intervals | `ZERO` imputation | `numeric_fill: zero` |
| Hosts | one model per `agent.name` | the whole fleet in one series, or one model per host with `--agent` |
| History before detection | 240 minutes seeded by RADAR's ingest script | at least 610 one-minute buckets of real data (MVAD with `sliding_window: 120`) |
| Decision | monitor fires at `anomaly_grade ≥ 0.01` and `confidence ≥ 0.01` | MVAD's decision, `threshold: 0.25`, `min_consecutive: 5` |

The collector's events match no rule, so they never reach `wazuh-alerts-*`. RADAR's deployment turns on `logall_json` on the manager and the archives in Filebeat. Without them, neither detector sees any data.

SONAR leaves out RADAR's seeded history, because it is a flat synthetic baseline (constant CPU and memory with a little jitter). RADAR uses it only to start its detector quickly. Training SONAR on it would teach SONAR a host that never existed.

## Before you start

- RADAR's `linux_resource_utilization` scenario is deployed, its collector runs on the agents, and events arrive in `wazuh-archives-*` (Discover: `predecoder.program_name: resource_usage_metric`).
- SONAR's configuration points at the indexer (`wazuh:` section, see the [setup guide](./setup-guide.md)). `sonar check --config <file>` succeeds.
- The indexer user can read `wazuh-archives-*` and RADAR's result index (`opensearch-ad-plugin-result-*`), and create a point-in-time (see [Alert ingestion](./setup-guide.md#alert-ingestion)).
- The collector has run for more than 10 hours on every host you want to model. Use 24 hours or more if you can: that is the scenario's `lookback_hours`.

Try the scenario first on the packaged debug data: the synthetic resource data rewritten as RADAR events.

```bash
poetry run sonar scenario --use-case radar_linux_resource_utilization --debug
```

## Running SONAR next to RADAR

### One model for the fleet

```bash
poetry run sonar train  --scenario radar_linux_resource_utilization --config sonar.yaml
poetry run sonar scenario --use-case radar_linux_resource_utilization --config sonar.yaml --mode realtime
```

A spike on one host of many moves the fleet's mean only slightly. The per-bucket maximum still shows it, but the comparison with RADAR's per-host models is fairer with one model per host.

### One model per host

`--agent <name>` restricts training, detection, evaluation and export to one `agent.name`, the field RADAR's detector splits on:

```bash
for host in web-01 db-01; do
  poetry run sonar train --scenario radar_linux_resource_utilization --config sonar.yaml --agent "$host"
done
poetry run sonar scenario --use-case radar_linux_resource_utilization --config sonar.yaml --agent web-01 --mode realtime
```

Each host gets its own model, `radar_linux_resource_utilization-<host>`, and its own scenario ID, `radar_resource_utilization-<host>`. The scenario ID names the watermarks, the data stream and the anomaly IDs, so SONAR events in Wazuh name the host through their `scenario`. The model stores the host's filter, so detection with that model reads that host only. Run one SONAR process per host, as you would schedule one detector per host.

`--agent` is applied after `--model-name`: `train --model-name x --agent web-01` saves `x-web-01`.

## Scoring both detectors on a labelled window

### 1. Record when the anomalies happen

Run RADAR's simulation on an agent and note the start and end in UTC. The script takes its settings (`MODE`, `DURATION_SECONDS`, …) from the variables at its top:

```bash
date -u +%Y-%m-%dT%H:%M:%SZ   # start
sudo bash radar/radar-test-framework/simulate/scenarios/linux_resource_utilization.sh
date -u +%Y-%m-%dT%H:%M:%SZ   # end
```

Leave at least an hour of normal activity between two runs. Otherwise one alarm can span both runs.

### 2. Export the training window and the test window

`sonar export` reads the scenario's index with the scenario's filter (and `--agent`). It writes three files to `--output-dir`:

- `events.json`: the events from the context before `--start` up to `--end`. The context is what the backend needs before it scores its first bucket: 119 one-minute buckets for MVAD here. SONAR therefore scores the whole window, as RADAR did.
- `labels.json`: the window (`--start` to `--end`) as the label span, and one event per `--event TYPE,START,END`.
- `radar_results.json`, with `--radar-results`: the anomaly detection results of RADAR's detector whose interval starts in the window, for that host when `--agent` is given.

```bash
# Training: a quiet day before the simulations
poetry run sonar export --scenario radar_linux_resource_utilization --config sonar.yaml --agent web-01 \
  --start 2026-11-18T00:00:00Z --end 2026-11-19T00:00:00Z --output-dir cmp/train

# Test: the day of the simulations, with RADAR's results and the labelled runs
poetry run sonar export --scenario radar_linux_resource_utilization --config sonar.yaml --agent web-01 \
  --start 2026-11-19T00:00:00Z --end 2026-11-20T00:00:00Z --output-dir cmp/test \
  --radar-results 'opensearch-ad-plugin-result-linux-resource-utilization*' \
  --event cpu_load,2026-11-19T09:00:00Z,2026-11-19T09:05:00Z \
  --event mem_load,2026-11-19T14:30:00Z,2026-11-19T14:35:00Z
```

Times without an offset are UTC. `--start` and `--end` are rounded down to a bucket. The command exits with 2 when the window holds no events, which usually means that the archives are not indexed or that the agent name is wrong.

The training export's `labels.json` lists no events and is not used.

### 3. Evaluate both

```bash
# SONAR: trains the scenario's backend on the training window, scores the test window
poetry run sonar evaluate --scenario radar_linux_resource_utilization --agent web-01 \
  --train-file cmp/train/events.json --test-file cmp/test/events.json --test-labels cmp/test/labels.json \
  --tolerance-minutes 1 --output-dir cmp/reports

# RADAR: its detector's results on the same window
poetry run sonar evaluate --detections cmp/test/radar_results.json --detector-name radar-rcf-web-01 \
  --test-labels cmp/test/labels.json --tolerance-minutes 1 --output-dir cmp/reports
```

Both reports count alarms and events the same way. Compare precision, recall, mean delay and false alarms per day. With `--agent`, `sonar evaluate` keeps that host's events from the files, so a fleet-wide export also works for per-host evaluation.

To calibrate SONAR's `threshold` and `min_consecutive` on your own hosts, export a second labelled window as the validation split and pass `--validation-file` and `--validation-labels`. Then copy the calibrated values and the reported `anomaly_confidence` into a copy of the scenario. The packaged values were calibrated on synthetic data.

## Reading the comparison

- **RADAR's decision rule.** `sonar evaluate` counts a RADAR result as an anomaly when its `anomaly_grade` is above 0, and uses the grade as the severity. RADAR's monitor also requires `anomaly_grade ≥ 0.01` and `confidence ≥ 0.01`, which leaves out almost nothing beyond that. Calibrating RADAR's threshold on a validation export (`--validation-detections`) gives it the same chance as SONAR.
- **Delay.** The reported delay runs from an event's start to the first anomalous bucket that is reported. With `min_consecutive: 5`, SONAR emits its alert only once five anomalous buckets have accumulated, which is up to four minutes after the first of them. RADAR's monitor runs once per minute.
- **Fleet versus host.** Compare a fleet-wide SONAR model with RADAR only for anomalies that affect several hosts at once. For an anomaly on a single host, use `--agent`.
- **Small samples.** A few simulation runs move recall in large steps. Treat differences of one or two events as indicative only.

## Data the scenario was calibrated on

`sonar/test_data/radar_format.py` rewrites the synthetic resource data of `generate_resource_data.py` as RADAR events, with the same timestamps and hosts. The labelled splits keep their label files:

```bash
poetry run python sonar/test_data/generate_resource_data.py --evaluation --output-dir eval/resource
for f in training validation test; do
  poetry run python sonar/test_data/radar_format.py eval/resource/$f.json eval/radar/$f.json
done
cp eval/resource/*_labels.json eval/radar/
```

The results are in the [evaluation evidence](../../specs/trp/assets/sonar-evaluation/README.md).
