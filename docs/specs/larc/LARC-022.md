---
active: true
derived: false
level: 2.6
links:
- SRS-056: cPHoeLEAeLaaZ8tCLEz_E724FHEVIvO-aLO0IBU7EMQ=
- SRS-071: ZHNgKjI-5h3aLRPBushyk3-rGXZlaZGed2XtpPWs0Gg=
normative: true
ref: ''
release: Alpha
reviewed: L8Bz65LZYF8pCwmbAtJp8SqJfAG49s2RDlMhQJ-8OXA=
version: '0.1'
---

# RADAR detector creation workflow

The diagram below depicts the sequence of operations for creating and starting an OpenSearch anomaly detector with `radar/anomaly_detector/detector.py`. `run-radar.sh` runs it, inside the `radar-cli` container, for the scenarios with a generic detector: `log_volume` and `linux_resource_utilization`. The `suspicious_login` model-mode detector is managed by `radar/anomaly_detector/off_hours.py` instead (SRS-062).

## Workflow stages

### 1. Configuration loading
- Read the scenario block from `config.yaml` (`scenarios.<name>`).
- Load `.env` (`OS_URL`, `OS_USER`, `OS_PASS`, `OS_VERIFY_SSL`, `OS_TIMEOUT`); `OS_URL` is required.

### 2. Detector existence check
- `POST /_plugins/_anomaly_detection/detectors/_search` for the exact name `<SCENARIO>_DETECTOR` (scenario name in upper case, e.g. `LOG_VOLUME_DETECTOR`).
- A 404 (AD system index not created yet) means no detector exists.

### 3. Detector specification building (only if none exists)
The specification is built from the scenario block:

- **indices**: `log_index_pattern`, else `<index_prefix>-*` (e.g. `wazuh-ad-log-volume-*`, `wazuh-archives-*`)
- **time_field**: `time_field` (`@timestamp`)
- **feature_attributes**: the `features` aggregations (e.g. max of `data.log_bytes`)
- **filter_query**: `filter_query`, else match all
- **detection_interval** / **window_delay**: `detector_interval`, `delay_minutes` (minutes)
- **category_field**: `categorical_field` (`agent.name`, one baseline per agent)
- **shingle_size**, **imputation_option** (default zero fill), detector **rules** (e.g. ignore small deviations)
- **result_index**: custom result index, with its minimum age, size and TTL

### 4. Detector creation
- Wait briefly until the index pattern holds documents: the AD plugin cannot start a detector on an empty index.
- `POST /_plugins/_anomaly_detection/detectors`; the response carries the detector ID.

### 5. Detector activation
- `POST /_plugins/_anomaly_detection/detectors/{detector_id}/_start`, for a new or an existing detector.

### 6. Output
- Print the detector ID on stdout; `run-radar.sh` passes it to `monitor.py` (LARC-023).

## Detector creation sequence

```plantuml
@startuml
participant "run-radar.sh" as CLI
participant "radar-cli\nContainer" as Docker
participant "config.yaml\n+ .env" as Config
participant "detector.py" as Script
participant "OpenSearch\nAD API" as OS

note over CLI,OS: Detector creation (log_volume, linux_resource_utilization)

CLI -> Docker: docker run radar-cli python detector.py <scenario>
Docker -> Script: start
Script -> Config: load scenario block and OS_* settings
Config --> Script: index pattern, features, interval, ...

group 1. Find existing detector
  Script -> OS: POST /detectors/_search\nname = <SCENARIO>_DETECTOR
  OS --> Script: hits (or 404: none yet)
end

alt Detector not found
  group 2. Build and create
    Script -> Script: detector_spec(scenario)
    note right of Script
      indices: <index_prefix>-*
      time_field: @timestamp
      features, filter_query, rules
      category_field: agent.name
      interval / window_delay (minutes)
      shingle_size, imputation_option
      result_index
    end note
    Script -> OS: POST <index>/_count (until documents exist)
    OS --> Script: count
    Script -> OS: POST /detectors {spec}
    OS --> Script: detector_id
  end
else Detector exists
  note over Script: reuse its detector_id
end

group 3. Start
  Script -> OS: POST /detectors/{detector_id}/_start
  OS --> Script: 200 OK
end

Script --> Docker: detector_id (stdout)
Docker --> CLI: detector_id
note over CLI: passed to monitor.py

@enduml
```

## Implementation reference

See [radar/anomaly_detector/detector.py](../../../radar/anomaly_detector/detector.py) and [radar/run-radar.sh](../../../radar/run-radar.sh). Operator guide: docs/manual/radar_docs/radar-run-ad.md.

Related: HARC-004, HARC-012.