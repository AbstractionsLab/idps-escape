---
active: true
derived: false
level: 2.6
links:
- HARC-004: B-4i2SClF5iGbeV-cWw9l0nDiMns0PHC2fNuaqSQAmo=
- HARC-012: ilKIUnLMG0LmoIUP781vdTvx8oRCMLZHrRM5puzgbGU=
- SRS-050: f1fx4EzuMUZpkPuPmI8RJXj5-ASOsNLfOUx5pm81PWc=
- SRS-051: L_FEEgh5sx0eJ_B6mZtm3kp_90KxFJLwar48ZeSHzbk=
- SRS-052: rnH2AeVu4U2ZbCOXkatJeqKiv_ziq90iRQZJjU1fHKc=
- SRS-056: xKvRTfbWPnFhLmrKkVnKcrA1gfDRFhhKwc6tXbXmnJw=
normative: true
ref: ''
release: Alpha
reviewed: RjNeV5T-NQOK3WWruo6nFAKinuWuS6dOfRJVKTDGqEo=
version: '0.1'
---

# RADAR detector creation workflow

The diagram below depicts the sequence of operations for creating and starting OpenSearch anomaly detectors via the `detector.py` module.

## Workflow stages

### 1. Configuration loading
- Read scenario definition from `config.yaml`
- Load environment variables from `.env` (OS_URL, OS_USER, OS_PASS, OS_VERIFY_SSL)
- Validate scenario exists in configuration

### 2. Detector existence check
- Query OpenSearch AD API: `GET /_plugins/_anomaly_detection/detectors/_search`
- Search by name pattern: `{scenario}_DETECTOR`
- If found, return existing detector ID (idempotent operation)

### 3. Detector specification building
Construct detector JSON specification including:

- **indices**: Index pattern to monitor (e.g., `wazuh-ad-log-volume-*`)
- **time_field**: Timestamp field for time-series analysis (`@timestamp`)
- **feature_attributes**: Aggregation queries from config (e.g., `max(data.log_bytes)`)
- **detection_interval**: How often to run detection (minutes)
- **window_delay**: Buffer time for late-arriving data (minutes)
- **category_field**: Field for high-cardinality detection (e.g., `agent.name` for per-endpoint baselines)
- **shingle_size**: Temporal sequence window size for RCF algorithm
- **result_index**: Custom index for storing detection results

### 4. Detector creation
- POST detector specification to OpenSearch AD plugin
- Endpoint: `POST /_plugins/_anomaly_detection/detectors`
- Receive detector ID in response

### 5. Detector activation
- Start the detector to begin analysis
- Endpoint: `POST /_plugins/_anomaly_detection/detectors/{detector_id}/_start`
- Detector begins processing data at configured intervals

### 6. Output
- Return detector ID to stdout for pipeline chaining
- Used by monitor.py in subsequent workflow stage

## Key functions

```python
find_detector_id(detector_name: str) -> str | None
detector_spec(scenario_config: dict) -> dict
create_detector(spec: dict) -> str
start_detector(detector_id: str) -> None
```

## Detector Creation Sequence

```plantuml
@startuml
participant "run-radar.sh" as CLI
participant "radar-cli\nContainer" as Docker
participant "config.yaml" as Config
participant "detector.py" as Script
participant "OpenSearch\nAPI" as OS
participant "AD Detector" as Detector

note over CLI,Detector: Detector Creation Workflow

CLI -> Docker: docker run radar-cli detector.py
Docker -> Config: Load scenario configuration
Config --> Script: scenario_name, index_pattern, features

group 1. Check for existing detector (idempotent)
  Script -> OS: GET /_plugins/_anomaly_detection/detectors/_search
  OS --> Script: Search results
  alt Detector exists
    Script --> CLI: Return existing detector_id
    note over Script: Exit early (idempotent)
  else Detector not found
    note over Script: Proceed to creation
  end
end

group 2. Build detector specification
  Script -> Script: Construct detector JSON
  note right of Script
    indices: "wazuh-ad-{scenario}-*"
    time_field: "@timestamp"
    features: [aggregations]
    detection_interval: 5 min
    window_delay: 1 min
    category_field: "agent.name" (HC)
    shingle_size: 8
    result_index: custom
  end note
end

group 3. Create detector via API
  Script -> OS: POST /_plugins/_anomaly_detection/detectors
  note over Script,OS: {detector specification JSON}
  OS -> Detector: Initialize detector
  OS --> Script: detector_id, status: "INIT"
end

group 4. Start detector processing
  Script -> OS: POST /detectors/{detector_id}/_start
  OS -> Detector: Start RCF model training
  Detector --> OS: Running
  OS --> Script: status: "RUNNING"
end

group 5. Return detector ID for chaining
  Script --> Docker: detector_id (stdout)
  Docker --> CLI: detector_id
  note over CLI: Pass to monitor.py
end

note over Script,Detector: Total duration: 2-5 seconds

@enduml
```

## Implementation reference

See [radar/anomaly_detector/detector.py](../../../radar/anomaly_detector/detector.py) for implementation details.