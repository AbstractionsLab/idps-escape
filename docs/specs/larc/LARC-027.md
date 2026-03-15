---
active: true
derived: false
level: 2.11
links:
- HARC-004: B-4i2SClF5iGbeV-cWw9l0nDiMns0PHC2fNuaqSQAmo=
- HARC-014: ShXINRasg8k_EUmwdYZIwUUznXOyfv6zDpDA8O-ZRVo=
- LARC-015: b6iWi1kYZwtxRQIRTDe5K8kFa4EUsP9n93xZMdplUb8=
- SRS-050: f1fx4EzuMUZpkPuPmI8RJXj5-ASOsNLfOUx5pm81PWc=
- SRS-051: L_FEEgh5sx0eJ_B6mZtm3kp_90KxFJLwar48ZeSHzbk=
- SRS-052: rnH2AeVu4U2ZbCOXkatJeqKiv_ziq90iRQZJjU1fHKc=
- SRS-056: xKvRTfbWPnFhLmrKkVnKcrA1gfDRFhhKwc6tXbXmnJw=
normative: true
ref: ''
release: Alpha
reviewed: cd8uvqWCbPUjFM-dbhgZ3XeC81TdLqyUvizvfbLpkIM=
version: '0.1'
---

# RADAR data ingestion pipeline

The diagram below depicts the data ingestion workflow orchestrated by `run-radar.sh` and implemented by scenario-specific `wazuh_ingest.py` scripts.

## Pipeline purpose

Data ingestion generates synthetic time-series data for training OpenSearch RCF anomaly detectors. Each behavior-based scenario requires historical baseline data to establish normal patterns before real-time detection begins.

## Workflow stages

### 1. Script invocation
Execute from run-radar.sh:
```
Command: Execute scenario ingestion script in containerized environment
  Container: radar-cli:latest
  Environment: Load OS_URL, OS_USER, OS_PASS, OS_VERIFY_SSL from .env
  Volumes: Mount scenarios directory
  Script: /app/scenarios/ingest_scripts/{scenario}/wazuh_ingest.py
```

### 2. Baseline query (scenario-dependent)

**Log volume scenario**:

- Query last 10 minutes of existing data from `wazuh-ad-log-volume-*`
- Retrieve 2 most recent documents
- Calculate delta between log byte values
- Fallback: 20,000 bytes if insufficient data

**Suspicious login scenario**:

- Query user authentication patterns
- Analyze login frequency distribution
- Determine normal session intervals

### 3. Time series generation

**Log volume algorithm**:
```
Algorithm: Generate realistic time series baseline
  Input: baseline_value, delta, lookback_minutes, sampling_interval_seconds

  total_points ← (lookback_minutes × 60) / sampling_interval_seconds
  start_time ← current_time - lookback_minutes

  for i from 0 to total_points:
    timestamp ← start_time + (i × sampling_interval_seconds)
    value ← baseline_value + (delta × i / total_points)  // Linear progression

    document ← {
      "@timestamp": timestamp (ISO8601 format),
      "agent": {"name": agent_name, "id": agent_id},
      "data": {"log_path": path, "log_bytes": value},
      "predecoder": {"program_name": metric_name}
    }

    append document to bulk_data

  Output: bulk_data collection
```

Example generated data characteristics:

- **Default parameters**: 240 minutes lookback, 20-second sampling = 720 points
- **Monotonic trend**: Realistic growth from baseline to baseline+delta
- **Proper timestamps**: ISO8601 with consistent spacing
- **Scenario-specific fields**: Match detector configuration exactly

### 4. Bulk indexing

**OpenSearch Bulk API specification**:

- Endpoint: `POST /{index}/_bulk`
- Content-Type: `application/x-ndjson`
- Format: Newline-delimited JSON (NDJSON)

**Example NDJSON structure**:
```json
{"index": {"_index": "wazuh-ad-log-volume-2026-02-16"}}
{"@timestamp": "2026-02-16T10:00:00Z", "agent": {...}, "data": {...}}
{"index": {"_index": "wazuh-ad-log-volume-2026-02-16"}}
{"@timestamp": "2026-02-16T10:00:20Z", "agent": {...}, "data": {...}}
```

**Batch processing**:

- Default batch size: 500-1000 documents per bulk request
- Error handling: Retry on transient failures (network, temporary unavailability)
- Progress logging: Document count, timestamp range after each batch

### 5. Verification
```
Algorithm: Verify successful ingestion
  1. Query document count in target index for time range
  2. Compare actual_count with expected_count
  3. Verify earliest and latest timestamps match expected range
  4. Validate field mappings (numeric fields are numbers, not strings)

  if all checks pass:
    return SUCCESS
  else:
    return FAILURE with diagnostic information
```

### 6. Output
- Log ingestion summary: document count, time range, index name
- Return success/failure exit code
- Output used by run-radar.sh to proceed to detector creation

## Scenario-specific ingestion patterns

### Log volume
- **Index**: `wazuh-ad-log-volume-*`
- **Key field**: `data.log_bytes` (numeric)
- **Pattern**: Monotonic increase with realistic deltas
- **Volume**: 720 points over 240 minutes

### Suspicious login
- **Index**: `wazuh-archives-*` or custom index
- **Key fields**: `srcuser`, `srcip`, `@timestamp`, enriched RADAR fields
- **Pattern**: Normal login distribution with occasional geographic diversity
- **Volume**: Variable based on user count and session patterns

### Insider threat (archived)
- **Index**: `wazuh-archives-*`
- **Key fields**: File access patterns, data transfer volumes
- **Pattern**: Baseline file activity with gradual increase
- **Volume**: Per-user baselines

## Data quality considerations

- **Timestamp accuracy**: Proper ISO8601 format with timezone
- **Field types**: Numeric fields as numbers, not strings (critical for aggregations)
- **Index patterns**: Match detector configuration exactly
- **Agent consistency**: Use consistent agent.name for high-cardinality detection
- **Realistic patterns**: Avoid synthetic steps or unrealistic spikes that confuse training

## Error handling

- **Connection failures**: Retry with exponential backoff
- **Index creation**: Auto-create if not exists (OpenSearch default)
- **Mapping conflicts**: Log error, fail fast
- **Bulk API errors**: Parse response, retry failed documents

## Data Ingestion Sequence

```plantuml
@startuml
participant "run-radar.sh" as RunScript
participant "radar-cli\nContainer" as Docker
participant "wazuh_ingest.py" as IngestScript
participant "scenario\nconfig.yaml" as Config
participant "OpenSearch\nQuery API" as OS_Query
participant "Time Series\nGenerator" as Generator
participant "Bulk\nIndexer" as Bulk
participant "OpenSearch\nIndex" as OS_Index
participant "Verification" as Verify

note over RunScript,Verify: Historical Data Ingestion for Detector Training

group 1. Script invocation
  RunScript -> Docker: docker run --env-file .env radar-cli
  Docker -> IngestScript: python wazuh_ingest.py
  IngestScript -> Config: Load scenario configuration
  Config --> IngestScript: index_pattern, lookback_minutes, features
end

group 2. Query existing data for baseline
  IngestScript -> OS_Query: GET /{index}/_search
  note over IngestScript,OS_Query
    {
      "size": 2,
      "sort": [{"@timestamp": "desc"}],
      "query": {"range": {"@timestamp": {"gte": "now-10m"}}}
    }
  end note

  OS_Query --> IngestScript: Recent documents

  alt Sufficient data found
    IngestScript -> IngestScript: Calculate delta from existing data
    note over IngestScript
      delta = value[0] - value[1]
      baseline_value = value[0]
    end note
  else Insufficient data
    IngestScript -> IngestScript: Use fallback baseline
    note over IngestScript
      baseline_value = 20000 (default)
      delta = 1000 (default growth)
    end note
  end
end

group 3. Generate synthetic time series
  IngestScript -> Generator: generate_time_series(baseline, delta, lookback_minutes)

  Generator -> Generator: Calculate parameters
  note over Generator
    total_points = lookback_minutes * 60 / sampling_interval
    sampling_interval = 20 seconds
    lookback_minutes = 240 (default)
    total_points = 720
  end note

  Generator -> Generator: Generate data points
  note over Generator
    for i in range(total_points):
      timestamp = start_time + (i * sampling_interval)
      value = baseline + (delta * i / total_points)
      document = construct_document(timestamp, value)
  end note

  Generator --> IngestScript: List of 720 documents
  note over Generator
    Linear progression:
    Time 0: baseline_value
    Time 240min: baseline_value + delta
    Realistic monotonic trend
  end note
end

group 4. Format for bulk indexing
  IngestScript -> Bulk: format_bulk_ndjson(documents)

  Bulk -> Bulk: Build NDJSON payload
  note over Bulk
    {"index": {"_index": "wazuh-ad-log-volume-2026-02-16"}}
    {"@timestamp": "2026-02-16T06:30:00Z", "agent": {...}, "data": {"log_bytes": 20145}}
    {"index": {"_index": "wazuh-ad-log-volume-2026-02-16"}}
    {"@timestamp": "2026-02-16T06:30:20Z", "agent": {...}, "data": {"log_bytes": 20290}}
    ...
  end note

  Bulk --> IngestScript: NDJSON string (batches of 500 docs)
end

group 5. Bulk index to OpenSearch
  loop For each batch (500-1000 docs)
    IngestScript -> OS_Index: POST /{index}/_bulk
    note over IngestScript,OS_Index: Content-Type: application/x-ndjson

    OS_Index -> OS_Index: Parse NDJSON
    OS_Index -> OS_Index: Index documents

    alt All successful
      OS_Index --> IngestScript: {"errors": false, "took": 523}
      IngestScript -> IngestScript: Log progress
      note over IngestScript: Indexed batch 1/2: 500 docs
    else Partial failure
      OS_Index --> IngestScript: {"errors": true, "items": [...]}
      IngestScript -> IngestScript: Parse error responses
      IngestScript -> IngestScript: Retry failed documents
      note over IngestScript: Retry: 3 docs failed (transient)
    end
  end
end

group 6. Verify ingestion success
  IngestScript -> Verify: verify_ingestion(index, expected_count, time_range)

  Verify -> OS_Index: GET /{index}/_count
  note over Verify,OS_Index
    {
      "query": {
        "range": {"@timestamp": {"gte": start, "lte": end}}
      }
    }
  end note
  OS_Index --> Verify: {"count": 720}

  Verify -> Verify: Compare counts
  note over Verify
    expected_count = 720
    actual_count = 720
    ✓ Match
  end note

  Verify -> OS_Index: GET /{index}/_search?size=1&sort=@timestamp:asc
  OS_Index --> Verify: Earliest document timestamp

  Verify -> OS_Index: GET /{index}/_search?size=1&sort=@timestamp:desc
  OS_Index --> Verify: Latest document timestamp

  Verify -> Verify: Validate time range
  note over Verify
    earliest = 2026-02-16T06:30:00Z
    latest = 2026-02-16T10:29:40Z
    delta = 239.98 minutes
    ✓ Covers 240-minute lookback
  end note

  alt Verification passed
    Verify --> IngestScript: Success
    IngestScript --> Docker: Exit code 0
    Docker --> RunScript: Ingestion complete
  else Verification failed
    Verify --> IngestScript: Error
    IngestScript --> Docker: Exit code 1
    Docker --> RunScript: Ingestion failed
  end
end

@enduml
```

## Implementation reference

Scenario-specific implementations:

- [radar/scenarios/ingest_scripts/log_volume/wazuh_ingest.py](../../../radar/scenarios/ingest_scripts/log_volume/wazuh_ingest.py) - Log volume implementation
- [radar/scenarios/ingest_scripts/suspicious_login/wazuh_ingest.py](../../../radar/scenarios/ingest_scripts/suspicious_login/wazuh_ingest.py) - Login behavioral implementation

## See also
- `/docs/manual/radar_docs/radar-run-ad.md` for workflow documentation