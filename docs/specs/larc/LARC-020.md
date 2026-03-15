---
active: true
derived: false
level: 1.2
links:
- SRS-027: qV_tYdjjxxvj9gBHqO5x5MwZ6kV9KPxPo3_-GYHq8FU=
- SRS-035: 81VhxH8mkXdcWevkkr-cbGE0_B3foxgnm2HWa3LRCE4=
- SRS-042: ZVOhqBvnZyb0lz9DIfJoWXcaZXgDi-Kx01kvKE_DUr8=
normative: true
ref: ''
release: Alpha
reviewed: JgEQkN1NxqNktbCrdyYILI9YA9KGQHaWtlOuSFBjQWw=
version: '0.1'
---

# SONAR detection pipeline sequence

## Detection workflow sequence diagram

The detection pipeline loads a trained model, processes recent alerts, and generates anomaly scores with optional shipping to data streams.

```plantuml
@startuml
participant "CLI (cli.py)" as CLI
participant "File System" as Storage
participant "MVAD Engine" as Engine
participant "Data Provider" as DataProvider
participant "Feature Engineer" as Features
participant "Post-Processor" as Pipeline
participant "Data Shipper" as Shipper
participant "Data Streams" as OpenSearch

CLI -> Storage: Load trained model
Storage --> CLI: Model object

CLI -> Engine: Initialize with model
Engine --> CLI: Ready

CLI -> DataProvider: Fetch recent alerts
DataProvider --> CLI: Raw alert list

CLI -> Features: Extract features
Features --> CLI: Time-series DataFrame

CLI -> Engine: Detect anomalies
Engine -> Engine: Score each window
Engine --> CLI: Anomaly scores

CLI -> Pipeline: Process scores
Pipeline -> Pipeline: Apply threshold
Pipeline -> Pipeline: Enrich documents
Pipeline --> CLI: Anomaly documents

alt Shipping enabled
  CLI -> Shipper: Ship anomalies
  Shipper -> OpenSearch: Bulk index
  OpenSearch --> Shipper: Success
  Shipper --> CLI: Indexed count
end

CLI -> CLI: Log results
@enduml
```

## Detection modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| **historical** | Process fixed time range | Batch analysis, validation |
| **realtime** | Continuous monitoring | Production deployment |
| **batch** | Scheduled execution | Periodic scans |

## Post-processing steps

1. **Thresholding**: Filter scores above configured threshold
2. **Consecutive filtering**: Require N consecutive anomalies
3. **Enrichment**: Add metadata (timestamp, scenario ID, severity)
4. **Formatting**: Convert to OpenSearch document format

## Related documentation

- Detection sequence diagram: `docs/manual/sonar_docs/uml-diagrams.md#detection-workflow`