---
active: true
derived: false
level: 11.0
links:
- MRS-032: T6hCz4404Ang3Ig9Z1a4aSLoszOGnnuq3HdS2NZZ2LQ=
- MRS-039: -K_FLcCc63SwoERy1DmALXIhaL5t_KOpDmEBzdT0mZY=
normative: true
ref: ''
reviewed: 0Cukta81x1SnRK8u4dPJ52P2h_UNxLooDrS7uTool-0=
---

# SONAR data flow architecture

The diagram below illustrates the high-level data flow through the SONAR subsystem for training and detection operations.

## Training data flow

```plantuml
@startuml
!define SONAR_COLOR #e1f5ff

database "Wazuh Indexer" as WI

package "SONAR System" SONAR_COLOR {
  component "Data Ingestion" as Ingest
  component "Feature Engineering" as Features
  component "MVAD Training" as MVAD
  database "Model Storage" as Model

  Ingest -down-> Features : Raw Events
  Features -down-> MVAD : Time-Series Data
  MVAD -down-> Model : Trained Model
}

WI -right-> Ingest : Historical Alerts

@enduml
```

## Detection data flow

```plantuml
@startuml
!define SONAR_COLOR #e1f5ff

database "Wazuh Indexer" as WI

package "SONAR System" SONAR_COLOR {
  database "Model Storage" as Model
  component "Data Ingestion" as Ingest2
  component "Feature Engineering" as Features2
  component "MVAD Detection" as MVAD2
  component "Post-Processing" as Pipeline
  component "Data Shipper" as Shipper

  Model -down-> MVAD2 : Load Model
  Ingest2 -down-> Features2 : Raw Events
  Features2 -down-> MVAD2 : Time-Series Data
  MVAD2 -down-> Pipeline : Anomaly Scores
  Pipeline -down-> Shipper : Anomaly Documents
}

component "RADAR Webhook" as RADAR
database "Data Streams" as DS

WI -right-> Ingest2 : Recent Alerts
Shipper -right-> DS : Bulk Index
Pipeline .right.> RADAR : Real-time Events

@enduml
```

## Data transformations

| Stage | Input | Output | Transformation |
|-------|-------|--------|----------------|
| **Ingestion** | Wazuh alerts (JSON) | Raw event list | Filtering, time-range selection |
| **Feature Engineering** | Raw events | Time-series vectors | Bucketing, aggregation, encoding |
| **MVAD Processing** | Time-series vectors | Anomaly scores | Multivariate analysis |
| **Post-Processing** | Anomaly scores | Anomaly documents | Thresholding, enrichment, formatting |
| **Shipping** | Anomaly documents | Indexed records | Bulk ingestion to data streams |

## Related documentation

- Data flow diagram: `docs/manual/sonar_docs/uml-diagrams.md#data-flow-diagram`
- Architecture details: `docs/manual/sonar_docs/architecture.md#data-flow`