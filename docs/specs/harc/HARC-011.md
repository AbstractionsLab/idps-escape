---
active: true
derived: false
level: 1.3
links:
- MRS-032: T6hCz4404Ang3Ig9Z1a4aSLoszOGnnuq3HdS2NZZ2LQ=
- MRS-033: U470hMVIXAfpaW14r-E4OSp8hO2VfCVVWdXg7KQ9lVE=
- MRS-034: T2ScW97WQgVksICRLgyu9SRNJnYdEmIi-y8tLzndmbw=
- MRS-039: -K_FLcCc63SwoERy1DmALXIhaL5t_KOpDmEBzdT0mZY=
- MRS-042: flMQ5MputiFRH6joyGqB6j3xgiSAWqI5mnD4hKn5Rjw=
normative: true
ref: ''
reviewed: zPYe5DalFgUhL4cOwMpaWQaonQU_2G3KruhGV4o_gJo=
---

# SONAR data flow architecture

The diagram below illustrates the high-level data flow through the SONAR subsystem for training and detection operations.

## Training data flow

Training fetches the scenario's history, builds the feature matrix, fits the scenario's detector backend (`mvad` by default, or `pca`, `ewma`) and stores the model directory. With the data stream enabled, it also prepares the scenario's index templates and ISM policy.

```plantuml
@startuml
!define SONAR_COLOR #e1f5ff

database "Wazuh Indexer" as WI
database "Local alert file\n(--debug)" as LF

package "SONAR System" SONAR_COLOR {
  component "Data Ingestion" as Ingest
  component "Feature Engineering" as Features
  component "Detector backend training\n(mvad, pca or ewma)" as Train
  database "Model directory\n(metadata.json + backend state)" as Model

  Ingest -down-> Features : Raw alerts
  Features -down-> Train : Time series + vocabulary
  Train -down-> Model : Trained model, feature contract
}

WI -right-> Ingest : Historical alerts
LF -right-> Ingest : Recorded alerts

@enduml
```

## Detection data flow

Detection fetches the scored window plus the context the model needs, builds features with the model's feature contract, scores each bucket, selects anomalies and delivers each new anomaly once to every configured sink.

```plantuml
@startuml
!define SONAR_COLOR #e1f5ff

database "Wazuh Indexer" as WI
database "Local alert file\n(--debug)" as LF

package "SONAR System" SONAR_COLOR {
  database "Model directory" as Model
  component "Data Ingestion" as Ingest2
  component "Feature Engineering" as Features2
  component "Detector backend\n(PointResult per bucket)" as Detect
  component "Post-Processing" as Pipeline
  component "Delivery\n(sinks + watermarks)" as Delivery
  database "Watermark file" as WM

  Model -down-> Detect : Load model
  Model -right-> Features2 : Feature config, vocabulary
  Ingest2 -down-> Features2 : Raw alerts
  Features2 -down-> Detect : Time series
  Detect -down-> Pipeline : Verdicts
  Pipeline -down-> Delivery : Anomaly documents
  Delivery -right-> WM : Advance per sink
}

component "Wazuh Manager" as Manager
database "Data stream / anomalies index" as DS
component "JSON lines / stdout" as Local

WI -right-> Ingest2 : Recent alerts
LF -right-> Ingest2 : Recorded alerts
Delivery -down-> Manager : SONAR events
Delivery -down-> DS : Create by anomaly_id
Delivery -down-> Local : SONAR events
Manager -up-> WI : SONAR alerts

@enduml
```

## Evaluation data flow

`sonar evaluate` trains a scenario's backend on a training file and scores labelled validation and test files, or scores another detector's exported results (for example RADAR's, written by `sonar export`), with the same metrics and the same decision rule as detection.

```plantuml
@startuml
!define SONAR_COLOR #e1f5ff

database "Labelled splits\n(alert files + label files)" as Splits
database "External detector results\n(sonar export --radar-results)" as Ext

package "SONAR System" SONAR_COLOR {
  component "Feature Engineering" as F3
  component "Detector backend" as B3
  component "Evaluation\n(score, calibrate)" as Eval
  F3 -down-> B3 : Time series
  B3 -down-> Eval : Detections
}

database "Report\n(JSON + Markdown)" as Report

Splits -right-> F3 : Training, validation, test alerts
Splits -down-> Eval : Labels
Ext -down-> Eval : Detections
Eval -right-> Report : Precision, recall, F1, delay,\nfalse alarms/day, calibrated settings

@enduml
```

## Data transformations

| Stage | Input | Output | Transformation |
|-------|-------|--------|----------------|
| **Ingestion** | Wazuh alerts (JSON) from the indexer or a local file | Raw alert list | Time range, scenario `alert_filter`, optional agent filter, exclusion of SONAR's own alerts; only the fields the features read |
| **Feature Engineering** | Raw alerts | Time-series matrix | Regular time grid, per-bucket counts and means, categorical vocabulary |
| **Detector backend** | Time-series matrix | One verdict per bucket | `is_anomaly`, severity (0–1), raw score, feature contributions |
| **Post-Processing** | Verdicts | Anomaly documents | Minimum severity, minimum run length, deterministic `anomaly_id`, model and scenario metadata |
| **Delivery** | Anomaly documents | SONAR events, indexed documents, local lines | Per-sink watermark filtering, Wazuh event derivation, create-only indexing |
| **Evaluation** | Detections, label files | Report | Alarm-level scoring, calibration of threshold and run length |

## Related documentation

- Data flow diagram: `docs/manual/sonar_docs/uml-diagrams.md#data-flow-diagram`
- Architecture details: `docs/manual/sonar_docs/architecture.md#data-flow`