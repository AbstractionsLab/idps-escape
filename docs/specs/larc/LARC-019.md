---
active: true
derived: false
level: 1.1
links:
- SRS-038: 30slhgia9ep5-kXDvrH9dQPPLqXk7dT1l8S4UcrImmE=
- SRS-048: 99qSBYETd0wd3i1ZE0oGQqjSxRZUeN9XptzHikj06-M=
normative: true
ref: ''
release: Alpha
reviewed: tBAdaDoIh9oEucE8_W8g6zRzNFEjkbJRqnJPiJn-V_w=
version: '0.1'
---

# SONAR training pipeline sequence

## Training workflow sequence diagram

The training pipeline retrieves historical alerts from Wazuh Indexer, extracts features, and trains the MVAD model.

```plantuml
@startuml
participant "CLI (cli.py)" as CLI
participant "Scenario Loader" as Scenario
participant "Data Provider" as DataProvider
participant "Feature Engineer" as Features
participant "MVAD Engine" as Engine
participant "File System" as Storage

CLI -> Scenario: Load scenario YAML
Scenario --> CLI: UseCase object

CLI -> DataProvider: Fetch alerts (lookback_hours)
DataProvider -> DataProvider: Query Wazuh Indexer
DataProvider --> CLI: Raw alert list

CLI -> Features: Extract features
Features -> Features: Bucket by time
Features -> Features: Aggregate metrics
Features -> Features: Encode categoricals
Features --> CLI: Time-series DataFrame

CLI -> Engine: Initialize MVAD
CLI -> Engine: Train model
Engine -> Engine: Fit multivariate model
Engine --> CLI: Training metrics

CLI -> Storage: Save model
Storage --> CLI: Model path

CLI -> CLI: Log completion
@enduml
```

## Key operations

| Component | Operation | Input | Output |
|-----------|-----------|-------|--------|
| **Scenario Loader** | Parse YAML | Scenario file path | UseCase object |
| **Data Provider** | Fetch alerts | Time range, filters | Raw alerts (JSON) |
| **Feature Engineer** | Extract features | Raw alerts | Time-series DataFrame |
| **MVAD Engine** | Train model | Time-series data | Trained model object |
| **File System** | Persist model | Model object | Model file path |

## Error handling

- **Insufficient data**: Warns if sample count < minimum threshold
- **Missing fields**: Uses default values or raises validation error
- **API failures**: Retries with exponential backoff
- **Model persistence**: Validates write permissions before training

## Related documentation

- Training sequence diagram: `docs/manual/sonar_docs/uml-diagrams.md#training-workflow`