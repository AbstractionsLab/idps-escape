---
active: true
derived: false
level: 1.1
links:
- SRS-072: AruROydDhjW4_MV-cEKfCWgHabyVzlBjT438e2NVVEE=
- SRS-073: OYCkjPvDjTuJLmUG6ZkEVwMF-fhHA7GjAfyI3vA4wP8=
- SRS-074: dzj0g7pw6HswRcv7ya9MQzj2kRCYUDKOlGE1Un8oaj8=
- SRS-079: 9f48bWybySuo6of5O-TzP7V8lKGZHna-QYhJjKO65as=
- SRS-086: Dpg2bXS2OYN2DLt7-GJr2hgdhvAX723BkkWSzKcdio0=
normative: true
ref: ''
release: Alpha
reviewed: m3GhHBe-fO4-QLEr0qQYD7bbm8f4HSv80genukXJ3og=
version: '0.1'
---

# SONAR training pipeline sequence

## Training workflow sequence diagram

The training pipeline retrieves historical alerts, builds the feature matrix and its categorical vocabulary, trains the scenario's detector backend (`mvad` by default, or `pca`, `ewma`) and saves the model directory. Every training command (`sonar train` with or without a scenario, and the training phase of `sonar scenario`) runs this one sequence (`_execute_training_phase` in `sonar/cli.py`).

```plantuml
@startuml
participant "CLI (cli.py)" as CLI
participant "Scenario Loader\n(scenario.py)" as Scenario
participant "Data Provider\n(WazuhIndexerClient or\nLocalDataProvider)" as DataProvider
participant "Feature Builder\n(features.py)" as Features
participant "ModelEngine\n(engine.py)" as Engine
participant "Detector backend\n(backends/)" as Backend
participant "File System" as Storage

CLI -> Scenario: Load scenario YAML (if given)
Scenario --> CLI: UseCase
CLI -> CLI: Build config: base config,\nthen scenario keys, --model-name, --agent

CLI -> DataProvider: Open (--debug: local file; else indexer, check connection)
CLI -> DataProvider: Fetch alerts (lookback_hours, alert_filter)
DataProvider --> CLI: Raw alert list

CLI -> Features: Build time series (grid starts at the first alert)
Features -> Features: Fit categorical vocabulary
Features -> Features: Bucket, count, average
Features --> CLI: Feature matrix + vocabulary

CLI -> Engine: train(matrix, vocabulary)
Engine -> Backend: fit(matrix)
alt too few buckets to learn from
  Backend --> Engine: InsufficientTrainingDataError
  Engine --> CLI: Error (required bucket count)
  CLI -> CLI: Exit 1, nothing saved
else trainable
  Backend --> Engine: Trained state + training record
  CLI -> Engine: save()
  Engine -> Storage: Write staging directory,\nswap in <models_dir>/<model_name>/
  CLI -> CLI: Exit 0
end
@enduml
```

With the `datastream` sink or shipping enabled (and not in debug mode), training then installs the data stream's index templates and ISM policy for the scenario ([SWD-024](../swd/SWD-024.md)).

## Key operations

| Component | Operation | Input | Output |
|-----------|-----------|-------|--------|
| **Scenario Loader** | Parse and validate YAML | Scenario file path | `UseCase` |
| **Data Provider** | Fetch alerts | Time range, `alert_filter` | Raw alerts (JSON); only the fields the features read, SONAR's own alerts excluded |
| **Feature Builder** | Build features | Raw alerts | Time-series matrix, categorical vocabulary |
| **ModelEngine** | Train | Feature matrix, vocabulary | Trained backend, metadata (feature contract, training record) |
| **Detector backend** | Fit | Feature matrix | Backend state (`mvad`: training pre-flight with `sonar/training_plan.py`) |
| **File System** | Persist model | Metadata and backend state | Model directory (no pickle) |

## Error handling

- **Insufficient data**: no alerts with a valid timestamp, or fewer buckets than the backend needs (for `mvad`: one optimiser update and a validation window under the configured parameters; for `pca` and `ewma`: a fixed minimum): training fails, saves nothing and exits with status 1, stating the required bucket count. For `mvad`, fewer updates than `min_gradient_steps` only warns.
- **Invalid parameters**: an unknown key in `extra_params` is an error; unknown keys elsewhere in configuration and scenario files are ignored with a warning.
- **Indexer failures**: every indexer request has a timeout (`wazuh.timeout_seconds`); a failed connection check or search ends training with status 1. Training does not retry.
- **Model persistence**: the model is written to a staging directory and swapped in only when complete, so a failed save leaves the previous model in place.

## Related documentation

- Training sequence diagram: `docs/manual/sonar_docs/uml-diagrams.md#training-workflow`