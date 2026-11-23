# SONAR UML diagrams

This document contains UML diagrams describing the software design of SONAR (SIEM-Oriented Neural Anomaly Recognition), rendered in Mermaid format for GitHub/GitLab compatibility.

## Design features

- **Unified scenario format**: Config files (infrastructure) separated from scenario files (detection logic)
- **Feature contract**: the model stores its feature settings and categorical vocabulary, and detection builds exactly the training columns
- **Debug mode**: Local data provider with configurable test data files
- **Flexible execution**: Training-only, detection-only, or combined workflows
- **Default configuration**: `default_config.yaml` automatically loaded when no `--config` specified
- **Anomaly sinks**: anomalies go to configurable sinks, by default the Wazuh manager, each with its own delivery watermark
- **Detector backends**: `ModelEngine` runs a `DetectorBackend` (`mvad`, `pca` or the `ewma` baseline); post-processing consumes only `PointResult`
- **Model directory**: a model is `<models_dir>/<model_name>/` with `metadata.json` and the backend's state, loaded without unpickling
- **Path independence**: paths in configuration and scenario files are relative to those files; unset ones default to the SONAR home (`sonar/paths.py`)
- **Per-host models**: `--agent NAME` trains and runs one model per host (`<model_name>-<NAME>`), with its own scenario ID
- **Evaluation**: `sonar evaluate` scores a backend's verdicts against labelled data and calibrates `threshold` and `min_consecutive` (`evaluation.py`); `sonar export` writes a live window, its labels and RADAR's detector results for it

## Table of contents

1. [Class diagram](#class-diagram)
2. [Component diagram](#component-diagram)
3. [Sequence diagrams](#sequence-diagrams)
   - [Training workflow](#training-workflow)
   - [Detection workflow](#detection-workflow)
   - [Scenario execution](#scenario-execution)
4. [State diagram](#state-diagram)
5. [Data flow diagram](#data-flow-diagram)

---

## Class diagram

The core classes and their relationships in SONAR:

```mermaid
classDiagram
    direction TB

    %% Configuration Classes
    class PipelineConfig {
        +WazuhIndexerConfig wazuh
        +MVADConfig mvad
        +FeatureConfig features
        +DebugConfig debug
        +ShippingConfig shipping
        +OutputConfig output
        +EWMAConfig ewma
        +PCAConfig pca
        +str backend
        +Optional~str~ models_dir
        +str model_name
        +Optional~str~ agent
        +model_path() str
    }

    class WazuhIndexerConfig {
        +str base_url
        +str username
        +str password
        +bool|str verify_ssl
        +str alerts_index_pattern
        +str anomalies_index
        +float timeout_seconds
        +int max_alerts
        +List~str~ exclude_rule_groups
    }

    class MVADConfig {
        +int sliding_window
        +str device
        +Dict extra_params
        +int min_gradient_steps
        +to_params() Dict
    }

    class EWMAConfig {
        +float alpha
        +float z_threshold
    }

    class PCAConfig {
        +int window
        +float variance
        +float z_threshold
    }

    class FeatureConfig {
        +Sequence~str~ numeric_fields
        +int bucket_minutes
        +Sequence~str~ categorical_fields
        +int categorical_top_k
        +bool|List derived_features
        +Optional~Dict~ alert_filter
        +Sequence~str~ max_numeric_fields
        +str numeric_fill
        +str count_transform
    }

    class DebugConfig {
        +bool enabled
        +str data_dir
        +str training_data_file
        +str detection_data_file
    }

    class ShippingConfig {
        +bool enabled
        +bool install_templates
        +Optional~str~ scenario_id
        +int rollover_days
        +int retention_days
    }

    class OutputConfig {
        +List~str~ sinks
        +str fallback
        +List~str~ debug_sinks
        +Optional~str~ jsonl_path
        +WazuhSinkConfig wazuh
        +Optional~str~ state_dir
    }

    class WazuhSinkConfig {
        +str transport
        +str file_path
        +int max_file_bytes
        +int backup_count
        +str api_url
        +str api_username
        +str api_password
        +bool|str verify_ssl
        +float timeout_seconds
        +float severity_medium
        +float severity_high
    }

    %% Scenario Classes
    class UseCase {
        +str name
        +str description
        +Optional~str~ model_name
        +TrainingScenario training
        +DetectionScenario detection
        +bool enabled
        +bool has_training
        +bool has_detection
        +from_yaml(path) UseCase
        +to_yaml(path) void
    }

    class TrainingScenario {
        +int lookback_hours
        +List~str~ numeric_fields
        +List~str~ categorical_fields
        +int categorical_top_k
        +int bucket_minutes
        +int sliding_window
        +str device
        +Dict extra_params
        +bool|List derived_features
        +Optional~Dict~ alert_filter
        +List~str~ max_numeric_fields
        +str numeric_fill
        +str count_transform
        +int min_gradient_steps
        +Optional~str~ backend
        +Dict ewma
        +Dict pca
    }

    class DetectionScenario {
        +str mode
        +int lookback_minutes
        +Optional~int~ polling_interval_seconds
        +int ingest_delay_seconds
        +int max_consecutive_failures
        +bool print_payloads
        +bool dry_run
        +Optional~str~ payload_dir
        +Optional~float~ threshold
        +int min_consecutive
        +Optional~float~ anomaly_confidence
    }

    %% Core Service Classes
    class WazuhIndexerClient {
        -WazuhIndexerConfig cfg
        -OpenSearch client
        -int max_alerts
        -bool print_payloads
        -bool dry_run
        -str payload_dir
        +search_alerts(start, end, query, source_fields, page_size) List~Dict~
        +search_detector_results(index, start, end, entity) List~Dict~
        +index_anomaly(doc) str
        +check_connection() bool
    }

    class LocalDataProvider {
        -Path data_dir
        -Optional~str~ data_file
        -List~Path~ alert_files
        -List~Dict~ _alerts
        +search_alerts(start, end, query, ignore_time_range) List~Dict~
        +check_connection() bool
        +get_all_alerts() List~Dict~
        +get_stats() Dict
        -_load_alerts() void
        Note: Supports JSON array, single object,
        and OpenSearch API response formats
    }

    class WazuhFeatureBuilder {
        -FeatureConfig cfg
        +FeatureVocabulary vocabulary
        +build_timeseries(alerts, start, end) DataFrame
        +fit_vocabulary(alerts) FeatureVocabulary
        +required_source_fields() List~str~
        +columns() List~str~
        -_parse_timestamp(ts) datetime
    }

    class ModelEngine {
        -PipelineConfig cfg
        -DetectorBackend backend
        -List~str~ training_columns
        -Dict metadata
        +train(ts_data, vocabulary) void
        +predict(ts_data) List~PointResult~
        +save() void
        +load() void
        +feature_config() FeatureConfig
        +vocabulary() FeatureVocabulary
        +context_buckets() int
    }

    class DetectorBackend {
        <<interface>>
        +str name
        +Dict metadata
        +min_points() int
        +fit(df) void
        +predict(df) List~PointResult~
        +save_state(directory) void
        +from_state(directory, metadata)$ DetectorBackend
    }

    class MVADBackend {
        -MVADConfig cfg
        +sliding_window() int
    }

    class EWMABackend {
        -EWMAConfig cfg
        -Dict center
        -Dict scale
    }

    class PCABackend {
        -PCAConfig cfg
        -List~str~ columns
        +window_buckets() int
    }

    class PointResult {
        +Timestamp timestamp
        +bool is_anomaly
        +float severity
        +float raw_score
        +List~Contributor~ contributors
    }

    class MVADPostProcessor {
        -FeatureConfig feature_cfg
        +build_wazuh_anomaly_docs(results, context, threshold, min_consecutive, feature_values) List~Dict~
    }

    class Watermark {
        +str scenario_id
        +Path path
        +load(sink) Optional~Timestamp~
        +advance(sink, bucket_start) Timestamp
    }

    %% Delivery
    class AnomalySink {
        <<interface>>
        +str name
        +emit(docs) DeliveryResult
    }

    class DeliveryResult {
        +int accepted
        +int total
        +Optional~str~ error
        +bool ok
    }

    class WazuhSink {
        +WazuhSinkConfig cfg
        +transport
        +emit(docs) DeliveryResult
    }

    class FileTransport {
        +Path path
        +int max_bytes
        +int backup_count
        +send(lines) Tuple
    }

    class ApiTransport {
        +WazuhApi api
        +send(lines) Tuple
    }

    class WazuhApi {
        +str url
        +request(method, path) Response
    }

    class DataStreamSink
    class WazuhDataShipper {
        +create_documents(stream_name, documents) Tuple
        +install() void
        +create_scenario_stream(scenario_id, scenario_name) str
    }
    class IndexSink
    class JsonlSink
    class StdoutSink

    %% Relationships
    PipelineConfig *-- WazuhIndexerConfig : contains
    PipelineConfig *-- MVADConfig : contains
    PipelineConfig *-- FeatureConfig : contains
    PipelineConfig *-- DebugConfig : contains
    PipelineConfig *-- ShippingConfig : contains
    PipelineConfig *-- OutputConfig : contains
    PipelineConfig *-- EWMAConfig : contains
    PipelineConfig *-- PCAConfig : contains
    OutputConfig *-- WazuhSinkConfig : contains

    UseCase *-- TrainingScenario : contains
    UseCase *-- DetectionScenario : contains

    WazuhIndexerClient --> WazuhIndexerConfig : uses
    LocalDataProvider ..|> WazuhIndexerClient : compatible interface
    WazuhFeatureBuilder --> FeatureConfig : uses
    ModelEngine --> PipelineConfig : uses
    ModelEngine o-- DetectorBackend : runs
    DetectorBackend <|.. MVADBackend
    DetectorBackend <|.. EWMABackend
    DetectorBackend <|.. PCABackend
    MVADBackend --> MVADConfig : uses
    EWMABackend --> EWMAConfig : uses
    PCABackend --> PCAConfig : uses
    DetectorBackend ..> PointResult : returns
    MVADPostProcessor --> FeatureConfig : uses
    MVADPostProcessor ..> PointResult : consumes

    AnomalySink <|.. WazuhSink
    AnomalySink <|.. DataStreamSink
    AnomalySink <|.. IndexSink
    AnomalySink <|.. JsonlSink
    AnomalySink <|.. StdoutSink
    AnomalySink ..> DeliveryResult : returns
    WazuhSink --> WazuhSinkConfig : uses
    WazuhSink --> FileTransport : file
    WazuhSink --> ApiTransport : api
    ApiTransport --> WazuhApi : uses
    IndexSink --> WazuhIndexerClient : index_anomaly
    DataStreamSink --> WazuhDataShipper : create_documents
```

`sinks.deliver()` offers each sink the documents after that sink's watermark and advances the watermark by `DeliveryResult.accepted`. `MVADModelEngine` remains an alias of `ModelEngine`.

---

## Component diagram

High-level component architecture showing the main modules and their dependencies:

```mermaid
flowchart TB
    subgraph CLI["CLI Layer"]
        cli[cli.py]
    end

    subgraph Config["Configuration"]
        config[config.py]
        scenario[scenario.py]
        paths["paths.py<br/>(SONAR home, file-relative paths)"]
    end

    subgraph DataIngestion["Data ingestion"]
        wazuh_client[wazuh_client.py]
        local_provider[local_data_provider.py]
        indexer["indexer.py<br/>(OpenSearch client factory)"]
    end

    subgraph FeatureEngineering["Feature engineering"]
        features[features.py]
    end

    subgraph MLEngine["Model engine"]
        engine["engine.py<br/>(model directory, feature contract)"]
        backends["backends/<br/>(mvad, pca, ewma)"]
        training_plan["training_plan.py<br/>(MVAD training-plan check)"]
        mvad_lib["time-series-anomaly-detector, torch"]
    end

    subgraph PostProcessing["Post-processing"]
        pipeline[pipeline.py]
    end

    subgraph Evaluation["Evaluation"]
        evaluation["evaluation.py<br/>(sonar evaluate, labels, calibration)"]
    end

    subgraph Delivery["Delivery"]
        sinks["sinks/<br/>(deliver, wazuh, indexer, local)"]
        watermark[watermark.py]
    end

    subgraph Shipping["Data stream management"]
        shipper[shipper/wazuh_data_shipper.py]
        templates[shipper/wazuh_base_template.py]
    end

    subgraph External["External systems"]
        wazuh[(Wazuh Indexer)]
        manager["Wazuh manager<br/>(file or server API)"]
        test_data[(Local JSON files)]
    end

    %% Dependencies
    cli --> config
    cli --> scenario
    cli --> wazuh_client
    cli --> local_provider
    cli --> features
    cli --> engine
    cli --> pipeline
    cli --> evaluation
    cli --> training_plan

    config --> paths
    cli --> paths
    wazuh_client --> config
    features --> config
    engine --> config
    engine --> features
    pipeline --> config
    pipeline --> watermark

    engine --> backends
    backends --> mvad_lib
    backends --> training_plan
    pipeline --> backends
    evaluation --> pipeline
    evaluation --> backends

    cli --> sinks
    cli --> shipper
    sinks --> watermark
    sinks --> shipper
    sinks --> wazuh_client
    sinks --> manager
    shipper --> config
    shipper --> templates
    shipper --> indexer

    wazuh_client --> indexer
    indexer --> config
    indexer <--> wazuh
    local_provider --> test_data

```

`features.py` imports only `sonar.config`, and `pipeline.py` only `sonar.config`, the `PointResult` type of `backends/` and `anomaly_id` from `watermark.py`. They receive alert lists and DataFrames from `cli.py` and never call `wazuh_client.py` or `local_data_provider.py` directly. `scenario.py` and `local_data_provider.py` import no other SONAR module. `evaluation.py` scores verdicts against label files with the same decision rule as detection (`select_anomalies` in `pipeline.py`).

`wazuh_client.py` (alert search and the `index` sink) and the shipper (the `datastream` sink) both get their OpenSearch client from `indexer.py`, so URL, credentials, TLS (`verify_ssl`) and timeout behave the same for both. The `wazuh` sink talks to the manager on its own: through a file the manager reads, or through the server API with its own `output.wazuh` settings.

---

## Sequence diagrams

### Training workflow

Complete training workflow from CLI invocation to model persistence:

```mermaid
sequenceDiagram
    autonumber
    participant User
    participant CLI as cli.py
    participant Config as PipelineConfig
    participant Client as WazuhIndexerClient
    participant FB as WazuhFeatureBuilder
    participant Engine as ModelEngine
    participant Backend as DetectorBackend (mvad, pca or ewma)
    participant Disk as File System
    participant Shipper as WazuhDataShipper

    User->>CLI: sonar train --lookback-hours 168
    CLI->>Config: load_config(path)
    Config-->>CLI: PipelineConfig

    CLI->>Client: WazuhIndexerClient(cfg.wazuh)
    CLI->>Client: check_connection()
    Client-->>CLI: True

    CLI->>Client: search_alerts(start, end, alert_filter, source_fields)
    Client-->>CLI: List[alerts]

    CLI->>FB: WazuhFeatureBuilder(cfg.features)
    CLI->>FB: build_timeseries(alerts, end)
    FB->>FB: _parse_timestamp() for each alert
    FB->>FB: fit_vocabulary() (top-k values of the categorical fields)
    FB->>FB: Count and aggregate per bucket, on a regular grid from the first alert to the end of the window
    FB-->>CLI: DataFrame (time series)

    CLI->>Engine: ModelEngine(cfg)
    CLI->>Engine: train(ts_data, vocabulary)
    Engine->>Engine: Validate data shape
    Engine->>Engine: new_backend(cfg)
    Engine->>Backend: fit(ts_data)
    alt Too few buckets to train (mvad: training-plan check)
        Backend-->>CLI: InsufficientTrainingDataError
        CLI-->>User: error with the bucket count needed, exit 1
    end
    Backend-->>Engine: trained state, metadata
    Engine->>Engine: metadata = feature contract + backend record
    Engine-->>CLI: void

    CLI->>Engine: save()
    Engine->>Disk: write metadata.json to a staging directory
    Engine->>Backend: save_state(staging)
    Backend->>Disk: mvad_config.json + mvad_weights.pt, pca_state.json or ewma_state.json
    Engine->>Disk: swap the staging directory in as models_dir/model_name
    Engine-->>CLI: void

    opt datastream sink (output.sinks or --ship), not in debug runs
        CLI->>Shipper: WazuhDataShipper(cfg.wazuh, install=install_templates)
        Shipper->>Shipper: install() if install_templates: index templates, MVAD component, ISM policy
        CLI->>Shipper: create_scenario_stream(scenario_id)
    end

    CLI-->>User: "Training complete"
```

### Detection workflow

Detection workflow showing anomaly detection and delivery to the sinks (here `wazuh` with the `api` transport, and `datastream`):

```mermaid
sequenceDiagram
    autonumber
    participant User
    participant CLI as cli.py
    participant Client as WazuhIndexerClient
    participant FB as WazuhFeatureBuilder
    participant Engine as ModelEngine
    participant PP as MVADPostProcessor
    participant Wazuh as Wazuh Indexer
    participant Manager as Wazuh manager API

    User->>CLI: sonar detect --lookback-minutes 10
    CLI->>CLI: load_config()

    CLI->>Engine: ModelEngine(cfg)
    CLI->>Engine: load()
    Engine->>Engine: Read metadata.json, check schema and format
    Engine->>Engine: backend_class(backend).from_state(directory)
    Engine-->>CLI: model loaded
    CLI->>CLI: Adopt the model's feature config (including alert_filter)

    CLI->>Client: search_alerts(window start - context, window end, alert_filter, source_fields)
    Client->>Wazuh: POST /{alerts_index_pattern}/_search/point_in_time (keep_alive 2m)
    Wazuh-->>Client: pit_id
    loop Until a page is short or max_alerts is reached
        Client->>Wazuh: POST /_search (pit, sort timestamp desc + id, search_after, size 10000)
        Wazuh-->>Client: page of hits
    end
    Client->>Wazuh: DELETE /_search/point_in_time
    Client-->>CLI: List[alerts] (oldest first)

    CLI->>FB: WazuhFeatureBuilder(model feature config, model vocabulary)
    CLI->>FB: build_timeseries(alerts, window start - context, window end)
    FB-->>CLI: DataFrame

    alt No alerts, or fewer buckets than the model needs
        CLI-->>User: exit 2 (nothing scored)
    end

    CLI->>Engine: predict(ts_data)
    Engine->>Engine: Validate numeric data and training columns
    Engine->>Engine: backend.predict(ts_clean)
    Engine-->>CLI: List[PointResult]
    CLI->>CLI: Keep results inside the scored window

    CLI->>PP: MVADPostProcessor(cfg.features)
    CLI->>PP: build_wazuh_anomaly_docs(results, context, threshold, min_consecutive, feature_values)
    PP->>PP: Keep is_anomaly with severity >= threshold, in runs >= min_consecutive
    PP->>PP: Build Wazuh-format documents
    PP-->>CLI: List[anomaly_docs]

    loop For each sink
        CLI->>CLI: Keep anomalies after this sink's watermark
        alt wazuh sink
            CLI->>Manager: POST /events (up to 100 SONAR events, bearer token)
            Manager-->>CLI: accepted / failed items
        else datastream sink
            CLI->>Wazuh: POST /_bulk (create under anomaly_id)
            Wazuh-->>CLI: 201, or 409 (already stored, counts as accepted)
        end
        CLI->>CLI: Advance this sink's watermark over the accepted anomalies
    end

    opt A sink rejected anomalies and output.fallback is set
        CLI->>Wazuh: Write the rejected anomalies to the fallback
    end

    alt At least one sink accepted (or nothing to deliver)
        CLI-->>User: exit 0 (failed sinks retry on the next run)
    else Every sink failed and no fallback took them
        CLI-->>User: exit 1
    end
```

### Scenario execution

Complete scenario execution with flexible phase detection:

```mermaid
sequenceDiagram
    autonumber
    participant User
    participant CLI as cli.py
    participant UC as UseCase
    participant Client as WazuhIndexerClient/LocalDataProvider
    participant FB as WazuhFeatureBuilder
    participant Engine as ModelEngine
    participant PP as MVADPostProcessor

    User->>CLI: sonar scenario --use-case scenario.yaml
    CLI->>UC: UseCase.from_yaml(path)
    UC->>UC: Parse YAML
    UC->>UC: Set has_training, has_detection flags
    UC-->>CLI: UseCase instance

    alt UseCase disabled
        CLI-->>User: "Scenario disabled, skipping"
    end

    opt has_detection == True
        CLI->>CLI: Check sink, fallback and transport names (exit 1 on an unknown one)
    end

    alt has_training == True
        Note over CLI: Phase 1: Training
        CLI->>Client: search_alerts(training window)
        Client-->>CLI: training alerts
        CLI->>FB: build_timeseries(alerts)
        FB-->>CLI: training DataFrame
        CLI->>Engine: train(ts_data)
        Engine-->>CLI: void
        CLI->>Engine: save()
    end

    alt has_detection == True
        Note over CLI: Phase 2: Detection

        CLI->>Engine: load() (from disk, also right after training)

        loop Once for historical/batch, once per bucket for realtime (until Ctrl+C)
            CLI->>Client: search_alerts(detection window)
            Client-->>CLI: detection alerts
            CLI->>FB: build_timeseries(alerts)
            FB-->>CLI: detection DataFrame
            alt No alerts, or fewer buckets than the model needs
                Note over CLI: Warn and score nothing (one-shot run exits 2, realtime keeps polling)
            else Enough buckets
                CLI->>Engine: predict(ts_data)
                Engine-->>CLI: results
                CLI->>PP: build_wazuh_anomaly_docs(threshold, min_consecutive)
                PP-->>CLI: anomaly_docs (flagged by the backend, severity at least threshold, in long enough runs)
                alt Debug run (--debug or debug.enabled)
                    Note over CLI: Deliver to output.debug_sinks (stdout by default), no watermark
                else Dry run
                    Note over CLI: Write the events to payload_dir/anomalies.jsonl, no watermark
                else Normal run
                    CLI->>CLI: deliver() to output.sinks (+ datastream with --ship), each after its own watermark
                    alt At least one sink accepted
                        Note over CLI: Watermarks advance per sink, failed sinks retry next run
                    else Every sink failed, no fallback took them
                        Note over CLI: Run fails
                    end
                end
            end
            opt Realtime poll failed
                Note over CLI: Retry after 10 s, doubling per failure up to one bucket. Exit 1 after max_consecutive_failures failures in a row
            end
        end
    end

    CLI-->>User: "Scenario complete"
```

---

## State diagram

Model lifecycle states in ModelEngine:

```mermaid
stateDiagram-v2
    [*] --> Uninitialized: ModelEngine(cfg)

    Uninitialized --> Training: train(ts_data)
    Uninitialized --> Loaded: load()

    Training --> Trained: fit() complete
    Trained --> Saved: save()
    Saved --> Loaded: load()

    Loaded --> Predicting: predict(ts_data)
    Trained --> Predicting: predict(ts_data)

    Predicting --> Loaded: prediction complete
    Predicting --> Trained: prediction complete

    Trained --> Training: retrain with new data
    Loaded --> Training: retrain with new data

    note right of Uninitialized
        No model loaded
        predict() raises RuntimeError
    end note

    note right of Trained
        Model in memory
        Can predict or save
    end note

    note right of Saved
        Model directory on disk
        metadata.json and backend state
    end note
```

---

## Data flow diagram

End-to-end data transformation pipeline:

```mermaid
flowchart LR
    subgraph Input["Data sources"]
        WZ[(Wazuh Indexer)]
        LF[(Local JSON Files)]
    end

    subgraph Ingestion["Ingestion layer"]
        WC[WazuhIndexerClient]
        LP[LocalDataProvider]
    end

    subgraph Transform["Transformation"]
        direction TB
        RAW[Raw Alerts<br/>List~Dict~]
        TS[Time Series<br/>DataFrame]
        FB[WazuhFeatureBuilder]
    end

    subgraph ML["ML processing"]
        direction TB
        TRAIN[Training]
        PRED[Prediction]
        MODEL[("Model directory<br/>models_dir/model_name/")]
    end

    subgraph Output["Output"]
        direction TB
        RESULTS["PointResult per bucket"]
        PP[MVADPostProcessor]
        DOCS[Wazuh Anomaly Docs]
    end

    subgraph Sinks["Sinks"]
        MGR[Wazuh manager<br/>rules 100500-100519]
        STREAM[(sonar_anomalies_mvad_id)]
        LOCAL[jsonl / stdout]
    end

    %% Flow
    WZ --> WC
    LF --> LP

    WC --> RAW
    LP --> RAW

    RAW --> FB
    FB --> TS

    TS --> TRAIN
    TRAIN --> MODEL
    MODEL --> PRED
    TS --> PRED

    PRED --> RESULTS
    RESULTS --> PP
    PP --> DOCS
    DOCS --> MGR
    DOCS -.-> STREAM
    DOCS -.-> LOCAL
    MGR -->|SONAR alerts, excluded from alert search| WZ
```

---

## Package structure

```mermaid
graph TB
    subgraph sonar["📦 sonar"]
        init["__init__.py"]
        cli["cli.py<br/><i>CLI entry point</i>"]
        main["__main__.py<br/><i>python -m sonar</i>"]
        paths["paths.py<br/><i>SONAR home, file-relative paths</i>"]
        config["config.py<br/><i>Configuration dataclasses</i>"]
        scenario["scenario.py<br/><i>UseCase YAML handling</i>"]
        wazuh["wazuh_client.py<br/><i>Alert search, anomaly indexing</i>"]
        indexer["indexer.py<br/><i>OpenSearch client factory</i>"]
        local["local_data_provider.py<br/><i>Debug mode data loading</i>"]
        features["features.py<br/><i>Feature extraction</i>"]
        engine["engine.py<br/><i>Model engine, model directory</i>"]
        backends["backends/<br/><i>mvad, pca, ewma detector backends</i>"]
        training_plan["training_plan.py<br/><i>MVAD training-plan check</i>"]
        pipeline["pipeline.py<br/><i>Post-processing</i>"]
        evaluation["evaluation.py<br/><i>Labels, scoring, calibration</i>"]
        watermark["watermark.py<br/><i>Per-sink delivery watermarks</i>"]
        sinks["sinks/<br/><i>Anomaly sinks and delivery</i>"]
        shipper["shipper/<br/><i>Data stream templates, ISM policy</i>"]
        wazuhdir["wazuh/<br/><i>Rules, localfile block, compose overlay</i>"]
    end

    subgraph test_data["📁 test_data"]
        normal["normal_baseline.json"]
        anomalies["with_anomalies.json"]
    end

    subgraph models["📁 models (not in git)"]
        model_dir["model_name/<br/><i>metadata.json + backend state</i>"]
        state_dir["state/<br/><i>delivery watermarks</i>"]
    end

    subgraph docs["📁 docs"]
        readme["README.md"]
        other["...other docs"]
    end
```

---

## Deployment view

```mermaid
flowchart TB
    subgraph Host["Host machine"]
        subgraph Poetry["Poetry environment"]
            CLI[SONAR CLI]
            subgraph Deps["Dependencies"]
                MVAD[time-series-anomaly-detector, torch]
                Pandas[pandas, NumPy]
                OpenSearchPy[opensearch-py]
            end
        end

        subgraph Storage["Local storage"]
            Model[("models_dir<br/>(default sonar/models/)")]
            TestData[(test_data/)]
            Config[(config.yaml)]
        end
    end

    subgraph Wazuh["Wazuh stack"]
        Manager[Wazuh manager<br/>SONAR rules 100500-100519]
        Indexer[(Wazuh Indexer<br/>OpenSearch)]
        Alerts[(wazuh-alerts-*)]
        Streams[(sonar_anomalies_mvad_*<br/>datastream sink)]
    end

    CLI --> Model
    CLI --> TestData
    CLI --> Config
    CLI --> MVAD
    CLI <-->|"HTTPS: alert search, datastream sink"| Indexer
    CLI -->|"file transport: anomalies.json (manager host)<br/>api transport: POST /events (dedicated host)"| Manager
    Manager -->|SONAR alerts| Alerts
    Indexer --> Alerts
    Indexer --> Streams
```

SONAR runs on the manager host or on a dedicated host, never on monitored endpoints; no Wazuh agent is needed on the SONAR host.

---

## Notes

- All diagrams are in [Mermaid](https://mermaid.js.org/) format
- GitHub and GitLab render Mermaid diagrams natively in markdown
- For local rendering, use VS Code with Mermaid extension or [Mermaid Live Editor](https://mermaid.live/)
