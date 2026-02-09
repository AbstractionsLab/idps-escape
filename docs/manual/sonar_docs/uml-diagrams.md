# SONAR UML diagrams

This document contains UML diagrams describing the software design of SONAR (SIEM-Oriented Neural Anomaly Recognition), rendered in Mermaid format for GitHub/GitLab compatibility.

## Latest design features (February 2026)

- **Unified scenario format**: Config files (infrastructure) separated from scenario files (detection logic)
- **Automatic column alignment**: Feature mismatches between training and detection handled automatically
- **Debug mode**: Local data provider with configurable test data files
- **Flexible execution**: Training-only, detection-only, or combined workflows
- **Default configuration**: `default_config.yaml` automatically loaded when no `--config` specified

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
        +str model_path
    }

    class WazuhIndexerConfig {
        +str base_url
        +str username
        +str password
        +bool verify_ssl
        +str alerts_index_pattern
        +str anomalies_index
    }

    class MVADConfig {
        +int sliding_window
        +str device
        +Dict extra_params
        +to_params() Dict
    }

    class FeatureConfig {
        +Sequence~str~ numeric_fields
        +int bucket_minutes
        +Sequence~str~ categorical_fields
        +int categorical_top_k
        +bool derived_features
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
        +bool fill_with_synthetic
        +int synthetic_count
        +str synthetic_mode
        +int synthetic_level
        +str synthetic_srcip
    }

    class DetectionScenario {
        +str mode
        +int lookback_minutes
        +Optional~int~ polling_interval_seconds
        +bool fill_with_synthetic
        +int synthetic_count
        +bool print_payloads
        +bool dry_run
        +Optional~str~ payload_dir
        +float threshold
        +int min_consecutive
    }

    %% Core Service Classes
    class WazuhIndexerClient {
        -WazuhIndexerConfig cfg
        -Session session
        -bool print_payloads
        -bool dry_run
        +search_alerts(start, end, query) List~Dict~
        +index_anomaly(doc) str
        +index_alert(doc) str
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
        +build_timeseries(alerts) DataFrame
        -_parse_timestamp(ts) datetime
        -_extract_single_alert_features(alert) Dict
        -_get_nested_field(alert, path) Any
    }

    class MVADModelEngine {
        -PipelineConfig cfg
        -MultivariateAnomalyDetector model
        -List~str~ training_columns
        +train(ts_data) void
        +predict(ts_data) Any
        +save() void
        +load() void
        -_align_columns(ts_data) DataFrame
    }

    class MVADPostProcessor {
        -FeatureConfig feature_cfg
        +build_wazuh_anomaly_docs(timestamps, results, context) List~Dict~
    }

    %% Relationships
    PipelineConfig *-- WazuhIndexerConfig : contains
    PipelineConfig *-- MVADConfig : contains
    PipelineConfig *-- FeatureConfig : contains
    PipelineConfig *-- DebugConfig : contains
    PipelineConfig *-- ShippingConfig : contains

    UseCase *-- TrainingScenario : contains
    UseCase *-- DetectionScenario : contains

    WazuhIndexerClient --> WazuhIndexerConfig : uses
    LocalDataProvider ..|> WazuhIndexerClient : compatible interface
    WazuhFeatureBuilder --> FeatureConfig : uses
    MVADModelEngine --> PipelineConfig : uses
    MVADPostProcessor --> FeatureConfig : uses
```

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
    end

    subgraph DataIngestion["Data ingestion"]
        wazuh_client[wazuh_client.py]
        local_provider[local_data_provider.py]
    end

    subgraph FeatureEngineering["Feature engineering"]
        features[features.py]
    end

    subgraph MLEngine["ML engine"]
        engine[engine.py]
        mvad_lib["time-series-anomaly-detector"]
    end

    subgraph PostProcessing["Post-processing"]
        pipeline[pipeline.py]
    end

    subgraph Shipping["Data shipping (optional)"]
        shipper[shipper/wazuh_data_shipper.py]
        templates[shipper/wazuh_base_template.py]
    end

    subgraph External["External systems"]
        wazuh[(Wazuh/OpenSearch)]
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

    scenario --> config
    wazuh_client --> config
    local_provider --> config
    features --> config
    engine --> config
    pipeline --> config

    engine --> mvad_lib

    cli --> shipper
    shipper --> config
    shipper --> templates
    shipper <--> wazuh

    wazuh_client <--> wazuh
    local_provider --> test_data

    features --> wazuh_client
    features --> local_provider
    pipeline --> wazuh_client
```

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
    participant Engine as MVADModelEngine
    participant MVAD as MultivariateAnomalyDetector
    participant Disk as File System

    User->>CLI: sonar train --lookback-hours 24
    CLI->>Config: load_config(path)
    Config-->>CLI: PipelineConfig

    CLI->>Client: WazuhIndexerClient(cfg.wazuh)
    CLI->>Client: check_connection()
    Client-->>CLI: True

    CLI->>Client: search_alerts(start, end)
    Client-->>CLI: List[alerts]

    CLI->>FB: WazuhFeatureBuilder(cfg.features)
    CLI->>FB: build_timeseries(alerts)
    FB->>FB: _parse_timestamp() for each alert
    FB->>FB: _extract_single_alert_features()
    FB->>FB: Aggregate into time buckets
    FB-->>CLI: DataFrame (time series)

    CLI->>Engine: MVADModelEngine(cfg)
    CLI->>Engine: train(ts_data)
    Engine->>Engine: Validate data shape
    Engine->>MVAD: MultivariateAnomalyDetector()
    Engine->>MVAD: fit(ts_data, params)
    MVAD-->>Engine: trained model
    Engine-->>CLI: void

    CLI->>Engine: save()
    Engine->>Disk: pickle.dump(model)
    Disk-->>Engine: void
    Engine-->>CLI: void

    CLI-->>User: "Training complete"
```

### Detection workflow

Detection workflow showing anomaly detection and result indexing:

```mermaid
sequenceDiagram
    autonumber
    participant User
    participant CLI as cli.py
    participant Client as WazuhIndexerClient
    participant FB as WazuhFeatureBuilder
    participant Engine as MVADModelEngine
    participant PP as MVADPostProcessor
    participant Wazuh as Wazuh Indexer

    User->>CLI: sonar detect --lookback-minutes 10
    CLI->>CLI: load_config()

    CLI->>Engine: MVADModelEngine(cfg)
    CLI->>Engine: load()
    Engine-->>CLI: model loaded

    CLI->>Client: search_alerts(start, end)
    Client->>Wazuh: POST /_search
    Wazuh-->>Client: hits
    Client-->>CLI: List[alerts]

    CLI->>FB: build_timeseries(alerts)
    FB-->>CLI: DataFrame

    CLI->>Engine: predict(ts_data)
    Engine->>Engine: Validate numeric data
    Engine->>Engine: model.predict(ts_clean)
    Engine-->>CLI: prediction results

    CLI->>PP: MVADPostProcessor(cfg.features)
    CLI->>PP: build_wazuh_anomaly_docs(timestamps, results, context)
    PP->>PP: Filter is_anomaly == True
    PP->>PP: Build Wazuh-format documents
    PP-->>CLI: List[anomaly_docs]

    loop For each anomaly
        CLI->>Client: index_anomaly(doc)
        Client->>Wazuh: POST /_doc
        Wazuh-->>Client: doc_id
        Client-->>CLI: doc_id
    end

    CLI-->>User: "Indexed N anomalies"
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
    participant Engine as MVADModelEngine
    participant PP as MVADPostProcessor

    User->>CLI: sonar scenario --use-case scenario.yaml
    CLI->>UC: UseCase.from_yaml(path)
    UC->>UC: Parse YAML
    UC->>UC: Set has_training, has_detection flags
    UC-->>CLI: UseCase instance

    alt UseCase disabled
        CLI-->>User: "Scenario disabled, skipping"
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

        alt Model not in memory
            CLI->>Engine: load()
        end

        loop Detection mode (batch/realtime)
            CLI->>Client: search_alerts(detection window)
            Client-->>CLI: detection alerts
            CLI->>FB: build_timeseries(alerts)
            FB-->>CLI: detection DataFrame
            CLI->>Engine: predict(ts_data)
            Engine-->>CLI: results
            CLI->>PP: build_wazuh_anomaly_docs()
            PP-->>CLI: anomaly_docs
            CLI->>Client: index_anomaly() for each doc
        end
    end

    CLI-->>User: "Scenario complete"
```

---

## State diagram

Model lifecycle states in MVADModelEngine:

```mermaid
stateDiagram-v2
    [*] --> Uninitialized: MVADModelEngine(cfg)

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
        Model persisted to disk
        Can be loaded later
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
        MODEL[(Trained Model<br/>mvad_model.pkl)]
    end

    subgraph Output["Output"]
        direction TB
        RESULTS[Anomaly Results]
        PP[MVADPostProcessor]
        DOCS[Wazuh Anomaly Docs]
    end

    subgraph Storage["Storage"]
        ANOM[(wazuh-anomalies-mvad)]
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
    DOCS --> WC
    WC --> ANOM
```

---

## Package structure

```mermaid
graph TB
    subgraph sonar["📦 sonar"]
        init["__init__.py"]
        cli["cli.py<br/><i>CLI entry point</i>"]
        config["config.py<br/><i>Configuration dataclasses</i>"]
        scenario["scenario.py<br/><i>UseCase YAML handling</i>"]
        wazuh["wazuh_client.py<br/><i>OpenSearch API client</i>"]
        local["local_data_provider.py<br/><i>Debug mode data loading</i>"]
        features["features.py<br/><i>Feature extraction</i>"]
        engine["engine.py<br/><i>MVAD model wrapper</i>"]
        pipeline["pipeline.py<br/><i>Post-processing</i>"]
    end

    subgraph test_data["📁 test_data"]
        normal["normal_baseline.json"]
        anomalies["with_anomalies.json"]
    end

    subgraph model["📁 model"]
        model_file["best_multi_ad_model.pt"]
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
                MVAD[time-series-anomaly-detector]
                Pandas[pandas]
                Requests[requests]
            end
        end

        subgraph Storage["Local storage"]
            Model[(mvad_model.pkl)]
            TestData[(test_data/)]
            Config[(config.yaml)]
        end
    end

    subgraph Wazuh["Wazuh stack"]
        Indexer[(Wazuh Indexer<br/>OpenSearch)]
        Alerts[(wazuh-alerts-*)]
        Anomalies[(wazuh-anomalies-mvad)]
    end

    CLI --> Model
    CLI --> TestData
    CLI --> Config
    CLI --> MVAD
    CLI <-->|HTTPS/REST| Indexer
    Indexer --> Alerts
    Indexer --> Anomalies
```

---

## Notes

- All diagrams are in [Mermaid](https://mermaid.js.org/) format
- GitHub and GitLab render Mermaid diagrams natively in markdown
- For local rendering, use VS Code with Mermaid extension or [Mermaid Live Editor](https://mermaid.live/)
