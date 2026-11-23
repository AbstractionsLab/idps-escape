---
active: true
derived: false
level: 1.2
links:
- MRS-031: pKEE0sGm889nXk2Qvqnwlu2RjNmcycWKx2wX-9_9sM8=
- MRS-032: T6hCz4404Ang3Ig9Z1a4aSLoszOGnnuq3HdS2NZZ2LQ=
- MRS-039: -K_FLcCc63SwoERy1DmALXIhaL5t_KOpDmEBzdT0mZY=
- MRS-041: ig3VUk73khs5Lx0Y-Ydr-0gDbCqg5rLE2v_WzcuNP2Y=
- MRS-042: flMQ5MputiFRH6joyGqB6j3xgiSAWqI5mnD4hKn5Rjw=
normative: true
ref: ''
reviewed: uQYPRnKTqw2ZvK73lWLmIjEHs0c8NbHIrDzQzxpBgVU=
---

# SONAR component architecture

The diagram below depicts the high-level component architecture of the SONAR subsystem.

## Component diagram

`cli.py` orchestrates every command (`train`, `detect`, `scenario`, `evaluate`, `export`, `check`, `wazuh install-rules`); the other modules do not call each other except where shown. The detector is pluggable: `engine.py` owns the feature contract and the model directory, and the backends behind the `DetectorBackend` interface only fit, predict and save their own state.

```plantuml
@startuml
!define CLI_COLOR #e1f5ff
!define CORE_COLOR #fff4e1
!define DATA_COLOR #e8f5e9
!define OUTPUT_COLOR #f3e5f5

package "CLI Layer" CLI_COLOR {
  component "cli.py\nCommands and orchestration" as CLIModule
}

package "Configuration" {
  component "config.py\nDataclasses" as ConfigModule
  component "scenario.py\nScenario YAML" as ScenarioModule
  component "paths.py\nSONAR home, file-relative paths" as PathsModule
  component "default_config.yaml\nscenarios/*.yaml" as YAMLConfig
}

package "Core Processing" CORE_COLOR {
  component "features.py\nFeature engineering" as FeaturesModule
  component "engine.py\nModelEngine" as EngineModule
  package "backends/" {
    component "mvad.py" as MVADBackend
    component "pca.py" as PCABackend
    component "ewma.py" as EWMABackend
  }
  component "training_plan.py\nMVAD training pre-flight" as PlanModule
  component "pipeline.py\nPost-processing" as PipelineModule
  component "evaluation.py\nMetrics and calibration" as EvalModule
}

package "Data Access Layer" DATA_COLOR {
  component "wazuh_client.py\nWazuhIndexerClient" as WazuhClient
  component "local_data_provider.py\nDebug data provider" as LocalProvider
  component "indexer.py\nOpenSearch client factory" as IndexerModule
}

package "Delivery" OUTPUT_COLOR {
  component "sinks/\nwazuh, datastream, index, jsonl, stdout" as SinksModule
  component "watermark.py\nPer-sink delivery watermarks" as WatermarkModule
  component "shipper/\nTemplates, ISM policy, bulk create" as ShipperModule
}

package "External Systems" {
  database "Wazuh Indexer\nOpenSearch" as WazuhIndexer
  component "Wazuh Manager" as Manager
  component "Microsoft MVAD\ntime-series-anomaly-detector" as MVADLib
  database "Model directories\nand watermark files" as Files
}

CLIModule --> ScenarioModule
CLIModule --> ConfigModule
CLIModule --> PathsModule
CLIModule --> WazuhClient
CLIModule --> LocalProvider
CLIModule --> FeaturesModule
CLIModule --> EngineModule
CLIModule --> PipelineModule
CLIModule --> EvalModule
CLIModule --> SinksModule
YAMLConfig --> ScenarioModule
ConfigModule --> PathsModule
EngineModule --> FeaturesModule : schema version, vocabulary
EngineModule --> MVADBackend
EngineModule --> PCABackend
EngineModule --> EWMABackend
EngineModule --> Files
MVADBackend --> PlanModule
MVADBackend --> MVADLib
EvalModule --> PipelineModule
PipelineModule --> WatermarkModule : anomaly_id
SinksModule --> WatermarkModule
SinksModule --> ShipperModule
SinksModule --> Manager
WatermarkModule --> Files
WazuhClient --> IndexerModule
ShipperModule --> IndexerModule
IndexerModule --> WazuhIndexer

@enduml
```

## Component responsibilities

| Component | Responsibility |
|-----------|---------------|
| **cli.py** | Command-line interface, argument parsing, configuration building (`apply_scenario_to_config`, `apply_agent`), workflow orchestration of training, detection, realtime polling, evaluation and export |
| **config.py** | Configuration dataclasses |
| **scenario.py** | Scenario YAML loading and validation |
| **paths.py** | SONAR home and resolution of paths relative to the configuration or scenario file, never to the working directory |
| **features.py** | Feature extraction: regular time grid, per-bucket counts and means, categorical vocabulary |
| **engine.py** | `ModelEngine`: backend selection, feature contract, model directory (save and load) |
| **backends/** | Detector backends behind `DetectorBackend`: `mvad` (default), `pca`, `ewma`; each returns one `PointResult` per bucket |
| **training_plan.py** | Reproduces the MVAD library's training arithmetic and refuses training that would perform no update |
| **pipeline.py** | Post-processing: decision rule (`threshold`, `min_consecutive`) and the anomaly document schema |
| **evaluation.py** | Event-level precision, recall, F1, delay and false alarms against label files; calibration |
| **wazuh_client.py** | Alert retrieval from the Wazuh Indexer (point-in-time paging), anomalies index, RADAR detector results |
| **local_data_provider.py** | Debug mode data provider (local JSON files) |
| **indexer.py** | The single OpenSearch client factory (TLS, credentials, timeout) |
| **sinks/** | Anomaly delivery: Wazuh manager events (`file` or `api` transport), data stream, plain index, JSON lines, standard output |
| **watermark.py** | Per-scenario, per-sink delivery watermarks and the deterministic `anomaly_id` |
| **shipper/** | Data stream index templates, ISM policy, bulk document creation |

## Related documentation

- Detailed architecture: `docs/manual/sonar_docs/architecture.md`
- Component diagram: `docs/manual/sonar_docs/uml-diagrams.md#component-diagram`