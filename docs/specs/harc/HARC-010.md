---
active: true
derived: false
level: 1.2
links:
- MRS-032: T6hCz4404Ang3Ig9Z1a4aSLoszOGnnuq3HdS2NZZ2LQ=
- MRS-039: -K_FLcCc63SwoERy1DmALXIhaL5t_KOpDmEBzdT0mZY=
normative: true
ref: ''
reviewed: nnndtxGMJOBCe5nNgyG9QTOOk5NyrVzD18njaPsNue8=
---

# SONAR component architecture

The diagram below depicts the high-level component architecture of the SONAR subsystem.

## Component diagram

```plantuml
@startuml
!define CLI_COLOR #e1f5ff
!define CORE_COLOR #fff4e1
!define DATA_COLOR #e8f5e9
!define SHIPPING_COLOR #f3e5f5

package "CLI Layer" CLI_COLOR {
  component "cli.py\nCommand Interface" as CLIModule
}

package "Core Processing" CORE_COLOR {
  component "scenario.py\nScenario Management" as ScenarioModule
  component "engine.py\nMVAD Engine Wrapper" as EngineModule
  component "pipeline.py\nPost-Processing" as PipelineModule
  component "features.py\nFeature Engineering" as FeaturesModule
}

package "Data Access Layer" DATA_COLOR {
  component "wazuh_client.py\nWazuh API Client" as WazuhClient
  component "local_data_provider.py\nDebug Data Provider" as LocalProvider
}

package "Data Shipping" SHIPPING_COLOR {
  component "shipper/\nOpenSearch Shipping" as ShipperModule
}

package "Configuration" {
  component "config.py\nDataclasses" as ConfigModule
  component "Scenario YAML Files" as YAMLConfig
}

package "External Systems" {
  database "Wazuh Indexer\nOpenSearch" as WazuhIndexer
  component "Microsoft MVAD\ntime-series-anomaly-detector" as MVAD
}

CLIModule --> ScenarioModule
CLIModule --> ConfigModule
ScenarioModule --> EngineModule
EngineModule --> MVAD
EngineModule --> FeaturesModule
FeaturesModule --> WazuhClient
FeaturesModule --> LocalProvider
PipelineModule --> ShipperModule
WazuhClient --> WazuhIndexer
ShipperModule --> WazuhIndexer
YAMLConfig --> ScenarioModule

@enduml
```

## Component responsibilities

| Component | Responsibility |
|-----------|---------------|
| **cli.py** | Command-line interface, argument parsing, workflow orchestration |
| **scenario.py** | YAML scenario loading, validation, configuration merging |
| **engine.py** | MVAD engine lifecycle, training/detection execution |
| **pipeline.py** | Post-processing, anomaly document creation, result formatting |
| **features.py** | Feature extraction, time-series bucketing, data transformation |
| **wazuh_client.py** | Wazuh Indexer API communication, alert retrieval |
| **local_data_provider.py** | Debug mode data provider (JSON file loading) |
| **shipper/** | OpenSearch data stream management, bulk ingestion |
| **config.py** | Configuration dataclasses, type definitions |

## Related documentation

- Detailed architecture: `docs/manual/sonar_docs/architecture.md`
- Component diagram: `docs/manual/sonar_docs/uml-diagrams.md#component-diagram`