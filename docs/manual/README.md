# IDPS-ESCAPE user manual

This manual documents all IDPS-ESCAPE components implementing a SOAR system following the MAPE-K paradigm (Monitor, Analyze, Plan, Execute, Knowledge).

**Subsystems:** [**RADAR**](./radar_docs/README.md) (automated response), [**SONAR**](./sonar_docs/README.md) (anomaly detection, at most TRL 6), and [ADBox](./adbox_docs/adbox.md) (legacy, research only).

**Detection approach:** Signature-based (Wazuh, Suricata) + multivariate AD (SONAR) + streaming AD (RRCF via OpenSearch AD plugin).

## Map of content

### RADAR
- [RADAR user README](./radar_docs/README.md) - Documentation hub
- [RADAR developer README](/radar/README.md) - Developer quick reference
- [Getting started](./radar_docs/radar-getting-started.md) - Setup and deployment
- [GUI user manual](./radar_docs/radar-gui-user-manual.md) - Web UI deployment and operations guide
- [Operations](./radar_docs/radar-operations.md) - Command-line reference, health checks, routine administration
- [Tuning](./radar_docs/radar-tuning.md) - Risk weights, tier thresholds, mitigations, detector sensitivity
- [Troubleshooting](./radar_docs/radar-troubleshooting.md) - Diagnosis and resolution of common failures
- [Run AD workflow](./radar_docs/radar-run-ad.md) - Detector and monitor creation
- [Detection rules](./radar_docs/radar-rules.md) - Wazuh rule definitions
- [Scenarios overview](/radar/scenarios/README.md) - Detailed scenario documentation
- [Suspicious login extensibility](./radar_docs/radar-scenarios/suspicious-login-extensibility-guide.md) - Protocol extensibility guide
- [Adversarial ML guidance](./radar_docs/adversarial-ml-guidance.md) - Robustness considerations
- [Webhook service](/radar/webhook/README.md) - Webhook deployment

### SONAR
- [SONAR user README](./sonar_docs/README.md) - Documentation hub
- [SONAR developer README](/sonar/README.md) - Developer quick reference
- [Setup and usage guide](./sonar_docs/setup-guide.md) - Installation and CLI
- [Scenario guide](./sonar_docs/scenario-guide.md) - YAML scenario configuration
- [Data injection guide](./sonar_docs/data-injection-guide.md) - Testing with synthetic data
- [Data shipping guide](./sonar_docs/data-shipping-guide.md) - Production integration
- [Troubleshooting](./sonar_docs/troubleshooting.md) - Common issues and solutions
- [Architecture](./sonar_docs/architecture.md) - System design and patterns
- [Model naming guide](./sonar_docs/model-naming-guide.md) - Model naming and versioning
- [UML diagrams](./sonar_docs/uml-diagrams.md) - System UML diagrams

### Deployment and integration
- [Getting started with full stack](./getting-started-stack.md) - Quick deployment
- [Custom deployment guides](./custom_deployments/README.md) - Optional Suricata + Wazuh deployment patterns

### ADBox (legacy - research only)

> **⚠️ DEPRECATED**: Use SONAR for production. ADBox maintained for research continuity only.

- [ADBox overview](./adbox_docs/adbox.md) - Main documentation
- [Installation](./adbox_docs/adbox_installation.md) - Setup instructions
- [Quick start](./adbox_docs/quick_start.md) - Getting started
- [Use case definition](./adbox_docs/use_case.md) - YAML configuration
- [Engine documentation](./adbox_docs/engine.md) - Core components
- [MTAD-GAT algorithm](./adbox_docs/mtad_gat.md) - Deep learning model
- [Detector data structure](./adbox_docs/detector_data_structure.md) - Output format
- [Data transformation](./adbox_docs/data_transformation.md) - Preprocessing pipeline
- [Run modes](./adbox_docs/runmodes.md) - Batch, realtime, historical
- [Wazuh integration](./adbox_docs/detector_data_stream.md) - Data shipping
- [Dashboard tutorial](./adbox_docs/dashboard_tutorial.md) - Visualization guide
- [Example walkthrough](./adbox_docs/example.md) - Complete example

### Reference
- [Glossary](./adbox_docs/glossary.md) - Terminology and definitions