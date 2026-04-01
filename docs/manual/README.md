# IDPS-ESCAPE user manual

This manual provides detailed documentation for all IDPS-ESCAPE components implementing a comprehensive SOAR system following the MAPE-K paradigm (Monitor, Analyze, Plan, Execute, Knowledge).

**Key subsystems:** [**RADAR**](./radar_docs/README.md) (automated response), [**SONAR**](./sonar_docs/README.md) (production anomaly detection), and [ADBox](./adbox_docs/adbox.md) (legacy research framework).

**Hybrid detection approach:** Signature-based (Wazuh, Suricata) + multivariate AD (SONAR) + streaming AD (RRCF via OpenSearch AD plugin).

## Core components

### SONAR (Production Anomaly Detection)

[Quick start](./sonar_docs/setup-guide.md) | [Full documentation](./sonar_docs/README.md)

**SONAR** (SIEM-Oriented Neural Anomaly Recognition) is our production-grade multivariate time-series anomaly detection subsystem:
- Multivariate anomaly detection using Microsoft MVAD library
- Scenario-based YAML workflows for repeatable detection strategies
- Debug mode for offline testing without Wazuh infrastructure
- Real-time and batch detection modes
- Data shipping integration to Wazuh data streams for RADAR-driven responses

**Use SONAR for all production deployments.**

### RADAR (Automated Response)

[Getting started](./radar_docs/radar-getting-started.md) | [Full documentation](./radar_docs/README.md)

The [RADAR](/radar/README.md) subsystem provides solutions for completing the SOAR mission of IDPS-ESCAPE:
- Risk-aware automated response orchestration
- OpenSearch AD integration (RRCF-based)
- AD scenario implementations with active response solutions
- SOAR playbooks facilitating security orchestration

## Map of content

### SONAR Documentation
- [SONAR user README](./sonar_docs/README.md) - Documentation hub
- [SONAR developer README](/sonar/README.md) - Developer quick reference
- [Setup and usage guide](./sonar_docs/setup-guide.md) - Installation and CLI
- [Scenario guide](./sonar_docs/scenario-guide.md) - YAML scenario configuration
- [Data injection guide](./sonar_docs/data-injection-guide.md) - Testing with synthetic data
- [Data shipping guide](./sonar_docs/data-shipping-guide.md) - Production integration
- [Troubleshooting](./sonar_docs/troubleshooting.md) - Common issues and solutions
- [Architecture](./sonar_docs/architecture.md) - System design and patterns

### RADAR Documentation
- [RADAR standalone user manual](./radar-user-manual.md) - Single end-user-oriented manual for deployment and operations
- [RADAR README](./radar_docs/README.md) - Main documentation
- [RADAR developer README](/radar/README.md) - Developer quick reference
- [Architecture](./radar_docs/radar-architecture.md) - System design and components
- [Getting started](./radar_docs/radar-getting-started.md) - Setup and deployment
- [Ansible playbook](./radar_docs/radar-manager-ansible-playbook.md) - Automated deployment
- [Run AD workflow](./radar_docs/radar-run-ad.md) - Detector and monitor creation
- [Detection rules](./radar_docs/radar-rules.md) - Wazuh rule definitions
- [Active response](./radar_docs/radar-active-response.md) - Response logic flow
- [Scenarios overview](/radar/scenarios/README.md) - Detailed scenario documentation
- [Webhook service](/radar/webhook/README.md) - Webhook deployment

### Deployment and Integration
- [Getting started with full stack](./getting-started-stack.md) - Quick deployment
- [Joint IDPS + SIEM deployment](../../deployment/README.md) - Suricata + Wazuh

### ADBox (Legacy - Research Only)

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
- [Glossary](./glossary.md) - Terminology and definitions

## SIEM, network and host IDPS and ML-based AD

To achieve comprehensive monitoring capabilities, we combine Suricata, an open-source Network Intrusion Detection System (NIDS), and Wazuh, a cybersecurity platform that integrates SIEM and XDR capabilities; see the [instructions for a joint deployment of IDPS, SIEM/XDR and OpenSearch AD](../../deployment/README.md).