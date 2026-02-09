# IDPS-ESCAPE

IDPS-ESCAPE (Intrusion Detection and Prevention System - Enhanced Security through a Cooperative Anomaly Prediction Engine) is a sub-project of [CyFORT](https://abstractionslab.com/index.php/research-and-development/cyfort/) implementing a **MAPE-K**-based (Monitor, Analyze, Plan, Execute, Knowledge) Security Orchestration, Automation, and Response (**SOAR**) system. Developed in the context of [IPCEI-CIS](https://ec.europa.eu/commission/presscorner/detail/en/ip_23_6246), it targets SMEs, CERT/CSIRT entities, SOC managers, system administrators, security engineers and cloud deployments.

<img src="./docs/manual/_figures/CyFORT-IDPS-ESCAPE-logo.png" alt="cyfort_logo" width="500"/>

**Core components:**
- [**RADAR**](/radar/README.md) - Risk-aware detection and automated response with Ansible-based deployment
- [**SONAR**](/sonar/README.md) - Production-grade multivariate anomaly detection powered by deep learning
- [**ADBox**](/docs/manual/adbox_docs/adbox.md) - Legacy research framework

**Built on:** [Ansible](https://github.com/ansible/ansible), [OpenSearch](https://opensearch.org/), [Wazuh](https://wazuh.com/), [Flowintel](https://github.com/flowintel/flowintel) and [PyFlowintel](https://github.com/AbstractionsLab/PyFlowintel), [Suricata](https://suricata.io/), [MISP](https://www.misp-project.org/)

We adopt a **hybrid detection approach** for defense-in-depth against known and emerging threats, combining signature-based engines (Wazuh, Suricata) and machine learning (ML) algorithms for ML-based anomaly detection (AD) through SONAR and RADAR relying on [MTAD-GAT](https://arxiv.org/pdf/2009.02040) (attention mechanism and deep learning) and [RRCF](https://proceedings.mlr.press/v48/guha16.pdf) (random forest) for streaming data, respectively.

This repository contains complete [documentation](./docs/manual/README.md), user manual, technical specifications, and validation test reports based on the [C5-DEC](https://github.com/AbstractionsLab/c5dec) method. See our [traceability website](https://abstractionslab.github.io/idps-escape/docs/traceability/index.html) for interlinked specifications and the [TRB page](https://abstractionslab.github.io/idps-escape/docs/traceability/TRB.html) providing our beta phase validation test execution report.

**Table of contents**

- [IDPS-ESCAPE suite](#idps-escape-suite)
- [Quick start](#quick-start)
- [Documentation](#documentation)
- [Development](#development)
- [Testing](#testing)
- [Roadmap](#roadmap)
- [Disclaimer](#disclaimer)
- [License](#license)
- [Contact](#contact)

## IDPS-ESCAPE suite

### RADAR - Risk-aware AD-based Automated Response

[**RADAR**](/radar/README.md) provides hybrid detection and intelligent automated response with [Ansible-based Infrastructure-as-Code](#fully-automated-deployment-with-ansible) deployment:

- **Hybrid detection**: Signature-based (Wazuh, Suricata) + ML-based anomaly detection (RRCF)
- **Risk-aware actions**: Tiered response (low/medium/high risk) with host isolation, process control, network rules, alert escalation, and incident case creation
- **Automatic case creation**: Incident case creation via integration with the DECIPHER subsystem of SATRAP-DL and Flowintel
- **Flexible deployment**: Local/remote manager and agent configurations
- **Production scenarios**: GeoIP detection, log volume monitoring, suspicious login
- **Experimental scenarios**: Insider threat, DDoS, C2 malware (require adaptation)

**Deployment modes:**

| Wazuh Manager | Wazuh Agents | Use Case |
|---------------|--------------|----------|
| Local | Local | Single-node testing/development |
| Local | Remote | Central manager with distributed endpoints |
| Remote | Remote | Fully distributed production |

See [RADAR README](/docs/manual/sonar_docs/README.md), [scenarios](/radar/scenarios/README.md), [adversarial ML guidance](/docs/manual/radar_docs/adversarial-ml-guidance.md) and [developer README](/radar/README.md).

### SONAR - SIEM-Oriented Neural Anomaly Recognition via multivariate AD

[**SONAR**](/sonar/README.md) provides production-grade anomaly detection:

- **Microsoft MVAD engine**: Battle-tested multivariate time-series detection
- **Debug mode**: Offline testing with synthetic data (no infrastructure required)
- **Scenario-based**: YAML configuration for repeatable workflows
- **RADAR integration**: Data shipping to Wazuh for automated response
- **Flexible modes**: Real-time, batch, and historical analysis

See [SONAR README](/docs/manual/sonar_docs/README.md), [scenario guide](/docs/manual/sonar_docs/scenario-guide.md), [architecture](/docs/manual/sonar_docs/architecture.md) and [developer README](/sonar/README.md).

### Fully automated deployment with Ansible

We [provide a complete **Infrastructure-as-Code** (IaC)](/radar/README.md) deployment mechanism using [Ansible](https://github.com/ansible/ansible), enabling teams to spin up a fully operational environment automatically and consistently, currently supporting only RADAR. This ensures a reproducible, scalable installation process suitable for production environments, testbeds, or research. We also provide a [**detailed technical documentation**](/docs/manual/radar_docs/radar-manager-ansible-playbook.md) of the manager automation pipeline.

The automated setup includes:

- **Wazuh Manager**: automatically installed and configured for signature-based and ML-based monitoring, AD and alerting.
- **Wazuh Agents**: deployed to monitored endpoints without manual intervention.
- **RADAR stack**: including all dependencies, configuration templates, and communication channels between RADAR, Wazuh, SONAR, and ADBox.

### ADBox (Legacy)

> **⚠️ Legacy System**: ADBox uses MTAD-GAT for research purposes only. **Use SONAR for all production deployments.**

[ADBox](/docs/manual/adbox_docs/adbox.md) is maintained for research continuity with PyTorch-based Graph Attention Networks. See the [ADBox manual](/docs/manual/adbox_docs/adbox.md) for legacy documentation.

## Documentation

See our [user manual](./docs/manual/README.md) for comprehensive documentation on [RADAR](/radar/README.md), [SONAR](/sonar/README.md), and [ADBox](/docs/manual/adbox_docs/adbox.md). Visit our [traceability page](https://abstractionslab.github.io/idps-escape/docs/traceability/index.html) for interlinked requirements, technical specifications such as architecture diagrams, and test reports ([TRB](https://abstractionslab.github.io/idps-escape/docs/traceability/TRB.html)).

## Quick start

### Decision tree

- **Want full automated response?** Bootstrap [complete RADAR stack](#full-stack-automated-deployment-radar)
- **Need production anomaly detection?** Deploy [SONAR with Wazuh](#production-deployment-with-sonar)
- **Just exploring?** Start with [SONAR debug mode](#evaluating-sonar-5-minutes) (no infrastructure needed)

### Full stack automated deployment (RADAR)

**Prerequisites:**

0. System requirements: Ensure your environment meets the [resource and network requirements](#requirements) specified below
1. Create `radar/.env` with credentials (see [env.example](/radar/env.example)):
   - OpenSearch URL, username, password, SSL certificates
   - Wazuh API credentials and manager address
   - SMTP settings for email alerts
   - FlowIntel API key (optional, for incident case creation)
   - Webhook URL (default: `http://<manager-ip>:8080/notify`)
2. Configure `radar/inventory.yaml` for remote endpoints (if using `--agent remote` or `--manager remote`)

```bash
# Bootstrap entire stack with Ansible
cd radar
sudo ./build-radar.sh geoip_detection --agent remote --manager local --manager_exists false
```

See the [RADAR getting started](/docs/manual/radar_docs/radar-getting-started.md) page for more details.

**What this deploys:**
- Wazuh Manager with scenario-specific rules, decoders, and active responses
- Wazuh Agents on remote endpoints with RADAR Helper (GeoIP enrichment)
- OpenSearch detector and monitor for anomaly detection (only if applicable, e.g. in log volume change scenario)
- Webhook service for alert routing
- Complete automation pipeline for the chosen scenario

Here we provide a screenshot of a successful run of the Geo IP detection RADAR scenario:

The currently implemented active response sends an email to a designated recipient.
![](/docs/manual/_figures/RADAR-GeoIP-detection-Automated-Response-email.png)

Additionally, if Flowintel is configured, the RADAR active response module creates a case in Flowintel for medium and high risk scenarios.
![](/docs/manual/_figures/RADAR-GeoIP-detection-Automated-Response-flowintel.png)

See [RADAR getting started](/docs/manual/radar_docs/radar-getting-started.md) for deployment modes and configuration.

### SONAR usage

SONAR provides scenario-based anomaly detection with flexible execution modes:

```bash
# Install and connect to Wazuh
poetry install --only sonar

# Check Wazuh connection
poetry run sonar check

# Run complete scenario (train + detect)
poetry run sonar scenario --use-case sonar/scenarios/brute_force_detection.yaml

# Debug mode (offline testing with synthetic data)
poetry run sonar scenario --use-case sonar/scenarios/example_scenario.yaml --debug

# Production mode with data shipping to RADAR
poetry run sonar scenario --use-case sonar/scenarios/my_scenario.yaml --ship
```

See the [SONAR documentation](/docs/manual/sonar_docs/README.md) for details. 

**Data shipping for Wazuh and RADAR integration:**

What `--ship` does:

- Creates dedicated data streams in Wazuh Indexer for scenario-specific anomalies
- Enables custom dashboard creation in Wazuh
- Enables real-time monitoring and RADAR automated response integration
- Installs index templates for proper field typing and validation
- Required for production SONAR→RADAR workflows

**Why shipping matters**: Without `--ship`, anomalies are indexed to a generic index. With `--ship`, each scenario gets a dedicated data stream (e.g., `sonar_anomalies_mvad_brute_force_v1`), enabling scenario-specific RADAR rules, dedicated dashboards, and independent data lifecycle policies.

```bash
# Ship anomalies to dedicated data stream during detection
poetry run sonar detect --scenario sonar/scenarios/my_scenario.yaml --ship
```

**Benefits:**
- **Scenario isolation**: Each model gets its own data stream (e.g., `sonar_anomalies_mvad_brute_force_v1`)
- **RADAR integration**: Anomalies automatically available for automated response
- **Dashboard visualization**: Dedicated index for SIEM dashboard widgets
- **Data lifecycle management**: Built-in rollover policies for stream management

See the [data shipping guide](/docs/manual/sonar_docs/data-shipping-guide.md) for configuration details and the [dashboard tutorial](/docs/manual/adbox_docs/dashboard_tutorial.md) for visualization and instructions explaining how to build such a dashboard (same process for SONAR and ADBox).

![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_25-Dashboard-10.png)

### Evaluating SONAR (5 minutes)

**Zero infrastructure required** - SONAR's debug mode uses synthetic test data for offline evaluation:

```bash
# Install and test with debug mode (no Wazuh, no OpenSearch, no containers)
poetry install --with sonar
poetry run sonar scenario --use-case sonar/scenarios/example_scenario.yaml --debug
```

**What debug mode provides:**
- Offline testing with pre-generated synthetic alerts
- Complete train → detect → report workflow
- Model evaluation without infrastructure overhead
- Ideal for proof-of-concept and algorithm evaluation

### Requirements

#### Resource requirements by component

| Component | RAM | Storage | CPU |
|-----------|-----|---------|-----|
| **Wazuh Manager** | 8 GB minimum | ~15 GB | 4 cores |
| **SONAR** | 4 GB | ~2 GB (models) | 2 cores |
| **RADAR** | 2 GB | ~1 GB | 2 cores |
| **Wazuh Agents** | 512 MB each | ~500 MB each | 1 core |
| **Full Stack** | 16 GB+ | ~26 GB total | 8+ cores |

#### Network requirements

- **Wazuh Manager**: Port 55000 (API), Port 1514/1515 (agent communication)
- **OpenSearch/Wazuh Indexer**: Port 9200 (HTTPS)
- **RADAR Webhook**: Port 8080 (configurable in `.env`)
- **FlowIntel** (optional): Port 7006 (API)

#### Deployment flexibility

Components can run on separate nodes for distributed deployments. See [deployment guide](./deployment/README.md) for multi-node setups and [Docker deployment](./deployment/README.md#docker-deployment) for containerized options.

### Docker deployment

**Build and run with convenience scripts:**

```bash
# Build images
./build.sh all              # All components
./build.sh sonar            # SONAR only

# Run SONAR
./sonar.sh check            # Check Wazuh connection
./sonar.sh scenario --use-case sonar/scenarios/example_scenario.yaml --debug

# Run ADBox (legacy)
./adbox.sh -u 1

# Run with custom arguments
./adbox.sh <your-adbox-arguments>
```

**Note**: Docker-based execution requires building the images first with `build.sh`.

## Development

```bash
# Install dependencies
poetry install --with sonar,radar,adbox,test

# Run tests
poetry run pytest tests/sonartests/  # SONAR
poetry run pytest tests/             # All
./radar/test.sh                      # RADAR

# SONAR CLI
poetry run sonar check
poetry run sonar scenario --use-case sonar/scenarios/example.yaml --debug

# Docker builds
./build.sh all
```

See [SONAR README](/sonar/README.md) and [RADAR README](/radar/README.md) for component-specific development guides.

## Testing

See our [traceability page](https://abstractionslab.github.io/idps-escape/docs/traceability/index.html) for test reports ([TRB](https://abstractionslab.github.io/idps-escape/docs/traceability/TRB.html)) and [RADAR test framework](/radar/radar-test-framework/README.md) for automated experimentation.

## Roadmap

- Integration with the [DECIPHER](https://github.com/AbstractionsLab/satrap-dl/tree/main/decipher) subsystem of [SATRAP-DL](https://github.com/AbstractionsLab/satrap-dl)
- Enhancing the RADAR lightweight risk engine with real-time CTI analysis by DECIPHER (in turn integrated with MISP)
- Automating SONAR-RADAR integration
- Scenarios with advanced hybrid correlation (signatures + RRCF + SONAR anomalies)
- Automatic model retraining (schedule-based, drift-triggered)
- Extended categorical feature support
- New scenario templates
- Greater robustness against adversarial ML
- [SATRAP](https://github.com/AbstractionsLab/satrap-dl) CTI integration
- [OpenTRICK](https://github.com/itrust-consulting/OpenTRICK) asset graph conversion

See [Wiki](https://github.com/AbstractionsLab/idps-escape/wiki) for detailed roadmap.

## Disclaimer

Provided for evaluation and testing. While SONAR and RADAR have been deployed in controlled environments, conduct thorough security assessments before production use. **Use at your own risk.**

## License

Copyright © itrust Abstractions Lab and itrust consulting. Licensed under [GNU AGPL v3.0](LICENSE). See [AUTHORS](/AUTHORS) for contributors.

## Acknowledgment

Co-funded by the Ministry of the Economy of Luxembourg in the context of the CyFORT project.

## Contact

Abstractions Lab: info@abstractionslab.lu