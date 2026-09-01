# IDPS-ESCAPE

IDPS-ESCAPE (Intrusion Detection and Prevention System - Enhanced Security through a Cooperative Anomaly Prediction Engine) is a sub-project of [CyFORT](https://abstractionslab.com/index.php/research-and-development/cyfort/) implementing a **MAPE-K**-based (Monitor, Analyze, Plan, Execute, Knowledge) Security Orchestration, Automation, and Response (**SOAR**) system. Developed in the context of [IPCEI-CIS](https://ec.europa.eu/commission/presscorner/detail/en/ip_23_6246), it targets SMEs, CERT/CSIRT entities, SOC managers, system administrators, security engineers and cloud deployments.

<img src="./docs/manual/_figures/CyFORT-IDPS-ESCAPE-logo.png" alt="cyfort_logo" width="500"/>

**Core components:**
- [**RADAR**](/radar/README.md) - Risk-aware hybrid detection and automated response, deployed and managed end-to-end from a point-and-click web GUI (backed by an API — no manual config editing needed)
- [**SONAR**](/sonar/README.md) - SIEM-oriented multivariate anomaly detection powered by deep learning
- [**ADBox**](/docs/manual/adbox_docs/adbox.md) - Legacy research framework
- **Wazuh integration and management**: all components integrate fully with Wazuh, with RADAR additionally providing Wazuh management and orchestration

**Built on:** [Wazuh](https://wazuh.com/), [OpenSearch](https://opensearch.org/), [SATRAP-DL](https://github.com/AbstractionsLab/satrap-dl), [PyFlowintel](https://github.com/AbstractionsLab/PyFlowintel), [Flowintel](https://github.com/flowintel/flowintel), [MISP](https://www.misp-project.org/), [Suricata](https://suricata.io/)

We adopt a **hybrid detection approach** for defense-in-depth against known and emerging threats, combining signature-based engines (Wazuh, Suricata) and machine learning (ML) algorithms for ML-based anomaly detection (AD) through RADAR and SONAR, relying on [RRCF](https://proceedings.mlr.press/v48/guha16.pdf) (random forest) for streaming data and [MTAD-GAT](https://arxiv.org/pdf/2009.02040) (attention mechanism and deep learning), respectively.

This repository contains complete [documentation](./docs/manual/README.md), user manual, **[interlinked technical specifications](https://abstractionslab.github.io/idps-escape/traceability/index.html)** for traceability, and validation test results, all based on the [C5-DEC](https://abstractionslab.github.io/c5dec/website/product-presentation.html) method.

For a visual user-oriented tour of IDPS-ESCAPE, visit the **[product presentation page](https://abstractionslab.github.io/idps-escape/website/product-presentation.html)**.

<img src="./docs/manual/_figures/IDPS-ESCAPE-product-website.png" alt="idps-escape-website" width="500"/>

## Table of contents

- [IDPS-ESCAPE suite](#idps-escape-suite)
- [Quick start](#quick-start)
- [Documentation](#documentation)
- [Development](#development)
- [Testing](#testing)
- [Disclaimer](#disclaimer)
- [License](#license)
- [Contact](#contact)

## IDPS-ESCAPE suite

### RADAR - Risk-aware AD-based Automated Response

[**RADAR**](/docs/manual/radar_docs/README.md) enhances Wazuh with hybrid detection and intelligent automated response through a fully API-based steering and management layer, following a scenario-based paradigm. Its browser-based GUI provides the complete deployment and operations experience on top of that API:

- **Hybrid detection**: Signature-based (Wazuh, Suricata) + ML-based anomaly detection ([RRCF](https://proceedings.mlr.press/v48/guha16.pdf))
- **Risk-aware actions**: Tiered response (low/medium/high risk) with host isolation, process control, network rules, alert escalation, email notification and incident case creation
- **Automatic case creation**: Incident case creation via integration with the [DECIPHER](https://github.com/AbstractionsLab/satrap-dl/blob/main/decipher/README.md) subsystem of [SATRAP-DL](https://github.com/AbstractionsLab/satrap-dl), [PyFlowintel](https://github.com/AbstractionsLab/PyFlowintel) and [Flowintel](https://github.com/flowintel/flowintel)
- **Flexible deployment**: Local/remote manager and agent configurations
- **Production scenarios**: Default baseline detection, GeoIP detection, log volume monitoring, suspicious login, web scanning detection
- **Web-based GUI**: provides a browser-based control panel covering the full deployment, orchestration and configuration lifecycle

![RADAR Demonstration](/docs/manual/_figures/RADAR_GUI.gif)

See [RADAR README](/docs/manual/radar_docs/README.md), [GUI user manual](/docs/manual/radar_docs/radar-gui-user-manual.md), [scenarios](/radar/scenarios/README.md), [adversarial ML guidance](/docs/manual/radar_docs/adversarial-ml-guidance.md) and [developer README](/radar/README.md).

### SONAR - SIEM-Oriented Neural Anomaly Recognition via multivariate AD

[**SONAR**](/sonar/README.md) provides a standalone SIEM-oriented anomaly detection solution based on deep learning:

- **Multivariate time series AD engine**: modular and optimized multivariate time-series detection based on [MTAD-GAT](https://arxiv.org/pdf/2009.02040)
- **Debug mode**: Offline testing with synthetic data (no infrastructure required)
- **Wazuh integration**: Integrated with Wazuh, the open-source SIEM, for monitoring data ingestion and detection data provision and visualization
- **Scenario-based**: YAML configuration for repeatable workflows
- **RADAR integration**: [SONAR data streams shipping](/docs/manual/sonar_docs/data-shipping-guide.md#integration-with-radar) to Wazuh for automated response and easy ingestion by RADAR
- **Flexible modes**: Real-time, batch, and historical analysis

See [SONAR README](/docs/manual/sonar_docs/README.md), [scenario guide](/docs/manual/sonar_docs/scenario-guide.md), [architecture](/docs/manual/sonar_docs/architecture.md) and [developer README](/sonar/README.md).

### Fully GUI-based deployment and management

RADAR provides a browser-based control panel for production-ready deployment and ongoing management of the Wazuh Manager, Wazuh Agents, and the full RADAR stack — no manual config files or CLI orchestration required. The GUI covers scenario deployment, agent onboarding, configuration, anomaly-detector setup, health checks, and teardown, giving full control over the stack from one place. See the [GUI user manual](/docs/manual/radar_docs/radar-gui-user-manual.md) for details.

## Documentation

See our [user manual](./docs/manual/README.md) for comprehensive documentation on [RADAR](/docs/manual/radar_docs/README.md), and [SONAR](/docs/manual/sonar_docs/README.md). Visit our [traceability page](https://abstractionslab.github.io/idps-escape/traceability/index.html) for interlinked requirements, technical specifications such as architecture diagrams, and test reports.

### ADBox (Legacy)

> **⚠️ Legacy System**: maintained for research continuity only. **Use SONAR for deployments requiring deep learning.**

See the [ADBox manual](/docs/manual/adbox_docs/adbox.md) for documentation.

## Quick start

### RADAR: full-stack GUI deployment and management

**Prerequisites:**

Ensure your environment meets the [resource and network requirements](#requirements) specified below, and then proceed as follows:

1. Create `radar/.env` and update relevant fields (use a copy [env.example](/radar/env.example)):
   - OpenSearch URL, username, password
   - Wazuh API credentials and manager address
   - SMTP settings for email alerts
   - FlowIntel API key (optional, for incident case creation)
   - Webhook URL (default: `http://<manager-ip>:8080/notify`)
2. Start the RADAR GUI using the `radar.sh` script from within the `radar/` directory (after making it executable `chmod +x ./radar.sh`):

```bash
./radar.sh gui
```

Then open the displayed local URL and use the **Deployment** page to deploy the
full stack, onboard agents, configure scenarios, start anomaly detection, run
health checks, and manage teardown. See the [RADAR GUI user manual](/docs/manual/radar_docs/radar-gui-user-manual.md) and [getting started](/docs/manual/radar_docs/radar-getting-started.md) page for full details.

Screenshots depicting the various stages in a Suspicious Login detection and response event flow are provided below.

**Suspicious login detection shown on the Wazuh dashboard:**

![Wazuh Dashboard RADAR Suspicious Login detection](/docs/manual/_figures/RADAR-wazuh-dashboard.png)

**Email notification sent by RADAR automated response:**

![Email alert sent by active response](/docs/manual/_figures/RADAR-email-suspicious-login.png)

**DECIPHER lookup in MISP to compute CTI score (used in RADAR risk score):**

![RADAR DECIPHER MISP lookup — CTI scoring via MISP](/docs/manual/_figures/RADAR-DECIPHER-MISP-lookup.png)

**Automatic incident case created in Flowintel using DECIPHER (subsystem of SATRAP-DL):**

![FlowIntel incident case created by RADAR via DECIPHER](/docs/manual/_figures/RADAR-FlowIntel-case.png)

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

# Production mode with data shipping to Wazuh (viewed in custom dashboard) and usable by RADAR
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

See the [data shipping guide](/docs/manual/sonar_docs/data-shipping-guide.md) for configuration details and the [dashboard tutorial](/docs/manual/adbox_docs/dashboard_tutorial.md) for visualization and instructions explaining how to build such a dashboard (same process for SONAR and ADBox).

![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_25-Dashboard-10.png)

### Evaluating SONAR (5 minutes)

No infrastructure required — debug mode runs the full train → detect → report workflow offline with synthetic data:

```bash
poetry install --with sonar
poetry run sonar scenario --use-case sonar/scenarios/example_scenario.yaml --debug
```

### Requirements

#### Resource requirements by component

| Component | RAM | Storage | CPU |
|-----------|-----|---------|-----|
| **Wazuh Manager** | 8 GB minimum | ~15 GB | 4 cores |
| **SONAR** | 4 GB | ~2 GB (models) | 2 cores |
| **RADAR** | 2 GB | ~1 GB | 2 cores |
| **Wazuh Agents** | 512 MB each | ~500 MB each | 1 core |
| **Full Stack** | 16 GB+ | ~26 GB total | 8+ cores |

See the [custom deployment guides](./docs/manual/custom_deployments/README.md) for optional network requirements and multi-node setups.

### Docker deployment

**Build and run with convenience scripts:**

```bash
# Build images
./build.sh all              # All components
./build.sh sonar            # SONAR only

# Run SONAR
./sonar/sonar.sh check            # Check Wazuh connection
./sonar/sonar.sh scenario --use-case sonar/scenarios/example_scenario.yaml --debug

# Run ADBox (legacy, see the ADBox manual)
./adbox/adbox.sh -u 1
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

See our test report (TRP) in the list of published documents on the [technical specifications traceability page](https://abstractionslab.github.io/idps-escape/traceability/index.html) detailing the validation test campaign results. Unit tests are available in the `tests` folder.

## Disclaimer

RADAR has been validated in controlled environments and is released as stable. SONAR is at most at TRL 6. Conduct a thorough security assessment before deploying either component in production. **Use at your own risk.**

## License

Copyright © itrust Abstractions Lab and itrust consulting. Licensed under [GNU AGPL v3.0](LICENSE). See [AUTHORS](/AUTHORS) for contributors.

## Acknowledgment

Co-funded by the Ministry of the Economy of Luxembourg in the context of the CyFORT project.

## Contact

Abstractions Lab: info@abstractionslab.lu