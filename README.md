# IDPS-ESCAPE

IDPS-ESCAPE, short for Intrusion Detection and Prevention Systems for Evading Supply Chain Attacks and Post-compromise Effects, is a sub-project of the [CyFORT](https://abstractionslab.com/index.php/research-and-development/cyfort/) project, which in turn stands for Cloud Cybersecurity Fortress of Open Resources and Tools for Resilience. CyFORT is carried out in the context of the [IPCEI-CIS](https://ec.europa.eu/commission/presscorner/detail/en/ip_23_6246) project. 

<img src="./docs/manual/_figures/CyFORT-IDPS-ESCAPE-logo.png" alt="cyfort_logo" width="500"/>

IDPS-ESCAPE is aimed at closely capturing the notion of **MAPE-K** (Monitor, Analyze, Plan, Execute and Knowledge) from autonomic computing applied to cybersecurity, which translates into a comprehensive package that implements a Security Orchestration, Automation, and Response (**SOAR**) system.

The resulting SOAR system combines the following building blocks: a Security Information and Event Management (SIEM) system, an Intrusion Detection and Prevention System (IDPS), Cyber Threat Intelligence (CTI) tools, a Risk-aware AD-based Automated Response ([**RADAR**](/soar-radar/README.md)) subsystem providing AD scenario implementations, coupled with active response solutions and SOAR playbooks facilitating security orchestration, and an anomaly detection (AD) subsystem called [**ADBox**](/docs/manual/README.md).

We adopt a hybrid method aimed at robustness and resilience to adversarial interference involving three elements: (i) signature-based detection with (ii) AD based on deep learning models via MTAD-GAT, relying on state-of-the-art advances in artificial intelligence (AI) and machine learning (ML) such as the *attention mechanism* and (iii) a classical algorithm for AD on streams such as the Robust Random Cut Forest (RRCF) algorithm supporting categorical features.

This repository contains the source code and full documentation (requirements, technical specifications, schematics, [user manual](./docs/manual/README.md), validation test case specifications and test reports) of IDPS-ESCAPE, based on the [C5-DEC](https://github.com/AbstractionsLab/c5dec) method and software also developed in CyFORT, which relies on storing, interlinking and processing all software development life cycle (SDLC) artifacts in a unified manner; see our [traceability web page](https://abstractionslab.github.io/idps-escape/docs/traceability/index.html) providing the technical specifications of IDPS-ESCAPE.

**Table of contents**

- [Overview](#overview)
- [Features](#features)
- [User manual](#user-manual)
- [Technical specifications](#documentation-and-technical-specifications)
- [Getting started](#getting-started)
  - [RADAR usage](#radar-usage)
    - [RADAR and full stack automated installation](#radar-and-full-stack-automated-installation)
    - [RADAR outcome in Wazuh](#radar-outcome-in-wazuh-dashboard)
  - [ADBox usage](#adbox-usage)
    - [Use case scenario example](#example-of-a-use-case-scenario)
    - [Wazuh-ADBox integration and detector dashboard](#wazuh-adbox-integration-and-detector-dashboard)
- [Integrations](#integrations)
- [Disclaimer](#disclaimer-use-of-alphaexperimental-software)
- [Testing](#testing)
- [Roadmap](#roadmap)
- [License](#license)
- [Contact](#contact)

## Overview

IDPS-ESCAPE, part of the [CyFORT](https://abstractionslab.com/index.php/research-and-development/cyfort/) suite of open-source cybersecurity software solutions, addresses various aspects of cybersecurity as an ensemble, targeting different user groups, ranging from public to private and from CERT/CSIRT entities to system administrators, and cloud-native deployments. IDPS-ESCAPE is being developed in parallel with another CyFORT sub-project, namely [SATRAP-DL](https://github.com/AbstractionsLab/satrap-dl), aimed at enhancing cyber threat intelligence (CTI) analysts' work using semi-automated reasoning over CTI.
 
As part of the alpha release, the main bulk of this repository is dedicated to a novel open-source and extensively documented anomaly detection (AD) toolbox and framework, called [**ADBox**](/docs/manual/README.md), and a Risk-aware AD-based Automated Response ([**RADAR**](/soar-radar/README.md)) subsystem implementing AD scenarios and automated response to fulfill the SOAR mission of IDPS-ESCAPE.

IDPS-ESCAPE builds on top of well-known open-source solutions such as [Ansible](https://github.com/ansible/ansible) for configuration management, deployment and infrastructure automation, [OpenSearch](https://opensearch.org/) for search and analytics, [Wazuh](https://wazuh.com/) as our SIEM\&XDR of choice, in turn connected to [MISP](https://www.misp-project.org/) and [OpenCTI](https://github.com/OpenCTI-Platform/opencti) for bidirectional SIEM-TIP enrichment of SIEM alerts and CTI content, and finally [Suricata](https://suricata.io/), acting both as our network-based IDPS of choice, as well as a network-level data acquisition source.

## Features

### Design

- Free/libre and open source;
- Cross platform: works on GNU/Linux, MacOS and Windows;
- Extensible due to a modular design and architecture;
- Based on open data formats such as Markdown, YAML, XML, JSON, CSV and HTML;
- Integrated with well-known open-source security solutions such as [OpenSearch](https://opensearch.org/), [Wazuh](https://wazuh.com/), [Suricata](https://suricata.io/);
- Thanks to building on top of Wazuh, an easy integration with other well-known [third-party solutions](https://documentation.wazuh.com/current/getting-started/use-cases/threat-hunting.html) such as [MISP](https://www.misp-project.org/) using existing mechanisms.

### RADAR

A collection of Risk-aware Anomaly Detection-based Automated Response ([**RADAR**](/soar-radar/README.md)) modules that complete the Security Orchestration, Automation and Response ([**SOAR**](/soar-radar/README.md)) mission of IDPS-ESCAPE, enhancing a traditional IDS/IPS setup by adding intelligent, adaptive, and automated decision-making capabilities on top of both signature-based detections and ML-based anomaly detection signals, providing

- RADAR scenario implementations, including anomaly detectors along with their corresponding active response solutions implemented for Wazuh, currently geared towards an [Amazon AWS implementation](https://github.com/aws/random-cut-forest-by-aws/) of the classical [Robust Random Cut Forest (RRCF) AD on streams algorithm](https://www.amazon.science/publications/robust-random-cut-forest-based-anomaly-detection-on-streams) integrated into Wazuh, enabled by installing the [OpenSearch AD plugin](https://wazuh.com/blog/enhancing-it-security-with-anomaly-detection/), supporting [categorical features](https://docs.opensearch.org/docs/latest/observing-your-data/ad/index/#setting-categorical-fields-for-high-cardinality);
- **Hybrid detection approach**, for a blended strategy aimed at reducing false negatives and increasing coverage across both known and emerging threat types:
  - ML-based anomaly detection (via ADBox and RRCF) for identifying previously unknown or behavior-based threats,
  - Signature-based detection (via Wazuh, Suricata, and a rule-based system) for precise detection of known attacks.
- **Risk-aware automated response**: RADAR is designed to evaluate alerts in context (severity, type, asset value, correlation with other events) and can apply automated response actions such as:
  - host isolation,
  - network rule deployment,
  - escalation or alerting,
  - remediation tasks.
- **Native integration with open-source tooling**:
  - Wazuh (log collection, endpoint monitoring, signature-based detection),
  - Suricata (network IDS/IPS),
  - [ADBox](#adbox) (custom anomaly detection engine powered by deep learning).
- A dedicated [RADAR test framework](/soar-radar/radar-test-framework/README.md) capable of automating the execution of RADAR experimentation pipelines, from data ingestion to attack simulation, detection and post-processing;
- A comprehensive [RADAR manual](/soar-radar/README.md) describing best practices for making use of our ADBox for AD powered by deep learning, in hybrid mode, together with the classical RRCF-based AD algorithm built into OpenSearch to tackle various AD and ML challenges, e.g., adversarial ML involving training data set poisoning and trained model manipulation.

### Fully automated deployment with Ansible

We [provide a complete **Infrastructure-as-Code** (IaC)](/soar-radar/README.md) deployment mechanism using [Ansible](https://github.com/ansible/ansible), enabling teams to spin up a fully operational environment automatically and consistently, currently supporting only RADAR. This ensures a reproducible, scalable installation process suitable for production environments, testbeds, or research. We also provide a [**detailed technical documentation**](/docs/manual/radar-manager-ansible-playbook.md) of the manager automation pipeline.

The automated setup includes:

- **Wazuh Manager**: automatically installed and configured for signature-based and ML-based monitoring, AD and alerting.
- **Wazuh Agents**: deployed to monitored endpoints without manual intervention.
- **RADAR stack**: including all dependencies, configuration templates, and communication channels between RADAR, Wazuh, and ADBox.

### ADBox

[ADBox](/docs/manual/README.md) is a custom-designed and implemented _anomaly detection_ subsystem, with its key features summarized as follows:

- A data ingestion module capable of fetching data from Wazuh and OpenSearch via a REST API;
- A data transformation module for preprocessing, data type conversions and data aggregation;
- A configuration management module for controlling backend configurations via dedicated files and loading such data into memory, (e.g., Wazuh, ML training parameters, etc.);
- A data management module for centralizing data storage and retrieval and managing created and stored detectors, with dedicated features for saving trained ML models and their associated parameterization data, both used by detectors;
- An integration of a machine learning package providing a [PyTorch-based implementation](https://github.com/ML4ITS/mtad-gat-pytorch) of the [MTAD-GAT algorithm](https://arxiv.org/pdf/2009.02040);
- A dedicated anomaly detection engine (called AD Engine), aimed at orchestrating and generalizing common AD tasks and capturing them via an abstract and extensible design and implementation (currently under active development);
- A driver module providing the entry point to the ADBox and currently using a CLI to interact with the user;
- A set of AD use-case scenario definitions encoded as YAML files, which can be directly used by the user, but they can also easily form the basis for creating new ones, tailored to the user's preferences for adjusting the training part as well as the prediction part of the ML-based algorithm and pipeline;
- A data shipper module to integrate the output anomaly detection data into Wazuh, allowing the user to view and analyze the ADBox prediction results using the native Wazuh GUI and dashboards.

### Front-end

- A command-line interface (**CLI**) for efficient user interactions and automation via scripting integration, currently available via the driver module (under active development);
- A dedicated Jupyter notebook for analysis and post-processing, providing a prepared playbook with tailored plotting and operating directly on top of anomaly prediction data produced by the ADBox backend;
- Integration into the Wazuh Dashboard, with the possibility to create dedicated detector dashboards to compare predictions with the original data.

### Integration package

- Artifacts (manuals, Docker compose files, configuration files, code and scripts) for integrating other tools with IDPS-ESCAPE, e.g., MISP, OpenCTI, OpenBAS, [SATRAP](https://github.com/AbstractionsLab/satrap-dl) and [OpenTRICK](https://github.com/itrust-consulting/OpenTRICK);
- Manuals providing tips and best practices for improving such integrations and avoiding certain pitfalls.

### Network and host monitoring

To achieve comprehensive monitoring capabilities, we combine well-established open-source solutions, namely [Wazuh](https://wazuh.com/), a cybersecurity platform that integrates SIEM and XDR capabilities and [Suricata](https://suricata.io/), an open-source Network Intrusion Detection System (NIDS). We provide deployment solutions that allow centralized monitoring for coping with limited resources (network agents relaying traffic data to a central node for processing) as well as running monitoring instances on each node and only grouping the obtained monitoring data in a centralized node for analysis.

See our [instructions for a joint deployment of IDPS, SIEM and ML-based OpenSearch AD](./deployment/README.md) for further details.

## User manual

Please see our extensive and detailed [IDPS-ESCAPE user manual](./docs/manual/README.md) to learn more about [RADAR](/soar-radar/README.md), and [ADBox](/docs/manual/adbox.md); we cover their setup requirements, installation, overall usage, specific modules of each and technical details covering internal aspects that are relevant for an effective use of the IDPS-ESCAPE suite of tools. You will also find dedicated [instructions for a network IDPS plus SIEM integrated deployment](./deployment/README.md), describing our combined architectural setup using Wazuh, Suricata and various networking deployment solutions.

## Documentation and technical specifications

You can visit our [traceability page](https://abstractionslab.github.io/idps-escape/docs/traceability/index.html) to view the technical specifications of IDPS-ESCAPE, e.g., [HARC](https://abstractionslab.github.io/idps-escape/docs/traceability/HARC.html) for high-level and [LARC](https://abstractionslab.github.io/idps-escape/docs/traceability/LARC.html) for low-level architectural diagrams, mission and system requirement specifications ([MRS](https://abstractionslab.github.io/idps-escape/docs/traceability/MRS.html) and [SRS](https://abstractionslab.github.io/idps-escape/docs/traceability/SRS.html)), software design artifacts ([SWD](https://abstractionslab.github.io/idps-escape/docs/traceability/SWD.html)), software validation test case specifications ([TST](https://abstractionslab.github.io/idps-escape/docs/traceability/TST.html)) and validation test campaign test reports ([TRB](https://abstractionslab.github.io/idps-escape/docs/traceability/TRB.html)).

## Getting Started

### RADAR and full stack automated installation

See the [main RADAR manual page](./soar-radar/README.md) to learn how to use the `build-rader.sh` script to bootstrap the entire IDPS-ESCAPE stack and RADAR dependencies, powered by Ansible.

### RADAR usage

The [RADAR](/soar-radar/README.md) subsystem provides solutions for completing the SOAR mission of IDPS-ESCAPE enabling security orchestration and automation driven by a Risk-aware AD-based active response (AR) paradigm. Please see the corresponding RADAR [README](/soar-radar/README.md) for more information.

Run `build-radar.sh` to bring up core services, optionally agent containers, run the Ansible playbook limited to the manager + agent group for the selected scenario, and build `radar-cli:latest`.

**Usage:**
```bash
build-radar.sh <scenario> --agent <local|remote> --manager <local|remote> 
                          --manager_exists <true|false> [--ssh-key </path/to/private_key>]

Scenarios:
  suspicious_login | insider_threat | ddos_detection | malware_communication | geoip_detection | log_volume

Flags:
  --agent           Where agents live:      local (docker-compose.agents.yml) | remote (SSH endpoints)
  --manager         Where manager lives:    local (docker-compose.core.yml)   | remote (SSH host)
  --manager_exists  Whether the manager already exists at that location:
                      - true  : do not bootstrap a manager
                      - false : bootstrap (local: docker compose up; remote: let Ansible bootstrap)
  --ssh-key         Optional: path to the SSH private key used for remote manager/agent access.
                    If not provided, defaults to: $HOME/.ssh/id_ed25519
```

Example

- Suspicious login scenario set up for a customer: local manager does not exist (single node or multi node), deploy Wazuh agents on remote endpoints.
```
./build-radar.sh suspicious_login --agent remote --manager local --manager_exists false
```

- Geo IP detection set up for a customer: local manager does not exist (single node or multi node), deploy Wazuh agents on remote endpoints.
```
./build-radar.sh suspicious_login --agent remote --manager local --manager_exists false
```

#### RADAR outcome in Wazuh Dashboard

Here we provide a screenshot of a successful run of the Geo IP detection RADAR scenario:

![Wazuh Dashboard Discover RADAR geo IP detection](/docs/manual/_figures/RADAR-GeoIP-detection-Wazuh-Dashboard-result.png "Wazuh Dashboard Discover RADAR Geo IP detection")

The currently implemented active response sends an email to a designated recipient.
![](/docs/manual/_figures/RADAR-GeoIP-detection-Automated-Response-email.png)

### ADBox installation

For a description of the deployment model using Docker and shell scripts and other installation methods, please see the [installation](./docs/manual/adbox_installation.md) page of the user manual.

### ADBox usage

Please note that you can set the parameters (IP, port, username and password) for connecting to Wazuh via the [Wazuh credentials JSON file](./siem_mtad_gat/assets/secrets/wazuh_credentials.json).

The ADBox driver/CLI currently provides four options:

1. Running ADBox using the `-u` flag following by the ID of a use-case YAML file (stored under `siem_mtad_gat/assets/drivers`), e.g., `./adbox.sh -u 2` to start a complete training and prediction pipeline determined by an AD [use-case](./docs/manual/use_case.md) scenario, in this case `uc_2.yaml`.

1. Running ADBox using the `-i` flag, i.e., `./adbox.sh -i` running the interactive console (**the console currently contains a known bug for prediction-only jobs (i.e., no training and using a trained model), please use option 1**).

1. Running ADBox without any arguments: it runs a training and prediction pipeline using default configurations.

1. Running ADBox using the `-c` flag, i.e., `./adbox.sh -c` to check your connection with Wazuh, which is recommended to ensure a successful channel can be established before executing AD workflows. Otherwise, in the absence of a functional connection, ADBox automatically falls back to local default configuration files and prepared sample training and prediction data.

1. Running ADBox using the `-s` flag enables data shipping to Wazuh on top of the expected behavior. Namely, `./adbox.sh -s`  and `./adbox.sh -u 2 -s`, perform the same operations as without this flag, plus the shipping to Wazuh. We recommend to read the manual's page about [ADBox integration in Wazuh](/docs/manual/detector_data_stream.md) before the usage. 

#### Example of a use-case scenario

For a detailed walkthrough and ADBox use-case scenario preparation and execution, see our [dedicated example](/docs/manual/example.md) illustrating the usage of ADBox, adopting the end user point of view.

#### Wazuh-ADBox integration and detector dashboard

Since IDPS-ESCAPE version `0.1.4`, it is possible to ship prediction outcomes to the Wazuh indexer and consult them directly using the Wazuh dashboard. We summarize the key points in the [installation page](/docs/manual/adbox_installation.md#shipping-data-to-wazuh), referring to the corresponding manual page [Wazuh-ADBox integration](/docs/manual/detector_data_stream).

![Wazuh Dashboard Discover ADBox Detector](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_30-Discover.png "Wazuh Dashboard Discover ADBox Detector")

With a customized Dashboard example provided below. You can find instructions for building such a dashboard in a [dedicated manual page](/docs/manual/dashboard_tutorial.md).
![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_25-Dashboard-10.png)

For an improved visualization, we explain in our [Detector Dashboard Tutorial](/docs/manual/dashboard_tutorial.md) how to construct a dedicated Detector Dashboard in the Wazuh Dashboard, combining multiple visualizations of global and feature-wise results, and related data from other Wazuh indices as well.

Combining Discover Dashboard and our Detector Dashboard we can monitor (in realtime) and investigate anomalies.
![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_36-Dashboard-video-2.gif)

## Integrations

In the [manual page](/integrations/README.md) of our integrations [package](/integrations/), you will find a concise overview of the artifacts (manuals, Docker compose files, configuration files, code and scripts) for integrating other tools with IDPS-ESCAPE, e.g., MISP, OpenCTI, OpenBAS. We also discuss best practices for improving such integrations and avoiding certain pitfalls.

## Disclaimer: use of alpha/experimental software

This software is currently in its alpha or experimental phase and is provided for testing and evaluation purposes only. It may contain errors, bugs, or other issues that could result in security vulnerabilities, data loss, or other unpredictable outcomes. As such, **this software is not intended for use in production environments** or for handling sensitive, confidential, or critical information.

In particular, given the nature of security-related software, it is crucial to understand that the algorithms, protocols, and implementations within this software may not have undergone thorough security audits or peer review. **Do not rely on this software for critical system functions.**

The developers, contributors, and affiliated organizations **disclaim all warranties, express or implied,** including but not limited to the implied warranties of fitness for a particular purpose. **No guarantee is made regarding the correctness, completeness, or security** of the software, and you assume full responsibility for any risks associated with its use.

By using this software, you acknowledge that you understand the risks and agree to use it **at your own risk.** You are strongly encouraged to conduct your own security assessments and tests before deploying this software in any environment.

### Usage recommendations and remarks

We advise the user __not__ to 
- set the detector time granularity parameter to a value lower than 30s,
- run prediction-only use-cases if there are no corresponding detectors available in the [detectors folder](./siem_mtad_gat/assets/detector_models/). 

Furthermore, we highlight the following points:

- Anomalous timestamps should be considered more as period indicators rather than precise links to an event for two reasons: 
  - (i) data points from events are aggregated, to which rounding is applied during preprocessing; 
  - (ii) the anomaly is defined in terms of windows, hence consecutive sets of events.
- Depending on the selected configurations, running the full stack of IDPS-ESCAPE may require up to 26 GB of persistent storage, while RAM usage for the default ADBox configuration remains close to 4 GB, the same as the recommended value for Wazuh, which is used as our source of data for training and prediction. Note that the various subsystems can be deployed on different nodes, e.g., the ADBox on one node and our customized Wazuh+Suricata setup on another, or all three on separate nodes (see the [integration](./deployment/README.md) and [remote monitoring](./deployment/remote_monitoring/remote_monitoring.md) pages).
- Clearly, the MTAD-GAT hyperparameters (e.g., the number of GRU layers) require tuning when it comes to training machine learning models.

## Testing

For software validation test cases, please see the test campaign results (e.g., TRA and TRB) on our [traceability web page](https://abstractionslab.github.io/idps-escape/docs/traceability/index.html). The test artifacts described below deal with unit/integration/system testing.

### RADAR

RADAR is also shipped with an extensive [unit test suite](./soar-radar/tests/), which can be run in a dedicated containerized environment using a [test entry point](./soar-radar/test.sh).

#### RADAR test framework

Moreover, the RADAR subsystem comes with a dedicated test framework with support for Infrastructure as Code (IaC) via Ansible aimed at automating the experimentation and validation chain of activities, i.e., a pipeline handling ingestion of datasets, preprocessing, training and ML model baseline establishment, attack simulation, data collection, followed by post-processing and computation of statistical measures. See [RADAR test framework](/soar-radar/radar-test-framework/README.md) for more details.

### ADBox

ADBox comes with an extensive suite of unit tests. A dedicated containerized environment can be built by running `./build-adbox.sh` (the script needs to be made executable). Then, the full set of unit tests can be run as follows

```sh
./run_test.sh
```

Otherwise, a test file can be specified:
```sh
./run_test.sh  tests/{name}_test.py
```

## Roadmap

Some of the currently planned items include:

- More advanced hybrid correlation logic between signatures and anomalies;
- Enhanced RADAR response strategies and orchestration;
- Automatic model training pipelines within ADBox (policy-based, e.g. schedule, custom criteria, etc.);
- Improved support for categorical and mixed-type anomaly detection in ADBox;
- Greater robustness against missing or noisy data;
- Extended integrations with additional open-source security tools;
- Adding new reusable RADAR and ADBox use case scenarios;
- Combining classical AD with deep learning, in our case: RRCF + MTAD-GAT;
- [SATRAP](https://github.com/AbstractionsLab/satrap-dl) engine integration for advanced real-time CTI on a system security graph combined with world CTI;
- [OpenTRICK](https://github.com/itrust-consulting/OpenTRICK) asset dependency conversion to a SATRAP system security graph;
- [OpenTide](https://github.com/OpenTideHQ) integration;
- Interconnecting ADBox and RADAR;

For details on our roadmap and features planned for future releases, please see the [Wiki](https://github.com/AbstractionsLab/idps-escape/wiki) section of this repository.

## License

Copyright (c) itrust Abstractions Lab and itrust consulting. All rights reserved.

Licensed under the [GNU Affero General Public License (AGPL) v3.0](LICENSE) license.

For more information, please consult the [list of authors and contributors page](/AUTHORS).

## Acknowledgment

The creation of the IDPS-ESCAPE software tools and its knowledge base is co-funded by the Ministry of the Economy of Luxembourg, in the context of the CyFORT project.

## Contact

If you wish to learn more about the project, feel free to contact us at Abstractions Lab: info@abstractionslab.lu