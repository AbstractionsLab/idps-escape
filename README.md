# IDPS-ESCAPE

IDPS-ESCAPE, short for Intrusion Detection and Prevention Systems for Evading Supply Chain Attacks and Post-compromise Effects, is a sub-project of the [CyFORT](https://abstractionslab.com/index.php/research-and-development/cyfort/) project, which in turn stands for Cloud Cybersecurity Fortress of Open Resources and Tools for Resilience. CyFORT is carried out in the context of the [IPCEI-CIS](https://ec.europa.eu/commission/presscorner/detail/en/ip_23_6246) project. 

<img src="./docs/manual/_figures/CyFORT-IDPS-ESCAPE-logo.png" alt="cyfort_logo" width="500"/>

IDPS-ESCAPE is aimed at closely capturing the notion of MAPE-K (Monitor, Analyze, Plan, Execute and Knowledge) from autonomic computing applied to cybersecurity, which translates into a comprehensive package that implements a Security Orchestration, Automation, and Response (SOAR) system.

The resulting SOAR system combines the following building blocks: a Security Information and Event Management (SIEM) system, an Intrusion Detection and Prevention System (IDPS), Cyber Threat Intelligence (CTI) tools, an anomaly detection (AD) subsystem, called [**ADBox**](/docs/manual/README.md), and a Risk-aware AD-based Active Response ([**RADAR**](/soar-radar/README.md)) subsystem providing AD scenario implementations, coupled with active response solutions and SOAR playbooks facilitating security orchestration.

We adopt a hybrid method aimed at robustness and resilience to adversarial interference involving three elements: (i) signature-based detection with (ii) AD based on deep learning models via MTAD-GAT, relying on state-of-the-art advances in artificial intelligence (AI) and machine learning (ML) such as the *attention mechanism* and (iii) a classical algorithm for AD on streams such as the Robust Random Cut Forest (RRCF) algorithm supporting categorical features.

This repository contains the source code and full documentation (requirements, technical specifications, schematics, [user manual](./docs/manual/README.md), validation test case specifications and test reports) of IDPS-ESCAPE, based on the [C5-DEC](https://github.com/AbstractionsLab/c5dec) method and software also developed in CyFORT, which relies on storing, interlinking and processing all software development life cycle (SDLC) artifacts in a unified manner; see our [traceability web page](https://abstractionslab.github.io/idps-escape/docs/traceability/index.html) providing the technical specifications of IDPS-ESCAPE.

**Table of contents**

- [Overview](#overview)
- [Features](#features)
- [User manual](#user-manual)
- [Technical specifications](#documentation-and-technical-specifications)
- [Getting started](#getting-started)
- [ADBox usage](#adbox-usage)
- [Use case scenario example](#example-of-a-use-case-scenario)
- [Wazuh-ADBox integration and detector dashboard](#wazuh-adbox-integration-and-detectors-dashboard)
- [RADAR](#radar)
- [Integrations](#integrations)
- [Disclaimer](#disclaimer-use-of-alphaexperimental-software)
- [Testing](#testing)
- [Roadmap](#roadmap)
- [License](#license)
- [Contact](#contact)

## Overview

IDPS-ESCAPE, part of the [CyFORT](https://abstractionslab.com/index.php/research-and-development/cyfort/) suite of open-source cybersecurity software solutions, addresses various aspects of cybersecurity as an ensemble, targeting different user groups, ranging from public to private and from CERT/CSIRT entities to system administrators, and cloud-native deployments. IDPS-ESCAPE is being developed in parallel with another CyFORT sub-project, namely [SATRAP-DL](https://github.com/AbstractionsLab/satrap-dl), aimed at enhancing cyber threat intelligence (CTI) analysts' work using semi-automated reasoning over CTI.
 
As part of the alpha release, the main bulk of this repository is dedicated to a novel open-source and extensively documented anomaly detection (AD) framework, called [**ADBox**](/docs/manual/README.md) and a Risk-aware AD-based Active Response ([**RADAR**](/soar-radar/README.md)) subsystem implementing AD scenarios and automated response to fulfill the SOAR mission of IDPS-ESCAPE.

IDPS-ESCAPE builds on top of well-known open-source solutions such as [OpenSearch](https://opensearch.org/) for search and analytics, [Wazuh](https://wazuh.com/) as our SIEM\&XDR of choice, in turn connected to [MISP](https://www.misp-project.org/) and [OpenCTI](https://github.com/OpenCTI-Platform/opencti) for bidirectional SIEM-TIP enrichment of SIEM alerts and CTI content, and finally [Suricata](https://suricata.io/), acting both as our network-based IDPS of choice, as well as a network-level data acquisition source.

The ADBox implementation provides a modular and extensible software framework for efficiently integrating ML and AD algorithms and it already comes with a deep learning-based paradigm, namely the Multivariate Time-series Anomaly Detection (MTAD) via Graph Attention Network (GAT) algorithm. We recommend following a hybrid method combining MTAD-GAT with signature-based detection and a classical AD algorithm such as the RRCF-based AD plugin built into OpenSearch that is used by our RADAR subsystem for more robust AD, resilient to adversarial interference, with support for categorical features.

In addition to providing security practitioners such as SOC operators or CTI analysts with anomaly detection over Wazuh indices (alerts, archives, statistics, etc.) in multiple modes (batch, real-time and historical), ADBox and RADAR can be used to simplify and refine the work of security practitioners across several dimensions, e.g.,

- rule management,
- events correlation,
- alert-to-incident derivation, and,
- alert/response policy tuning and mappings to KBs such as MITRE ATT&CK.

ADBox can also be used as a software library to deploy various ML based AD algorithms in different environments, while allowing for a high degree of tailoring thanks to its modular and extensible design. An environment-driven customization can not only contribute to reducing false positives, but it can also help detect suspicious behavior with arguably limited information, or to otherwise provide an investigation entry point dealing with adversarial patterns for which prior signatures or indicators of compromise may not be readily available.

As a consequence, ADBox also provides a stepping stone towards settling various controversial statements and at times questionable findings and claims from the academic literature and those made by practitioners in the industry: plug in the latest implementation of a deep learning based AD algorithm into ADBox, integrated with a real-world security tool such as Wazuh, to assess and (in)validate such claims.

## Features

### Design

- Free/libre and open source;
- Cross platform: works on GNU/Linux, MacOS and Windows;
- Extensible due to a modular design and architecture;
- Based on open data formats such as Markdown, YAML, XML, JSON, CSV and HTML;
- Integrated with well-known open-source security solutions such as [OpenSearch](https://opensearch.org/), [Wazuh](https://wazuh.com/), [Suricata](https://suricata.io/);
- Thanks to building on top of Wazuh, an easy integration with other well-known [third-party solutions](https://documentation.wazuh.com/current/getting-started/use-cases/threat-hunting.html) such as [MISP](https://www.misp-project.org/) using existing mechanisms.

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

### SOAR-RADAR

A collection of Risk-aware Anomaly Detection-based Active Response (**RADAR**) modules that complete the Security Orchestration, Automation and Response ([**SOAR**](/soar-radar/README.md)) mission of IDPS-ESCAPE, providing

- AD scenarios, along with their corresponding active response solutions implemented for Wazuh, currently geared towards an [Amazon AWS implementation](https://github.com/aws/random-cut-forest-by-aws/) of the classical [Random Cut Forest (RCF) AD on streams algorithm](https://www.amazon.science/publications/robust-random-cut-forest-based-anomaly-detection-on-streams) integrated into Wazuh, enabled by installing the [OpenSearch AD plugin](https://wazuh.com/blog/enhancing-it-security-with-anomaly-detection/), supporting [categorical features](https://docs.opensearch.org/docs/latest/observing-your-data/ad/index/#setting-categorical-fields-for-high-cardinality);
- A dedicated [RADAR manual](/soar-radar/README.md) describing best practices for making use of our ADBox for AD powered by deep learning, in hybrid mode, together with the classical RCF-based AD algorithm built into OpenSearch to tackle various AD and ML challenges, e.g., adversarial ML involving training data set poisoning and trained model manipulation.

### Front-end

- A command-line interface (**CLI**) for efficient user interactions and automation via scripting integration, currently available via the driver module (under active development);
- A dedicated Jupyter notebook for analysis and post-processing, providing a prepared playbook with tailored plotting and operating directly on top of anomaly prediction data produced by the ADBox backend;
- Integration into the Wazuh Dashboard, with the possibility to create dedicated detector dashboards to compare predictions with the original data.

### Integration package

- Artifacts (manuals, Docker compose files, configuration files, code and scripts) for integrating other tools with IDPS-ESCAPE, e.g., MISP, OpenCTI, OpenBAS, [SATRAP](https://github.com/AbstractionsLab/satrap-dl) and [OpenTRICK](https://github.com/itrust-consulting/OpenTRICK);
- Manuals providing tips and best practices for improving such integrations and avoiding certain pitfalls.

### Network and host monitoring

To achieve comprehensive monitoring capabilities, we combine well-established open-source solutions, namely [Wazuh](https://wazuh.com/), a cybersecurity platform that integrates SIEM and XDR capabilities and [Suricata](https://suricata.io/), an open-source Network Intrusion Detection System (NIDS). We provide deployment solutions that allow centralized monitoring for coping with limited resources (network agents relaying traffic data to a central node for processing) as well as running monitoring instances on each node and only grouping the obtained monitoring data in a centralized node for analysis.

See our [Instructions for IDPS and SIEM integrated deployment](./deployment/README.md) page for further details.

## User manual

Please see our extensive and detailed [IDPS-ESCAPE user manual](./docs/manual/README.md) to learn more about the installation, setup requirements, overall usage, specific modules of the ADBox and technical details covering internal aspects that are relevant for an effective use of the suite IDPS-ESCAPE tools. You will also find dedicated [instructions for a network IDPS plus SIEM integrated deployment](./deployment/README.md), describing our combined architectural setup using Wazuh, Suricata and various networking deployment solutions.

## Documentation and technical specifications

You can visit our [traceability page](https://abstractionslab.github.io/idps-escape/docs/traceability/index.html) to view the technical specifications of IDPS-ESCAPE.

## Getting Started

### IDPS and SIEM integrated deployment

Note that if you already have a running instance of Wazuh, and do not wish to integrate Suricata, you can simply skip to the [ADBox installation section](#adbox-installation).

A complete and installation of the signature-based intrusion detection and the SIEM subsystems of IDPS-ESCAPE can be done using the following guides:

1. Suricata, to enable network monitoring capabilities:

      a.  [installation in a containerized environment](./deployment/suricata/suricata_installation.md#installation-and-configuration-of-suricata)
      
      b.  [configuration to local network](./deployment/suricata/suricata_installation.md#suricata-configuration-file)
1. Wazuh central components installation, for SIEM \& XDR:

    a. [installation of Dashboard, Manager and Indexer in a containerized environment ](./deployment/wazuh/wazuh_installation.md)

    b. [configuration to local system](./deployment/wazuh/wazuh_installation.md#next-steps)

1. [Installation of a Wazuh agent](./deployment/wazuh/wazuh_agents.md) to enable host monitoring capabilities.

    a. Possibly, deployment of additional agents on other remote hosts (system *endpoints*), same as above.
  
    b. Possibly, [enable remote traffic monitoring](./deployment/remote_monitoring/remote_monitoring.md).

1. Follow [integration procedure of Suricata and Wazuh](./deployment/integration.md).

 Details of the above steps and scripts are provided in the [Guide for IDPS and SIEM integrated deployment](./deployment/README.md).

 This integration guarantees:
 
 - joint monitoring of host and network events, and
 - centralized storage.

All the data ending up in the central SIEM \& XDR can now be fed to ADBox for training ML models and anomaly detection, providing a holistic view of the system(s) under monitoring.

### ADBox installation

ADBox can be deployed using the following methods:
  
- [Deployment using Docker and our shell scripts](./docs/manual/installation.md#installing-adbox-via-docker-and-shell-script) (**recommended for end-users**);

- [Deployment in a development containerized environment in VS Code](./docs/manual/installation.md#installing-adbox-in-a-development-containerized-environment-in-vs-code) (**recommended for developers**);

Below we describe the deployment using Docker and shell scripts. For other installation methods, please see the [installation](./docs/manual/installation.md) page of the user manual.

#### Installing ADBox via Docker and shell scripts

The easiest and recommended way to deploy and run ADBox is described in this section and can be achieved using our Docker definition file and build/execution scripts, which can be found in the repository. The instructions below work on GNU/Linux, MacOS and Windows Subsystem for Linux (WSL). ADBox is run as a service in a Docker container.

##### Requirements

The following pieces of software are necessary for setting up the ADBox as a service in a Docker container.

- A local installation of [Docker Engine](https://docs.docker.com/engine/install/), with the Docker service running prior to launching ADBox.

##### Installation

1. Simply clone the repository or download a ZIP archive of the project 

    ```sh
    git clone https://github.com/AbstractionsLab/idps-escape.git
    ```

2. Unzip the archive, switch to the extracted directory (`cd foldername`) via a terminal running a shell (e.g., bash, zsh) and make the two shell scripts executable: `chmod +x script-name.sh`. Then, change working directory to the cloned folder containing all the files along with the Dockerfile and build the image by running our build script: `./build-adbox.sh`;

3. Finally, launch ADBox by executing `./adbox.sh`, which runs the default mode if no arguments are provided to the command-line interface (CLI); running `./adbox.sh -h` displays the CLI help menu describing the available commands.

![ADBox CLI](./docs/manual/_figures/adbox-cli.png)

### ADBox usage

Please note that you can set the parameters (IP, port, username and password) for connecting to Wazuh via the [Wazuh credentials JSON file](./siem_mtad_gat/assets/secrets/wazuh_credentials.json).

The ADBox driver/CLI currently provides four options:

1. Running ADBox using the `-u` flag following by the ID of a use-case YAML file (stored under `siem_mtad_gat/assets/drivers`), e.g., `./adbox.sh -u 2` to start a complete training and prediction pipeline determined by an AD [use-case](./docs/manual/use_case.md) scenario, in this case `uc_2.yaml`.

1. Running ADBox using the `-i` flag, i.e., `./adbox.sh -i` running the interactive console (**the console currently contains a known bug for prediction-only jobs (i.e., no training and using a trained model), please use option 1**).

1. Running ADBox without any arguments: it runs a training and prediction pipeline using default configurations.

1. Running ADBox using the `-c` flag, i.e., `./adbox.sh -c` to check your connection with Wazuh, which is recommended to ensure a successful channel can be established before executing AD workflows. Otherwise, in the absence of a functional connection, ADBox automatically falls back to local default configuration files and prepared sample training and prediction data.

1. Running ADBox using the `-s` flag enables data shipping to Wazuh on top of the expected behavior. Namely, `./adbox.sh -s`  and `./adbox.sh -u 2 -s`, perform the same operations as without this flag, plus the shipping to Wazuh. We recommend to read the manual's page about [ADBox integration in Wazuh](/docs/manual/detector_data_stream.md) before the usage. 


#### Verifying connection with Wazuh

Before running ADBox training and prediction scenarios, you can verify whether a connection between ADBox and an instance of Wazuh can be established successfully using the `-c` flag:

```sh
./adbox.sh -c
```

You can set/modify the parameters (IP, port, username and password) for connecting to Wazuh via the [Wazuh credentials JSON file](./siem_mtad_gat/assets/secrets/wazuh_credentials.json).

#### Executing a use-case from a YAML file

The ADBox takes inputs from a YAML file stored in the `/siem_mtad_gat/assets/drivers/` folder. By default, the folder contains several YAML-encoded use-cases, which can be used for training models and running predictions.

A training and detection use-case can be run by providing the `-u` flag along with an integer to the script.

```sh
./adbox.sh -u {number}
```

For example, to run use-case 1, execute the script as follows:

```sh
./adbox.sh -u 1
```

With this input, the ADBox will take the inputs specified in the `uc_1.yaml` file.

The folder containing the YAML files also contains a `driver.yaml` file that provides a template for writing your own custom YAML files.

For example, one can run a new [use-case](./docs/manual/use_case.md), by specifying different input parameters in a new YAML file, called `uc_6.yaml` and then run the adbox as follows:

```sh
./adbox.sh -u 6
```

All the outputs produced as a result of running use-cases are stored in `./siem_mtad_gat/assets/detector_models/{detector_id}/prediction_{current_date}/predict_output.json`.

#### Interacting with a console (contains bugs in the alpha version):

```sh
./adbox.sh -i
```

Running the script using the `-i` flag will open an interactive console which will ask for user inputs.

The output of the all the detections performed through the console are stored in `./siem_mtad_gat/assets/detector_models/{detector_id}/prediction_{current_date}/predict_output.json` file.


#### Executing as default:

```sh
./adbox.sh
```

In this mode, the ADBox will train a detector using the default arguments and then also perform detection based on default arguments, with the detector trained using the previously mentioned default arguments. To know more about the input arguments used in default mode, visit the [user manual](./docs/manual/README.md) page.

The output of the default detection is also stored in `./siem_mtad_gat/assets/detector_models/{detector_id}/prediction` folder.

#### Shipping Data to Wazuh

#### Install ADBox-Wazuh shipping

Adding the "shipping flag" for the first time installs dedicated ADBox index templates and policies in the Wazuh indexer. We recommend reading the manual page about [ADBox integration in Wazuh](/docs/manual/detector_data_stream.md) before using this option. 

```sh
./adbox.sh -s
```
#### Executing use cases and shipping to Wazuh
By adding the `-s` flag,

```sh
./adbox.sh -u 2 -s
```
the computed predictions are shipped to a custom data stream in the Wazuh indexer. We recommend reading the manual page about [ADBox integration in Wazuh](/docs/manual/detector_data_stream.md) before using this option. 

## Example of a use-case scenario

In this section, we present an example illustrating the usage of ADBox, adopting the end user point of view.

### My system

I have deployed all the components as explained in the [guide for IDPS and SIEM integrated deployment](./deployment/guide_sids.md) and the
[ADBox user manual installation page](./docs/manual/installation.md). Moreover, I have enabled [Linux resource monitoring](./docs/manual/linux_resource.md).

### My use-case

I want a detector which correlates resource usage and rules statistics. Once created, I want this detector to keep running on new data.

Therefore, I prepare a dedicated [use-case file](./docs/manual/use_case.md).

Namely,

- I have to identify the features of the [multivariate time-series](./docs/manual/time_series.md) that I want to perform detection on. To do so, I analyze the event logs of my system.

- For every feature, I choose a suitable aggregation method for the *granularity* I wish to use. 

- For example, I would like a new point every 30 seconds (**lowest advised granularity**). Every point has 3 dimensions representing the average CPU percent usage, average memory percent usage and the total `firedtimes` rule statistics parameter.

I have to decide:

- how I wish to handle missing values,
- the detector name,
- the data that is to be used to train my detector,
- the detection interval (window size), and
- the number of epochs for training.

For example, I want anomalies to be flagged over intervals of 3.5 minutes, so the window size should be 8. Then, I also want to use all my data of the current month that is already available to train the detector.

For the prediction, I want almost real-time results but I would like to fetch data in batches. For example, I want to get points every 6 minutes, then in batches of 12 points.

I encode this in [`siem_mtad_gat/assets/drivers/uc-9.yaml`](../../siem_mtad_gat/assets/drivers/uc_9.yaml)

```YAML
training:
  aggregation: true
  aggregation_config:
    features:
      data.cpu_usage_%:
      - average
      data.memory_usage_%:
      - average
      rule.firedtimes:
      - count
    fill_na_method: Zero
    granularity: 30s
    padding_value: 0
  categorical_features: false
  columns:
  - data.cpu_usage_%
  - data.memory_usage_%
  - rule.firedtimes
  display_name: detector_example
  index_date: '2024-08-*'
  train_config:
    epochs: 8
    window_size: 6

prediction: 
    run_mode: BATCH
    batch_size: 12
```
#### Running the pipeline

I run ADBox

```sh
./adbox.sh -u 9
```

and stop it after a few hours.

This produces a detector with id `2d36a80a-c47a-4eb4-bb3e-5b2bfb90dc9` and the associated folder [`siem_mtad_gat/assets/detector_models/2d36a80a-c47a-4eb4-bb3e-5b2bfb90dc9`](./siem_mtad_gat/assets/detector_models/2d36a80a-c47a-4eb4-bb3e-5b2bfb90dc95/).

```sh
2d36a80a-c47a-4eb4-bb3e-5b2bfb90dc9
├── input
│   ├── detector_input_parameters.json
│   └── training_config.json
├── prediction
│   ├── uc-9_predicted_anomalies_data-1_2024-08-30_10-24-15.json
│   └── uc-9_predicted_data-1_2024-08-30_10-24-15.json
└── training
    ├── losses_train_data.json
    ├── model.pt
    ├── scaler.pkl
    ├── spot
    │   ├── spot_feature-0.pkl
    │   ├── spot_feature-1.pkl
    │   ├── spot_feature-2.pkl
    │   └── spot_feature-global.pkl
    ├── test_output.pkl
    ├── train_losses.png
    ├── train_output.pkl
    └── validation_losses.png
```

### Detection analysis

Using the [ADBox Result Visualizer Notebook](./siem_mtad_gat/frontend/viznotebook/result_visualizer.ipynb), I can plot the results and analyze them. Here, I collect a few observations.

#### Training

The training losses are rather good for 8 epochs, while the same cannot be said about the validation losses. I could try the same setting, while training the detector for more epochs.

![training losses](./siem_mtad_gat/assets/detector_models/2d36a80a-c47a-4eb4-bb3e-5b2bfb90dc95/training/train_losses.png)

![validation losses](./siem_mtad_gat/assets/detector_models/2d36a80a-c47a-4eb4-bb3e-5b2bfb90dc95/training/validation_losses.png)

#### Prediction

I ran the batch prediction from `2024-08-30T10:18:04Z` to `2024-08-30T13:05:30Z` UTC time.

**Global overview**

![Batch](./docs/manual/_figures/example_global.png)

During this time period, 5 anomalous windows were flagged, 4 consecutive and 1 alone. Let's call them A1 and A2, respectively.

![a1](./docs/manual/_figures/example-a1.png)

![a2](./docs/manual/_figures/example-a2.png)

**Feature overview**

Looking at the feature statistics, we can see these two anomalies expressing two different cases:

- anomalies in A1 can be also considered anomalies at the feature level.
- the anomaly in A2 is anomalous **only** at a global level. 

![f1](./docs/manual/_figures/f1.png)

![f2](./docs/manual/_figures/f2.png)

![t1](./docs/manual/_figures/true.png)

**Wazuh Dashboard**

Looking at the Wazuh Dashboard, we can observe a high number of events in proximity of A1:

![w1](./docs/manual/_figures/example-w1.png)

![w2](./docs/manual/_figures/example-w2.png)

### Mapping anomalies to real events

We traced the two anomalies to two real events that had happened in the corresponding detections intervals:

- A1 matches with the running of `apt update` and `apt upgrade` on the host machine.
- A2 matches with a reboot.

### Remarks

In both cases, the actions that (most probably) generated the anomalies had been carried out by a system administrator. Otherwise, while A1 would have been noticed by looking at single features and/or Wazuh; A2 would not have been as obvious to track.

## Wazuh-ADBox integration and detector dashboard

Since IDPS-ESCAPE version 0.1.4, it is possible to ship prediction outcomes to the Wazuh indexer and consult them directly using the Wazuh dashboard.
We summarize the key points below, referring to the corresponding manual page [Wazuh-ADBox integration](/docs/manual/detector_data_stream).

### Data shipping to the Wazuh indexer and dashboard integration

The training and prediction pipelines are instructed via [use cases](/docs/manual/use_case.md). To enable the data shipping to the Wazuh indexer, it is sufficient to run ADBox with the flag `-s`:

```sh
$ ./build-adbox.sh
...
$ ./adbox.sh -u {number} -s
```

This way, ADBox:
- at *training time*,  creates a [**detector data stream**](/docs/manual/detector_data_stream.md#detector-data-streams) associated with the detector.
- at *prediction time*, adds the outcomes to the corresponding detector data stream.

A **detector stream** is a [data stream index](https://opensearch.org/docs/latest/im-plugin/data-streams/) of the Wazuh Indexer (i.e., its underlying OpenSearch  distribution).  

Following the [**integration procedure**](/docs/manual/detector_data_stream.md#integrate-in-wazuhs-dashboard) described in the manual it is possible to explore a detector's anomaly predictions via the Wazuh Discovery Dashboard.

![Wazuh Dashboard Discover ADBox Detector](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_30-Discover.png "Wazuh Dashboard Discover ADBox Detector")

With a customized Dashboard example provided below. You can find instructions for building such a dashboard in a [dedicated manual page](/docs/manual/dashboard_tutorial.md).
![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_25-Dashboard-10.png)

### Video walkthrough of ADBox Detector dashboard creation in Wazuh

For an improved visualization, we explain in our [Detector Dashboard Tutorial](/docs/manual/dashboard_tutorial.md) how to construct a dedicated Detector Dashboard in the Wazuh Dashboard, combining multiple visualizations of global and feature-wise results, and related data from other Wazuh indices as well.

Combining Discover Dashboard and our Detector Dashboard we can monitor (in realtime) and investigate anomalies.
![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_36-Dashboard-video-2.gif)

## RADAR

The [RADAR](/soar-radar/) subsystem provides solutions for completing the SOAR 
mission of IDPS-ESCAPE enabling security orchestration and automation driven by a 
Risk-aware AD-based active response (AR) paradigm. Please see the corresponding RADAR [README](/soar-radar/README.md) for more information.

## Integrations

In the [manual page](/integrations/README.md) of our integrations [package](/integrations/), you will find a concise overview of the artifacts (manuals, Docker compose files, configuration files, code and scripts) for integrating other tools with IDPS-ESCAPE, e.g., MISP, OpenCTI, OpenBAS, [SATRAP](https://github.com/AbstractionsLab/satrap-dl) and [OpenTRICK](https://github.com/itrust-consulting/OpenTRICK). We also discuss best practices for improving such integrations and avoiding certain pitfalls.

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

ADBox comes with an extensive suite of unit tests. A dedicated containerized environment can be built by running `./build-adbox.sh` (the script needs to be made executable). Then, the full set of unit tests can be run as follows

```sh
./run_test.sh
```

Otherwise, a test file can be specified:
```sh
./run_test.sh  tests/{name}_test.py
```

For software validation test cases, please see the test campaign results (e.g., TRA and TRB) on our [traceability web page](https://abstractionslab.github.io/idps-escape/docs/traceability/index.html). 

## Roadmap

Some of the currently planned items include:

- tailoring the underlying ADBox algorithms to specific SOC operations;
- adding new reusable anomaly detection use case scenarios, i.e., other than the ones geared towards resource usage monitoring;
- stabilizing the current implementation and improving its resilience/fault tolerance, especially when it comes to dealing with missing and ill-formed raw data;
- adding new automated mechanisms aimed at preventive measures (i.e., the "P" in IDPS), directly integrated into Wazuh, towards the SOAR goal of IDPS-ESCAPE.

For details on our roadmap and features planned for future releases, please see the [Wiki](https://github.com/AbstractionsLab/idps-escape/wiki) section of this repository.

## License

Copyright (c) itrust Abstractions Lab and itrust consulting. All rights reserved.

Licensed under the [GNU Affero General Public License (AGPL) v3.0](LICENSE) license.

## Acknowledgment

The creation of the IDPS-ESCAPE software tools and its knowledge base is co-funded by the Ministry of the Economy of Luxembourg, in the context of the CyFORT project.

## Contact

If you wish to learn more about the project, feel free to contact us at Abstractions Lab: info@abstractionslab.lu