# ADBox: A modular and extensible Anomaly Detection framework

> **⚠️ DEPRECATED - Research Only**: ADBox is maintained for research continuity only. **For production deployments, use [SONAR](../sonar_docs/README.md)**, which provides a faster, simpler, and more maintainable anomaly detection solution optimized for Wazuh integration.

The ADBox implementation provides a modular and extensible software framework for efficiently integrating ML and AD algorithms and it already comes with a deep learning-based paradigm, namely the Multivariate Time-series Anomaly Detection (MTAD) via Graph Attention Network (GAT) algorithm. We recommend following a hybrid method combining MTAD-GAT with signature-based detection and a classical AD algorithm such as the RRCF-based AD plugin built into OpenSearch that is used by our RADAR subsystem for more robust AD, resilient to adversarial interference, with support for categorical features.

In addition to providing security practitioners such as SOC operators or CTI analysts with anomaly detection over Wazuh indices (alerts, archives, statistics, etc.) in multiple modes (batch, real-time and historical), ADBox and RADAR can be used to simplify and refine the work of security practitioners across several dimensions, e.g.,

- rule management,
- events correlation,
- alert-to-incident derivation, and,
- alert/response policy tuning and mappings to KBs such as MITRE ATT&CK.

ADBox can also be used as a software library to deploy various ML based AD algorithms in different environments, while allowing for a high degree of tailoring thanks to its modular and extensible design. An environment-driven customization can not only contribute to reducing false positives, but it can also help detect suspicious behavior with arguably limited information, or to otherwise provide an investigation entry point dealing with adversarial patterns for which prior signatures or indicators of compromise may not be readily available.

As a consequence, ADBox also provides a stepping stone towards settling various controversial statements and at times questionable findings and claims from the academic literature and those made by practitioners in the industry: plug in the latest implementation of a deep learning based AD algorithm into ADBox, integrated with a real-world security tool such as Wazuh, to assess and (in)validate such claims.

## Overview

- [Installation](./adbox_installation.md): Instructions to install ADBox.

- [Setup and prerequisites](./setup_and_prerequisites.md): List of configuration files and prerequisites to complete the deployment of ADBox and to be able to create and run detectors.

- [Quick start](./quick_start.md): A concise description of how to get started with AD scenario selection and training/prediction pipeline execution.

- [Use case definition guide](./use_case.md): Via ADBox it is possible to create, use and maintain detectors which ingest data and analyze them. The user can simply define the parameters via *use-case* configuration files and feed them to the ADBox entry point. This page contains the instructions for understanding and defining use-case files.

- [Anomaly detection engine](./engine.md): The anomaly detection engine is the core component of ADBox. In fact, for every available anomaly detection method it orchestrates the interaction between the bulk functions of every algorithm, the data ingestion, data storage, user output, etc. In other words, the engine determines the sequence of actions to be performed to successfully go through the detection pipeline. This page also gives an overview of the training and prediction pipelines.
- [MTAD-GAT](./mtad_gat.md): ADBox incorporates machine learning algorithms for AD. Currently, the MTAD-GAT algorithm is supported. This page gives a high-level overview.
- [Detector](./detector_data_structure.md): The *detectors* are the "objects" used to perform detection. This page explains this notion and provides an overview of the ADBox pipelines' outcomes.
- [Front-end](./front_end.md): Available front-end interfaces.
- [Data transformation](./data_transformation.md): The raw data ingested by ADBox from Wazuh, or any other source, must be cleaned and prepared to be fed to the machine learning model. This page provides an overview of the transformations, including the preprocessing.
- [Run modes](./runmodes.md): A **run mode** is a flag to control the running of the prediction pipeline with respect to the time period of the data analyzed. This page explains the reasoning behind time management within ADBox and our implementation of run modes. ADBox supports one *offline* run mode, i.e., *historical*, and two *online* run modes, i.e., *batch* and *realtime*.
- [Wazuh ADBox integration](./detector_data_stream.md): A **detector data stream** is a Wazuh data stream index storing the prediction output. Via detector data streams we can interact with ADBox detection directly using the Wazuh Dashboard.
- [Example](./example.md): A simple example of ADBox usage from use-case definition to output analysis using a Jupyter notebook. This example uses data from HIDS and includes [Monitoring Linux resource usage](./linux_resource.md).
- [Detector dashboard tutorial](./dashboard_tutorial.md): A complete tutorial from use-case definition to building custom Wazuh Dashboard visualization.
- [Data cleaning](./data_cleaning.md): Tool for removing outdated detectors.
- [Integrations](../../../integrations/README.md): Artifacts (manuals, Docker compose files, configuration files, code and scripts) for integrating other tools with IDPS-ESCAPE, e.g., MISP, OpenCTI, OpenBAS, [SATRAP](https://github.com/AbstractionsLab/satrap-dl) and [OpenTRICK](https://github.com/itrust-consulting/OpenTRICK).
- [Glossary](./glossary.md): A summary of specific terminology used in this manual.

Combining Discover Dashboard and our Detector Dashboard we can monitor (in realtime) and investigate anomalies.
![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_36-Dashboard-video-2.gif)

![ADBox high level architecture](../specs/harc/assets/1B3A4_DIA_IDPS_ESCAPE_ADBoxDiagrams-ADBox-components_v1.3.png "ADBox high level architecture")