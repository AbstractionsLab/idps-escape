# IDPS-ESCAPE user manual

IDPS-ESCAPE is aimed at closely capturing the notion of MAPE-K (Monitor, Analyze, Plan, Execute and Knowledge) from autonomic computing applied to cybersecurity, which translates into providing a comprehensive package fulfilling the roles of a Security Orchestration, Automation, and Response (SOAR) system, a Security Information and Event Management (SIEM), and an Intrusion Detection and Prevention System (IDPS), with a central subsystem dealing with anomaly detection (AD) based on state-of-the-art advances in artificial intelligence such as the attention mechanism in machine learning (ML). We call this AD subsystem "**ADBox**", which comes with out-of-the-box integration with well-known open-source solutions such as [OpenSearch](https://opensearch.org/) for search and analytics, [Wazuh](https://wazuh.com/) as our SIEM\&XDR of choice, in turn connected to [MISP](https://www.misp-project.org/) for enriching alerts, and to [Suricata](https://suricata.io/), acting both as our network-based IDPS of choice, as well as a network-level data acquisition source.

Our extensible **ADBox** framework and implementation also include a Multivariate Time-series Anomaly Detection (MTAD) algorithm relying on Graph Attention Networks (GAT).

# Signature-based network and host IDPS and SIEM

To achieve comprehensive monitoring capabilities, we combine Suricata, an open-source Network Intrusion Detection System (NIDS), and Wazuh, a cybersecurity platform that integrates SIEM and XDR capabilities.

See the [Instructions for IDPS and SIEM integrated deployment](../../deployment/README.md).

# ADBox

The two major missions of ADBox are to:

1. perform core time-series anomaly detection operations via ML;
2. manage the data flow from the indexer to the core machine learning algorithm, and back to the SIEM.

## Table of contents

- [Install](/docs/manual/installation.md)
- [Setup and prerequisites](/docs/manual/setup_and_prerequisites.md)
- [User guide](/docs/manual/user_guide.md)
- [Use case definition guide](/docs/manual/use_case.md)
- [Anomaly detection engine](/docs/manual/engine.md)
- [MTAD-GAT](/docs/manual/mtad_gat.md)
- [Detector](/docs/manual/detector_data_structure.md)
- [Front-end](/docs/manual/front_end.md)
- [Data transformation](/docs/manual/data_transformation.md)
- [Run modes](/docs/manual/runmodes.md)
- [Wazuh ADBox integration](/docs/manual/detector_data_stream.md)
- [Example](/docs/manual/example.md)
- [Detector dashboard tutorial](/docs/manual/dashboard_tutorial.md)
- [Data cleaning](/docs/manual/data_cleaning.md)
- [Glossary](/docs/manual/glossary.md)


## Overview

- **Install.** Instructions to install ADBox.
- **Setup and prerequisites.** List of configuration files and prerequisites to complete the deployment of ADBox and to be able to create and run detectors.
- **User guide**. 
- **Use case definition guide**. Via ADBox it is possible to create, use and maintain detectors which ingest data and analyze them. The user can simply define the parameters via *use-case* configuration files and feed them to the ADBox entry point. This page contains the instructions for understanding and defining use-case files.
- **Anomaly detection engine.** The anomaly detection engine is the core component of ADBox. In fact, for every available anomaly detection method it orchestrates the interaction between the bulk functions of every algorithm, the data ingestion, data storage, user output, etc. In other words, the engine determines the sequence of actions to be performed to successfully go through the detection pipeline. This page also gives an overview of the training and prediction pipelines.
- **MTAD-GAT.** ADBox incorporates machine learning algorithms for AD. Currently, the MTAD-GAT algorithm is supported. This page gives a high-level overview.
- **Detector**. The *detectors* are the "objects" used to perform detection. This page explains this notion and provides an overview of the ADBox pipelines' outcomes.
- **Front-end.** Available front-end interfaces.
- **Data transformation.** The raw data ingested by ADBox from Wazuh, or any other source, must be cleaned and prepared to be fed to the machine learning model. This page provides an overview of the transformations, including the preprocessing.
- **Run mode**. A **run mode** is a flag to control the running of the prediction pipeline with respect to the time period of the data analyzed. This page explains the reasoning behind time management within ADBox and our implementation of run modes. ADBox supports one *offline* run mode, i.e., *historical*, and two *online* run modes, i.e., *batch* and *realtime*.
- **Wazuh ADBox integration**. A **detector data stream** is a Wazuh data stream index storing the prediction output. Via detector data streams we can interact with ADBox detection directly using the Wazuh Dashboard.
- **Example**. A simple example of ADBox usage from use-case definition to output analysis using a Jupyter notebook. This example uses data from HIDS and includes [Monitoring Linux resource usage](/docs/manual/linux_resource.md).
- **Detector dashboard tutorial**. A complete tutorial from use-case definition to building custom Wazuh Dashboard visualization.
- **Data cleaning**. Removing outdated detectors.
- **Glossary**. Summary of specific terminology used in this manual.

![ADBox high level architecture](../specs/harc/assets/1B3A4_DIA_IDPS_ESCAPE_ADBoxDiagrams-ADBox-components_v1.3.png "ADBox high level architecture")
