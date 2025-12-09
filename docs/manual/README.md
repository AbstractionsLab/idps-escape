# IDPS-ESCAPE user manual

IDPS-ESCAPE is aimed at closely capturing the notion of MAPE-K (Monitor, Analyze, Plan, Execute and Knowledge) from autonomic computing applied to cybersecurity, which translates into providing a comprehensive package that implements a Security Orchestration, Automation, and Response (SOAR) system.

This resulting SOAR system combines following building blocks: a Security Information and Event Management (SIEM) system, an Intrusion Detection and Prevention System (IDPS), Cyber Threat Intelligence (CTI) tools, a Risk-aware AD-based Active Response ([**RADAR**](/soar-radar/README.md)) subsystem providing AD scenario implementations, coupled with active response solutions and SOAR playbooks facilitating security orchestration, and an anomaly detection (AD) subsystem, called [**ADBox**](/docs/manual/adbox.md).

We adopt a hybrid method aimed at robustness and resilience to adversarial interference involving three elements: (i) signature-based detection with (ii) AD based on deep learning models via MTAD-GAT, relying on state-of-the-art advances in artificial intelligence (AI) and machine learning (ML) such as the *attention mechanism* and (iii) a classical algorithm for AD on streams such as the Robust Random Cut Forest (RRCF) algorithm supporting categorical features.

## RADAR and ADBox

The [RADAR](/soar-radar/README.md) subsystem provides solutions for completing the SOAR 
mission of IDPS-ESCAPE enabling security orchestration and automation driven by a 
Risk-informed AD-based active response (AR) paradigm.

The two major missions of ADBox are to:

1. perform core time-series anomaly detection operations via ML;
2. manage the data flow from the indexer to the core machine learning algorithm, and back to the SIEM.

## Map of content

- [RADAR](/soar-radar/README.md)
    - [Automated manager deployment via Ansible playbook](/docs/manual/radar-manager-ansible-playbook.md)
    - [Automated agent deployment via Ansible playbook (soon...)]()
- [ADBox](/docs/manual/adbox.md) 
    - [Installation](/docs/manual/adbox_installation.md)
    - [Setup and prerequisites](/docs/manual/setup_and_prerequisites.md)
    - [Quick start](/docs/manual/quick_start.md)
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
- [Joint deployment of IDPS, SIEM and OpenSearch AD](../../deployment/README.md)
- [Integrations](/integrations/README.md)
- [Glossary](/docs/manual/glossary.md)

## SIEM, network and host IDPS and ML-based AD

To achieve comprehensive monitoring capabilities, we combine Suricata, an open-source Network Intrusion Detection System (NIDS), and Wazuh, a cybersecurity platform that integrates SIEM and XDR capabilities; see the [instructions for a joint deployment of IDPS, SIEM/XDR and OpenSearch AD](../../deployment/README.md).