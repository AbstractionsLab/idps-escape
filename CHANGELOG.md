# 0.5.2 (2025-12-09)

## Modified

- Main README
- Detailed technical documentation of automated Wazuh and RADAR deployment and activation: `/docs/manual/radar-manager-ansible-playbook.md`
- Validation test verdicts in `TRB-013` and `TRB-014`
- Validation test results updated in `TRB-009`, `TRB-010` and `TRB-011` for `v0.5.1` after test reruns
- Rebuilt the traceability web site

# 0.5.1 (2025-12-09)

## Added

- Detailed technical documentation of the automation pipeline for the Wazuh manager and all the RADAR core stack: `/docs/manual/radar-manager-ansible-playbook.md`

## Modified

- Main README, RADAR README, ADBox README, and user manual README

## Fixed

- RADAR email notification automated response, used by suspicious login, geo ip detection and log volume size change detection
- RADAR `build-radar.sh` for the `log_volume` scenario, previously broken when run after building other scenarios

# 0.5 (2025-12-09)

## Added

- Dataset standardization via RADAR helpers to enable usage of RADAR on real Wazuh data
- 3 new RADAR scenario implementations capable of operating on real Wazuh monitoring data:
    - RADAR scenario: Signature-based anomaly detection of connection from non-whitelist countries
    - RADAR scenario: ML-based anomaly detection for unusual changes in log volumes
    - RADAR scenario: Signature-based anomaly detection for suspicious login (failed attempts burst and impossible travel)
- New dev container config file and Dockerfile for a lightweight dev container without pre-installing all ADBox dependencies
- Fully automated RADAR deployment, including core IDPS-ESCAPE dependencies (Wazuh manager and agents) powered by Ansible, managed and bootstrapped via `soar-radar/build-radar.sh` and `soar-radar/run-radar.sh`
- Support for remote Wazuh Manager for RADAR (Wazuh manager deployed on a VM different from the orchestration node)
- System requirement for new use case: detection of connection from non-whitelisted country list
- System requirement for new use case: anomalous size change of certain logs per endpoint
- RADAR and RATF technical specifications `HARC`, `LARC`, `SRS` and `SWD` added
- RADAR TST and TRB specifications for the December release validation test campaign

## Modified

- Migration of technical specs (under `docs/specs`) from YAML to Markdown with YAML front matter
- Moved ADBox dev container JSON config `devcontainer.json` file to `.devcontainer/adbox`
- Assigned meaningful names to both dev container configuration files under `.devcontainer`
- Technical specifications under `docs/specs/` and traceability page: `HARC`, `LARC`, `SRS`, `SWD`, `TST`, `TRB`

## Fixed

- Detection in the RADAR suspicious login scenario

# 0.4 (2025-09-03)

## Added

- New RADAR detection scenarios and Wazuh active/automated responses under `soar-radar`
    - suspicious login: detect anomalies in login patterns, such as logins from unusual locations or at odd hours
    - DDOS detection: identify Distributed Denial-of-Service (DDoS) attacks by monitoring network traffic for unusual spikes
    - C2 malware communication: detect network traffic patterns indicative of malware communication with command-and-control servers
- RADAR automated test framework (`soar-radar/radar-test-framework`) powered by Ansible providing a pipeline for deployment, ingestion, attack simulation, detection, data collection, post-processing and statistical analysis 
- Experiment evaluation module for computing information retrieval measures, e.g. precision, recall, etc.
- Datasets for RADAR experiments
- RADAR automated deployment via Infrastructure as Code (IaC) using Ansible (`deployment/wazuh/ansible`), handling Wazuh server and agents

## Modified

- RADAR insider threat scenario: identifying unusual user activities that may indicate insider threats, such as unauthorized access to sensitive data or abnormal login pattern
- Refactored RADAR scenario implementation
- Documentation of RADAR

## Fixed

- Detector and attack simulator bugs

# 0.3 (2025-06-18)

## Added

- Risk-aware Anomaly Detection-based Active Response (RADAR) scenarios towards the SOAR mission of IDPS-ESCAPE, stored in the `soar-radar` folder at the root
- Integration artifacts for Wazuh, OpenCTI and OpenBAS: `integrations` folder at the root
- C5-DEC publishing code to the tech specs folder
- Manual pages for the RADAR subsystem and CTI integrations to the `soar-radar` and `integrations` folders at the root, respectively

## Modified

- Technical specifications and traceability: added headers to all MRS, SRS and TRB items
- User manual: revisions throughout but mainly the project README, the setup and prerequisites manual page to detail dependencies for resource usage anomaly detection
- Various MRS, SRS, TST and TRB items to improve content and accuracy
- Traceability: regenerated all HTML pages providing artifact traceability

## Fixed

- Errors in the test case specifications

# 0.2 (2025-01-24)

## Added

- Software validation test campaign results for the main v0.1.4 features
- Test policies
- Driver tests
- Minor improvements throughout the code base
- Generic policy method to data shipping
- New technical diagrams (SWD, LARC)

## Modified

- All specs and diagrams (HARC, LARC, SWD, TST, TRA, TRB), user manual and README
- Improved shipping and added new default features
- Refactored: driver, console, data shipper, logging
- CHANGELOG

## Fixed

- Various bugs in the data shipping module, driver, ADBox engine and data transformer
- Rollover policy

# 0.1.4 (2024-11-18)

## Added
- Request-Response handler package: collecting all the functions to generate response and request dictionary (used e.g., by engine pipelines and data shipper)
- Shipper package: dedicated package aimed at shipping outcomes to an external database or application
    - Wazuh Data Shipper sub-package: including the data shipper subclass for shipping detectors' prediction to the Wazuh indexer and to manage detector data streams. This includes a Template Handler taking care of producing ad-hoc OpenSearch templates for the detectors.
- DataCleaner: aimed at removing detector folders and the corresponding data stream in the indexer.
- `siem_mtad_gat/assets/default_configs/mtad_gat_train_config_default_args.json`: configuration file to control the number of threads used by torch.
- Addition of manual pages for the ADBox-Wazuh integration and custom ADBox dashboard creation tutorial
- ADBox driver/CLI options `-s` for installing the Wazuh-oriented data shipping module and running it

## Fixed

- ConfigManager: missing conversion to string, recursive retrieval default arguments.
- Engine: add `.destroy_all_singletons()` to the prediction pipeline, and waiting time for batch prediction
- unit tests: Adapt to changes 

## Modified
- Redirection of logging to unique files
- SPOTManager: implementation of a distinct method for storing and recovering SPOT objects. For offline (i.e., historical) detection using training data, while for online (i.e., batch and realtime) storing distinct objects in the prediction folder.
- Specifications (HARC, LARC, SRS, SWD, TST, TRA, TRB), the user manual and README file
- `siem_mtad_gat/assets/default_configs/mtad_gat_train_config_default_args.json`: default features.

# 0.1.3 (2024-10-14)

## Added

- DetectorConfigManager in `config_managers`
- TimeManager
- Unit tests for: config managers, data managers, mtad_gat functions, spot manager, time manager
- Script for dedicated containerized testing
- Page about ADBox run modes and time management to the user manual
- Custom exceptions

## Fixed

- Time mapping: new time mapping and time management

## Modified

- Engine: integration of new components into the pipeline and refactoring of training and prediction pipelines
- User manual (engine and use cases)
- Driver: adapted to changes in the engine; removed prediction call from the default behavior
- README: instructions for running unit tests
- HARC, LARC and SWD design artifacts
- Centralization of logging into the `commons` logger


# Deprecation

- `engine/mtad_gat/detector.py`: Functionalities delegated to: TimeManager, DetectorConfigManager

# 0.1.2 (2024-09-07)

## Added

- New system/software requirement specification (SRS) items

## Fixed

- Broken relative links in the user manual and README

## Modified

- Technical specifications and traceability graph: revised content and certain high-level architecture (HARC) design artifacts moved to the low-level architecture (LARC) and others to software design (SWD)
- README to provide further usage recommendations and to highlight a few technical points related to the underlying machine learning algorithm
- User manual "overview" page renamed to "README"

# 0.1.1 (2024-09-01)

## Added

- Missing sample detector models to `./siem_mtad_gat/assets/detector_models` discussed in the README: `2d36a80a-c47a-4eb4-bb3e-5b2bfb90dc95` and `cf6e38ba-2cc0-41e1-b2bc-9072d80284fa`

# 0.1 (2024-09-01)

- Initial (Alpha) release of IDPS-ESCAPE