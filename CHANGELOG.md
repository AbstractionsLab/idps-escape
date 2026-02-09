# 0.7 (2026-02-09)

## Added

- **SONAR (SIEM-Oriented Neural Anomaly Recognition)**: Production-grade multivariate anomaly detection subsystem for Wazuh, a redesign and rewrite of ADBox
  - Powered by Microsoft's anomaly detection library implementing MTAD-GAT (time-series-anomaly-detector)
  - Complete SONAR subsystem with dedicated modules including CLI, engine, features, pipeline, and configuration modules
  - YAML-based scenario configuration system for repeatable detection workflows
  - CLI with `train`, `detect`, `scenario`, and `check` commands
  - Debug mode for offline testing with synthetic/historical JSON data without requiring Wazuh infrastructure
  - Support for real-time, batch, and historical detection modes
  - Categorical feature support with one-hot encoding (top-k categories per field)
  - Data shipping module (`sonar/shipper/`) for streaming anomalies to Wazuh data streams (RADAR integration)
  - Synthetic alert generation for sparse data scenarios with configurable modes (constant, random, copy)
  - Pre-built scenario templates: brute force detection, lateral movement, privilege escalation, Linux resource monitoring
  - Comprehensive test data including 12,000+ normal baseline alerts and attack scenario datasets
  - Full test suite in `tests/sonartests/` with test modules covering CLI, engine, features, scenarios, and integration
  - Complete documentation suite in `docs/manual/sonar_docs/`: architecture, setup, scenario guide, data shipping, troubleshooting, UML diagrams
- **RADAR lightweight risk engine** for real-time risk computation and tiered automated response
  - Mathematical formalization of risk calculation combining AD signals, signature-based detection, and CTI
  - Normalized risk scores (0-1) with configurable tier boundaries
  - Three-tier response system: Tier 1 (notify), Tier 2 (notify + remediate + case creation), Tier 3 (notify + isolate)
  - Time-boxed IOC extraction and context collection within configurable time windows
  - Scenario-to-rule mapping system for automated scenario identification
  - Consolidated active response script (`radar/scenarios/active_responses/radar_ar.py`) replacing scenario-specific implementations
  - Risk calculation documentation and specifications in `docs/manual/radar_docs/radar-risk-math.md`
- **FlowIntel integration** for automatic risk-oriented case creation upon anomaly detection
  - Initial minimal version of PyFlowintel as a standalone, self-contained piece of code in `radar_ar.py`
  - API clients for RADAR to communicate with FlowIntel and Wazuh
  - Note: Temporary implementation - future releases will migrate to DECIPHER REST API; initial implementation in RADAR has been further developed as part of project CyFORT and released as [PyFlowintel](https://github.com/AbstractionsLab/PyFlowintel)
- **SATRAP-DL DECIPHER CTI analysis integration** for real-time CTI analysis and incident case handling (stub/mock for now in `radar_ar.py`, integration planned for next update)
- **RADAR documentation**: New comprehensive guides in `docs/manual/radar_docs/`
  - `radar-architecture.md`: System architecture and component diagrams
  - `radar-active-response.md`: Active response logic flows and tier-based actions
  - `radar-risk-math.md`: Mathematical specification of risk engine
  - Scenario-specific guides: GeoIP detection, log volume, suspicious login
- **Dev container reorganization**: Separated configurations for different workflows
  - `.devcontainer/devcontainer.json`: Default lightweight SONAR-focused container
  - `.devcontainer/adbox/devcontainer.json`: ADBox legacy development environment
  - `.devcontainer/radar/devcontainer.json`: RADAR development environment
- Added SRS for ransomware detection scenario
- RADAR configuration in `radar/scenarios/active_responses/ar.yaml`: Risk-based active response configuration
- RADAR responses as lock user and terminate service oriented for Linux OS
- Added software validation test case `TST-049`-`TST-059` for `v0.7`
- Test results from `TRB-016` to `TRB-023` for `v0.7` after software validation test case executions
- Technical documentations for RADAR parts in `/docs/manual/radar_docs/`

## Modified

- **ADBox maintenance status**: Designated as legacy AD engine (MTAD-GAT) for research purposes only
  - New production deployments should use SONAR
  - ADBox retained for research continuity and algorithm comparison
  - Test files reorganized into `tests/adboxtests/` subdirectory
- **RADAR architecture**: Refactored design and restructured repository organization
- **Ansible automation**: Switched Wazuh manager customizations to persistent volume-mapped host paths
- **Active responses**: Consolidated multiple scenario-specific scripts into single generalized `radar_ar.py` implementation
- **Agent settings**: Moved agent-side configuration from per-agent tasks to centralized manager deployment using Wazuh `agent_config`
- **Wazuh version**: Upgraded to 4.14.1
- **stop-radar.sh**: Extended to support remote deployment options
- **Risk-based active response**: Implemented with FlowIntel case creation and tiered response logic
- **Project structure**: Renamed `soar-radar/` folder to `radar/` for consistency
- **pyproject.toml**: Refactored dependency groups for SONAR, ADBox, and RADAR subsystems

## Fixed

- **MVAD predict() TypeError**: Handle library signature changes by trying `context=` parameter first, then falling back to positional arguments
- **DataLoader validation**: Pre-validate training sample counts to prevent `num_samples=0` errors with informative error messages
- **SONAR configuration**: Fixed config file handling and default arguments
- **Dev container**: Fixed IDPS-ESCAPE dev container after ADBox folder refactoring

# 0.6 (2025-12-18)

## Added

- Documentation on the internals of `run-radar.sh` (`/docs/manual/radar-run-ad.md`): comprehensive guide to the three-stage pipeline (data ingestion, detector creation, monitor setup)
- New RADAR log volume scenario configurations: `agent-conf.xml`, `agent-config.xml`, `radar-pipeline.json`, `radar-transform.json`, and `wazuh_ingest.py`
- Refactored Ansible playbook tasks for Wazuh manager: modularized role split into `bootstrap.yml`, `host.yml`, `decoders.yml`, `rules.yml`, `responses.yml`, `ossec.yml`, `filebeat.yml`, `lists.yml`, and `stage.yml` for improved maintainability
- Archive of original monolithic Ansible playbook: `roles/wazuh_manager/tasks/archive/main_original.yml`

## Modified

- Main README
- RADAR README and main README updated with v0.5.3 information
- Technical documentation of automated Wazuh and RADAR deployment and activation: `/docs/manual/radar-manager-ansible-playbook.md`
- RADAR configuration in `config.yaml`: updated with log volume scenario parameters and detector configuration adjustments
- Ansible playbook main.yml: refactored from monolithic 1542 lines to modular tasks
- RADAR `monitor.py`: enhanced webhook and monitor configuration
- RADAR `webhook.py`: improved alert handling and integration
- RADAR `detector.py`: added connectivity improvements
- Exact launch commands used in `TRB-009`, `TRB-010` and `TRB-011` 
- Test results updated in `TRB-009`, `TRB-010`, `TRB-011`, `TRB-012`, and `TRB-015` for `v0.5.3` after software validation test case executions
- SRS-056 and TST-045, TST-048 specification updates
- RADAR suspicious login rules: enhanced detection logic in `local_rules.xml`
- Rebuilt the traceability web site
- Docker compose configuration cleanup in `docker-compose.core.yml`

## Fixed

- bugs in RADAR build corrupting previously installed scenarios depending on the order of execution
- RADAR Dockerfile.radar-cli: corrected CLI image configuration
- Log volume scenario README: resolved deployment documentation gaps
- Log volume detector template and pipeline configurations for improved aggregation accuracy
- Suspicious login helper script refactored into inline detection logic (removed `radar-auth-helper.py`, integrated directly into rules)

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