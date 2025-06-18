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