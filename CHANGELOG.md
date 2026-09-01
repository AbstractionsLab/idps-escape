# 2.0.0 (2026-09-01)

- **Documentation restructuring & consolidation**:
  - Reorganized deployment documentation: moved custom deployment guides from `/deployment/` to `/docs/manual/custom_deployments/`
  - Removed legacy Ansible playbooks and deprecated Wazuh installation guides
  - Streamlined and consolidated RADAR operational and user documentation
  - Updated specifications and web assets for improved clarity
  - Cleaned up obsolete CI/CD workflows and deployment scripts
- **Scanning detection scenario**:
  - Updated the scanning-detection rules, agent configuration, and manager snippets according to SRS-066.
  - Reworked scanning simulation and its tests with interactive execution, verification-aware waits.
  - Added DECIPHER integration for DECIPHER CTI score use in RADAR risk score computation and case creation in Flowintel.
- **Manager Enrichment & Architecture**:
  - Enrichment redesign: Moved enrichment logic into the manager; added a new manager-enrichment package (`enrichment.py`, `web_enrichment.py`, `geoip.py`, `state_store.py`) to centralize enrichment processing.
  - Enrichment integration: Enrichment processing is integrated with manager workflows and web endpoints; enrichment responsibilities moved out of previous components.
  - Migrating an existing `suspicious_login`/`geoip_detection` deployment: agents now ship raw `/var/log/auth.log` directly instead of running a per-endpoint enrichment helper/venv/systemd service; set `MAXMIND_LICENSE_KEY` in the manager's `.env`, redeploy the scenario with `sudo ./build-radar.sh suspicious_login`/`geoip_detection`, then re-run `bootstrap-agent.sh` on every existing endpoint (manager and agent updates must land together per endpoint). This also fixes per-user velocity/ASN state previously being tracked separately per endpoint instead of centrally.
- **Manager APIs & Integration**:
  - API redesign: Major API changes and integrator fixes to support the new manager-centric enrichment flow and related operations.
  - Wazuh API client & CLI: Added `wazuh_api` module to provide programmatic and CLI access to manager operations.
- **Deployment & Orchestration**:
  - Manager deployment scripts: Added manager helper scripts under `radar_deploy` (apply-scenario, assign-agent-group, ensure-certs, health, local-agent, mint-token, and helper libs) and top-level `radar.sh` and `bootstrap-agent.sh`.
- **Enrollment authentication & agent management**:
  - Enrollment hardening: Added `manager-harden-enrollment.sh` to secure Wazuh manager enrollment with password protection (`use_password=yes`), purge disabled (`purge=no`), and cluster key management.
  - Enrollment window control: Added `manager-enrollment-window.sh` to manage time-limited enrollment windows via firewall rules (port 1515).
  - Webhook enrollment: Webhook deployment now mints a short-lived registration token when needed, reuses an existing enrollment, persists the agent state, and fails clearly when a token is unavailable.
  - Agent lifecycle management: New scripts for agent operations: `manager-deregister-agent.sh` (deregister agents), `manager-unassign-agent-group.sh` (unassign groups), and `manager-undo-scenario.sh` (undo scenarios and remove associated rules/decoders/lists).
  - Wazuh API enhancements: Improved health checks, scenario operations, and token minting functionality via `wazuh_api` module.
- **RADAR GUI**:
  - Deploy, Infrastructure and Connector pages adapted to support new manager flows and deployment interactions.
  - Each action has a corresponding undo action (deregister agent, undo deployment, unassign agent group).
- **Test specifications & Documentation**:
  - New tests: unit/integration tests were added according to code changes.
  - Specifications: Added spec documents `TST-055.md` through `TST-058.md`.
  - RADAR manuals and specifications: Updated RADAR documentation for the redesign.
- **Ansible / Roles & Cleanup**:
  - Role removals & refactor: Removed Ansible role tasks and playbooks (health_check, wazuh_agent playbooks, multiple wazuh_manager tasks) as part of the redesigned manager workflow.
  - Code cleanup: General duplicates removal, tests fixes, and layer/fix adjustments across the repo.
  - Archived scenarios removal: Removed unmaintained archived scenarios (DDoS detection, GeoIP detection, insider threat) from `radar/archives/` to streamline the codebase.
- **Simulation Changes**:
  - Simulate scenarios: Updated radar simulation scenarios to run standalone on the endpoint without depending on Ansible automation.
- **Log-volume monitoring**:
  - Endpoint collection: `bootstrap-agent.sh --group log_volume` now installs and enables a systemd service/timer that records `/var/log` size every 30 seconds, while the Wazuh agent watches the resulting file.
  - Lifecycle cleanup: `uninstall-agent.sh` removes the collector, timer, logrotate configuration, and optionally its data.
- **Build & project layout cleanup**:
  - Per-component Dockerfiles and run scripts relocated into their own subdirectories: `sonar/Dockerfile.sonar`, `adbox/Dockerfile.adbox`, `adbox/Dockerfile.test`, `adbox/adbox.sh`, `adbox/run_test.sh`, `sonar/sonar.sh` (replacing the former root-level `sonar.Dockerfile`, `adbox.Dockerfile`, `test.Dockerfile`, `sonar.sh`, `adbox.sh`, `run_test.sh`); `build.sh` and all documentation/spec references updated accordingly.
  - Removed the root-level `radar.Dockerfile` (superseded by `radar/Dockerfile.radar-cli` and `radar/Dockerfile.test`) and the per-component `.devcontainer/adbox` and `.devcontainer/radar` dev container configs, consolidating on the single root `.devcontainer/devcontainer.json`.
  

# 1.1.0 (2026-05-19)

## Added

- **Web scanning detection scenario**: New production-ready RADAR scenario for detecting web-layer attacks:
  - **Signature-based detection** on Apache/Nginx HTTP access logs using built-in `web-log` decoder
  - **Automated response** with firewall-drop active response and email notifications for high-risk detections
  - **Full documentation**: Scenario guide ([scanning_detection_explained.md](docs/manual/radar_docs/radar-scenarios/scanning_detection_explained.md)) with objectives, detection methodology, manual setup, and deployment instructions
  - **System requirements and testing specification**: Formal requirement specification for web scanning detection with acceptance criteria and test specification are delivered
  - **Test report**: Added test report execution for `scanning_detection` scenario
- **RADAR default-rule support**: 
  - **Default active response and rule mapping**: Updated `radar/scenarios/active_responses/ar.yaml` and `radar/scenarios/ossec/radar-default-ossec-snippet.xml` to include the new default warning rule IDs `23503`, `23504`, and `23505`, and to use `authentication_failures` rule group
  - **Test and validation coverage**: Added test specifications and execution reports for the default-rule flow, active response handling, and simulation behavior across `TST-053` and `TST-054`
  - Added a new `default` simulation so the default Wazuh ruleset can be exercised end to end from the existing simulation entrypoints
  - `default` is now an explicit scenario option and is restricted to `--agent remote`
  - Added `scenarios.default.simulate` configuration support in `radar/config.yaml`
  - Extended `radar/roles/wazuh_agent/playbooks/simulate.yml` with a new `default` block that downgrades to vulnerable version and schedules an independent safety-net restore after `safety_net_minutes`

## Modified

- **Rule group support**: Consolidated RADAR Active Response script with the support of rule group additional to rule ID.
- **Unit test updates**: Adjusted `radar/tests/py/test_radar_ar.py` to cover the canonical rule group naming and accurate scenario identification behavior.


# 1.0.0 (2026-05-05)

## Added

- **Web interface**: Flask-based control panel (`app.py`) serving four pages with a functional deployment of RADAR scenarios.
  - **Active Responses page**: per-scenario configuration of risk weights, signature and anomaly detection scoring, time windows, tier boundaries, and per-tier mitigation actions.
  - **Infrastructure page**: full Ansible inventory management with cards for each manager and agent showing connection type, IP, and credential status.
  - **Connectors page**: credential and URL management for OpenSearch, Wazuh API, OpenSearch Dashboards, SMTP, DECIPHER, and Webhook. 
  - **Deploy page**: three-tab interface for running `build-radar.sh` (Build & deploy), `run-radar.sh` (Run Anomaly Detector, Hybrid and Anomaly ML scenarios only), and `health-radar.sh` (Status). 
  - **Vault and credential management**: Ansible Vault integration storing sudo passwords encrypted in `host_vars/<name>.yml`. The vault password is held in a server-side in-memory session (never written to disk) tied to a `radar_vault_sid` cookie, with create, unlock, and lock flows. SSH key passphrases are managed in the same session and used to drive a short-lived `ssh-agent` process for the duration of each remote Ansible run.
  - **REST API**: API under `/api/` covering scenarios, connectors, infrastructure CRUD, health checks, deploy streaming, vault, and SSH passphrase session management. 
  - **Software Design Specification**: software design specification for the RADAR GUI covering module structure, Flask application architecture, orchestrator module design decisions, the credential and session security model
  - **System requirements**: SRS-063 (REST API contract), SRS-064 (frontend specification), and SRS-065 (Ruleset-as-Code) define the three new subsystems
- **GeoIP frequency rule**: New rule detects high-frequency authentication attempts from non-whitelisted countries, providing escalation path for coordinated geographic anomalies
- **Off-hour login detection scenario specification** (`SRS-062`): New system requirement for per-user behavioral baseline detection of authentication events outside business hours (Mon–Fri, 07:00–20:00) using OpenSearch RCF with `data.user.keyword` categorical field
- **Ruleset as Code (RaC)**: GitHub Actions-based CI/CD pipeline for developing, reviewing, and deploying Wazuh rules and decoders without direct server access.
- **Test case and execution report**: TST-050 (SONAR Linux resource monitoring scenario, v1.0) and TRP-040 (execution report: 6/6 steps passed on 2026-05-04, debug mode)
- **New manual pages**: `radar-gui-user-manual.md` (GUI user guide with first-time setup checklist), `radar-rules.md` (Wazuh rules repository overview), `radar-risk-engine-roadmap.md` (CTI integration strategy), and `suspicious-login-extensibility-guide.md` (protocol extensibility guide)

## Modified

- **Active response logging**: Enhanced `radar_ar.py` to always log planned mitigations including `would_be_mitigations` when `allow_mitigation` is false, improving observability and audit trail for response decisions
- **Filebeat pipeline volume mapping**: the Wazuh archives ingest pipeline was configured with volume-mapped binding.
- **Ansible playbook documentation** (`radar-manager-ansible-playbook.md`): Updated task file table, variable tables, and per-block step descriptions
- **RADAR container hardening**: Applied security hardenings for RADAR containers' dockerfiles
- **Documentation review**: corrected factual and logic errors, and removed all cross-document duplication by consolidating repeated content to a single authoritative location per topic
- **Product presentation website**: Extended `product-presentation.html` with a RADAR GUI gallery section (four screenshots: Scenarios, Infrastructure, Connectors, Deploy); moved scenario screenshot from main README to `radar/README.md` and replaced it with a GIF walkthrough; simplified roadmap to reflect delivered items
- **SpecEngine C5-DEC v1.3 upgrade**: Added the dependency content fingerprinting feature of SpecEngine to IDPS-ESCAPE

## Fixed

- Decoder parsing for domain:port format in authentication event enrichment
- Re-attaches an existing monitor to a newly created detector when the stored `detector_id` is stale.
- Updated `test_monitor.py` and simulation test fixtures to reflect the new monitor re-attach logic and the `get_scenario_simulate` import added to the scenario scripts.

# 0.10 (2026-04-15)

## Added

- **Default rules**: Support for low-friction baseline threat detection framework for rapid RADAR deployment without prerequisite data preparation
- **SONAR per-bucket max aggregation**: New `max_numeric_fields` configuration key for `FeatureConfig` and scenario YAML files; fields listed there produce an additional `<field>__max` column computed via per-bucket `resample().max()` alongside the existing mean, enabling detection of brief spikes (e.g. a 55-second CPU burst) that bucket averaging would obscure
- **SONAR alert filter**: New `alert_filter` configuration key for `FeatureConfig` and scenario YAML files; accepts an arbitrary OpenSearch query fragment forwarded as a `bool.must` clause to `search_alerts()`, scoping ingestion to a specific rule group or rule ID set and preventing unrelated alert types from diluting the feature signal
- **SONAR resource-monitoring derived features**: Five new threshold-based derived features added to `WazuhFeatureBuilder._extract_derived_features()`: `is_cpu_high` (≥ 80 %), `is_cpu_critical` (≥ 95 %), `is_memory_high` (≥ 80 %), `is_memory_critical` (≥ 95 %), and `is_high_load` (`1min_loadAverage` ≥ 4.0); values are averaged per bucket, producing the fraction of alerts in that minute where the threshold was exceeded
- **SONAR scenario `derived_features` flag**: New `derived_features` boolean field in `TrainingScenario` (default `true`) properly wired from YAML through `cmd_scenario()` into `FeatureConfig`, replacing the previous no-op YAML key
- **Linux resource monitoring scenario improvements**: Updated `sonar/scenarios/linux_resource_monitoring.yaml` with additional numeric fields (`data.disk_usage_%`, `data.1min_loadAverage`, `data.5min_loadAverage`, `data.15min_loadAverage`), `max_numeric_fields` for CPU and memory spike detection, and `alert_filter` scoped to `rule.groups: performance_metric` matching Wazuh rules 100054–100060
- **SONAR test coverage**: new unit tests across `test_engine_and_features.py` (`TestMaxAggregation`, `TestResourceDerivedFeatures`), `test_scenario.py` (`TestTrainingScenarioNewFields`), and `test_wazuh_and_pipeline.py` (`TestAlertFilterForwarding`) covering max column generation, all five resource derived feature thresholds, new `TrainingScenario` field defaults, YAML parse/roundtrip, and `alert_filter` forwarding to `search_alerts()`
- **User interface prototype**: Added UI prototypes for the RADAR web interface, covering four functional screens: scenario binding to active response, AR configuration (weights, tiers, mitigations), manager and agent cluster management, and DECIPHER/Wazuh connector configuration.

## Fixed

- Poetry entrypoint script conflict resolution issue (adbox and sonar)

## Modified

- **Unified configuration files**: Consolidated scenario parameters from three sources into a single `radar/config.yaml` file
  - Added optional `ingest:` section under applicable scenarios for data ingestion parameters
  - Added optional `simulate:` section under all scenarios for RADAR test framework simulation parameters
  - All scenario configuration (detector/monitor, ingestion, and simulation settings) now co-located in `radar/config.yaml` for simplified management
- **SONAR `TrainingScenario`**: Extended with `derived_features`, `alert_filter`, and `max_numeric_fields` fields; `UseCase.from_yaml()` and `to_yaml()` updated to parse and emit all three
- **SONAR `cli.py`**: `cmd_scenario()` now propagates `derived_features`, `alert_filter`, and `max_numeric_fields` from the scenario into `cfg.features`; `_execute_training_phase()` and `_run_single_detection()` pass `query=cfg.features.alert_filter` to every `search_alerts()` call
- **SONAR feature log line**: Updated to report `N numeric + M max + D derived + C categorical = total` columns

## Modified

- **Unified configuration files**: Consolidated scenario parameters from three sources into a single `radar/config.yaml` file
  - Added optional `ingest:` section under applicable scenarios for data ingestion parameters
  - Added optional `simulate:` section under all scenarios for RADAR test framework simulation parameters
  - All scenario configuration (detector/monitor, ingestion, and simulation settings) now co-located in `radar/config.yaml` for simplified management

# 0.9 (2026-04-01)

## Added

- **Apache/Nginx web access log support for GeoIP detection**: Extended GeoIP scenario to monitor HTTP/HTTPS requests in addition to SSH authentication
  - New `accesslog` decoder (`0375-web-accesslog.xml`) for parsing Apache and Nginx web server access logs
  - New detection rule 100902 for identifying non-whitelisted country web access
  - Updated `SRS-055` with web server access log detection requirements and acceptance criteria
  - Extended unit tests for GeoIP enrichment functionality
- **Multi-node Wazuh deployment support**: Full support for multi-node Wazuh manager topologies
- **Webhook service bootstrap improvements**: Separate `bootstrap_webhook.yml` Ansible task for independent webhook deployment
- **Optional data ingestion for flexible detector training**: New `--ingest` flag for `run-radar.sh` script
  - Control synthetic dataset ingestion during scenario deployment
  - Enables both fresh deployments with training data and production deployments with live data
  - Updated documentation with usage examples and guidance on when to use/skip ingestion
  - BATS test case validating `--ingest` flag behavior
- **Test Case Specification TST-049**: New comprehensive test specification for RADAR integrity testing with a resulted report `TRP-038`
- A "What's new" page to the product presentation website highlighting the main features of our release notes

## Modified

- **GeoIP detection scenario**: Updated to support both SSH authentication and HTTP/HTTPS web access monitoring
- **DECIPHER incident endpoint**: Active Response was updated to new incident endpoint specification.
- **RADAR deployment documentation**:
  - `radar-getting-started.md`: Added multi-node deployment mode and configuration parameter documentation. Specified precondition details for Ansible executable.
  - `radar-architecture.md`: Added multi-node Wazuh deployment section with topology guidance
  - `radar-run-ad.md`: Updated with `--ingest` flag documentation and data ingestion guidance
  - `radar-manager-ansible-playbook.md`: Webhook bootstrap section explained
  - `geoip_detection_explained.md`: Added Apache/Nginx web server configuration for GeoIP monitoring
- **Specifications** (`docs/specs/srs/SRS-055.md`):
  - Expanded scope to include Apache/Nginx web access log monitoring
  - Added rule `100902` specifications for web server access control via GeoIP
  - Updated acceptance criteria with web access log test cases

## Fixed

- Improved webhook container initialization reliability with state-aware checks and retry logic
- Enhanced anomaly detection accuracy through configurable threshold-based filtering rules
- Health check validation now uses explicit file lists instead of pattern matching for higher reliability

# 0.8.1 (2026-03-16)

## Modified

- Revisions in the main README

# 0.8 (2026-03-15)

## Added

- **SATRAP-DL DECIPHER integration**: Replaced `SatrapClientMock` with a fully operational `DecipherClient` for real-time CTI analysis and incident case creation via the DECIPHER REST API (`analyze` and `create_incident` endpoints)
- **RADAR Health Check**: manager and agent side health checks using ansible tasks for RADAR elements via an entrypoint `health-radar.sh`
- **RADAR simulation**: attack simulation for 3 RADAR scenarios `simulate-radar.sh` orchestration script: Python simulation modules for GeoIP, log volume, and suspicious login
- **Software design specifications**: New HARC, LARC and SWD items for technical specs completeness
  - Explicit implementation reference sections linking to actual source files
  - Structured behavioral specifications
- **Tech specs README**: New `docs/specs/README.md` documenting the specification structure and publishing workflow based on C5-DEC
- **SpecEngine C5DEC v1.2 upgrade**: All SpecEngine scripts consolidated under `docs/specs/SpecEngine/`; new tools added: `c5graph.py` (interactive spec graph), `c5mermaid.py` (Mermaid diagram rendering), `doorstop_yml_to_md.py` (item migration helper), `prune_bad_links.py` (link hygiene); `dev.Dockerfile` extended with Node.js 20, Chromium and Mermaid CLI for diagram rendering
- **C5DEC traceability statistics script** (`docs/specs/SpecEngine/c5traceability.py`): generates traceability matrix coverage metrics including SRS test coverage, SRS design coverage, MRS specification coverage, HARC implementation coverage, TST execution coverage, defect severity summary, and overall health score; produces console output and HTML report (`docs/traceability/traceability_stats.html`)
- **C5-DEC interactive items browser** (`docs/specs/SpecEngine/c5browser.py`): generates a standalone Bootstrap + DataTables HTML page (`docs/traceability/items_browser.html`) with sortable and filterable tables for all Doorstop document types
- **C5-DEC specifications graph viewer**: visual interactive graph for browsing the interlinked specification and design artifacts
- **RADAR simulation ansible**: Ansible playbook for remote agent simulation support with SSH key authentication
- **RADAR simulation specs**: Technical specifications (SWD, SRS and TST) for RADAR simulation
- **RADAR Health Check specs**: Technical specifications (manual, SWD and SRS) for RADAR Health check
- **TRP document type**: TRA and TRB Doorstop document types merged into a single TRP (Test Case Execution Report) document type; v0.8 test campaign results captured in TRP-030 through TRP-037
- **SRS-061**: New system requirement specifying the tiered active response logic with DECIPHER risk-based decision making
- **Product website**: New IDPS-ESCAPE product presentation page (`docs/website/product-presentation.html`)

## Modified

- **Software design specifications**: Refactored HARC, LARC and SWD items for improved clarity and maintainability
  - Removed verbose pseudocode in favor of concise algorithmic descriptions
  - Improved formatting consistency with formulas, tables, and diagrams
  - Decoupled specification documents from implementation details
  - Enhanced traceability between design specs and source code
- **RADAR scenario**: new suspicious login correlation rule
- **RADAR scenario SRS items**: Refined and condensed SRS-050 through SRS-058 for improved clarity and conciseness; removed legacy `srs.xlsx` binary artifact
- **GeoIP SRS items**: Fixed content and formatting of SRS items related to GeoIP detection scenario; rebuilt traceability HTML pages
- **Tech specs publish script** (`docs/specs/publish.sh`): Updated to invoke scripts from `docs/specs/SpecEngine/`; integrated calls to `c5traceability.py` and `c5browser.py` for automatic report generation on publish
- **`pyproject.toml`**: Added `rich` (>=13.0) and `pyyaml` to the `docs` dependency group
- **Active Response mitigations**: Updated the command invocation syntax, extended `terminate_service.sh` to support `.service` units; updated LARC to document service support, and corrected the log format.
- **RADAR helper**: Removed the velocity cap; updated the calculation to use the timestamp from the log instead of the processing time; introduced a constant `dt_eps` to prevent division by zero when events share the same timestamp.
- **RADAR helper unit tests**: unit tests for RADAR helper `/radar/tests/py/test_radar_helper.py` reflect the new changes; additionally, two new tests were added to verify that country-change and ASN novelty tracking are maintained independently per user
- **RADAR helper specifications**: HARC, LARC and SWD items for RADAR helper were updated according to the updates made
- **Detector parameterization support**: included parameterization via `config.yaml` such as `rules`, `result_index_min_age`, `result_index_min_size`, `result_index_ttl` and `flatten_custom_result_index`
- **Tiered AR configuration**: Introduced `tier1_min` (Tier 0 boundary) to handle low-risk events without escalation; split `mitigations` into per-tier `mitigations_tier2` and `mitigations_tier3`; removed the now-redundant `risk_threshold` and `create_case` config keys
- **IOCExtractor**: Added country, ASN, and agent fields to the extracted IOC set; domain extraction now filters out file-extension-like TLDs via a blocklist
- **RADAR active response unit tests** (`radar/tests/py/test_radar_ar.py`): Extended for `DecipherClient` and incident endpoint coverage
- **DECIPHER environment configuration**: FLOWINTEL env vars replaced by `DECIPHER_BASE_URL`, `DECIPHER_VERIFY_SSL`, `DECIPHER_TIMEOUT_SEC` in `env.example` and `health-radar.sh`
- **RADAR documentation**: Updated `radar-architecture.md` and `radar-active-response.md` for the tiered DECIPHER logic; updated `radar-getting-started.md`
- **RADAR README**: Added MISP integration explanation and screenshots
- **Context diagram**: Removed direct CTI arrow from IDPS-ESCAPE context diagram

## Fixed

- **Numerical table sorting in `c5browser.py`**: Fixed incorrect alphanumeric sorting of requirement ID columns; columns with numeric suffixes (e.g. SRS-001, SRS-010) now sort numerically rather than lexicographically
- **`stop-radar.sh`**: Removed hardcoded `PROJECT=soar-radar` variable that caused Docker Compose project naming conflicts
- **`simulate-radar.sh`**: Fixed container name lookup to use the correct nested `scenarios` key in the YAML config

# 0.7 (2026-02-09)

## Added

- **SONAR (SIEM-Oriented Neural Anomaly Recognition)**: multivariate anomaly detection subsystem for Wazuh, a redesign and rewrite of ADBox
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