# RADAR Scenarios

This directory contains all the artifacts required for deploying RADAR (Risk-aware Anomaly Detection-based Automated Response) scenarios in the IDPS-ESCAPE system. Each scenario integrates signature-based and/or ML-based anomaly detection with automated response capabilities through Wazuh.

## Overview

The `scenarios/` folder provides a modular, scenario-driven approach to security orchestration. Each scenario includes detection rules, decoders, active responses, agent configurations, and deployment pipelines that work together to detect and respond to specific security threats.

## Directory structure

```
scenarios/
├── active_responses/       # Shared active response scripts
├── agent_configs/          # Agent-side configurations per scenario
├── decoders/              # Log parsing and field extraction rules
├── dockerfiles/           # Container definitions for local detection agents
├── ingest_scripts/        # Dataset ingestion utilities
├── lists/                 # Reference lists (e.g., whitelists)
├── ossec/                 # Manager-side OSSEC configuration snippets
├── pipelines/             # Data processing pipeline configurations
├── rules/                 # Detection rules per scenario
│   ├── default/           # Baseline command shell execution detection
│   ├── geoip_detection/   # Geographic access control rules
│   ├── log_volume/        # OpenSearch AD integration rules
│   └── suspicious_login/  # Credential attack detection rules
└── templates/             # Index templates for OpenSearch
```

## Folder details

### `active_responses/`

Contains Python scripts that execute automated responses when anomalies are detected. These scripts are triggered by Wazuh rules and perform action as email notifications. This further can be extended to blocking, isolation and termination actions.

- **`radar_ar.py`**: Main active response orchestrator that coordinates automated actions based on detected anomalies.

Active responses reduce manual analyst workload by automating initial triage and response actions.

### `agent_configs/`

Stores agent-side configuration snippets organized by scenario. Each scenario folder contains:

- **`radar-<scenario>-agent-snippet.xml`**: Configuration blocks that get injected into the Manager's `agent.conf` file via centralized agent configuration
- Defines log collection settings, localfile entries, and agent-specific parameters required for the scenario

These configurations are deployed to agent groups through Wazuh's centralized configuration management system.

### `decoders/`

Contains custom log decoders organized by scenario. Decoders parse incoming log data and extract structured fields for analysis:

- **`geoip_detection/`**: Decoders for GeoIP-based detection scenarios
- **`log_volume/`**: Decoders for log volume anomaly detection
- **`suspicious_login/`**: Contains `0310-ssh.xml` - a customized SSH decoder that extracts velocity/location change and geographic information from SSH logs

Decoders transform unstructured log messages into structured events that rules can analyze.

### `dockerfiles/`

Provides Dockerfiles for containerized deployment of scenario-specific detection agents:

- **`Dockerfile.geoip_detection_agent`**: Builds container for GeoIP detection agents
- **`Dockerfile.log_volume_agent`**: Builds container for log volume monitoring agents  
- **`Dockerfile.suspicious_login_agent`**: Builds container for suspicious login detection agents

These containers run Wazuh agents pre-configured for their specific detection scenarios, enabling scalable and isolated deployments.

### `ingest_scripts/`

Contains scripts for populating the Wazuh indexer with data:

- **`log_volume/wazuh_ingest.py`**: Ingests custom event datasets into OpenSearch to accelerate detector initialization and model training
- **`suspicious_login/wazuh_ingest.py`**: Ingestion script for authentication log datasets

These scripts are essential for testing scenarios with demo datasets and for training ML models before production deployment.

### `lists/`

Stores reference lists used by detection rules:

- **`whitelist_countries`**: List of approved country codes for GeoIP-based detection. Connections from non-whitelisted countries trigger alerts

Lists provide dynamic, updateable reference data that rules can check without requiring rule modifications.

### `ossec/`

Contains OSSEC configuration snippets that get injected into the Wazuh manager's `ossec.conf`. These are needed configurations for Wazuh Manager depending on scenario. It is a binding and controlling configurations, currently it is mainly connecting rules and active response.

These snippets are deployed idempotently via Ansible's `blockinfile` module, ensuring repeatable configuration management.

### `pipelines/`

Defines data processing pipelines for ingesting and transforming logs:

- **`log_volume/radar-pipeline.txt`**: Contains the `date_index_name` processor configuration that gets injected into Filebeat's Wazuh archives pipeline. This ensures logs are separately indexed with proper time-based index names for the log volume scenario.

Pipelines modify how data flows from Wazuh through Filebeat into OpenSearch, enabling scenario-specific indexing strategies.

### `rules/`

Contains Wazuh detection rules organized by scenario. Each scenario folder includes:

- **`default/radar_rules.xml`**: Baseline threat detection rules for all deployments (6 rules: IDs 100400–100405). These rules operate on standard Wazuh event formats without requiring custom decoders, radar-helper enrichment, or index schema modifications. Current focus: command shell execution detection (PowerShell, CMD.exe, batch scripts), extensible to any threat indicators available in standard events.
- **`geoip_detection/a2-geoip-detection.xml`**: Rules that trigger on SSH connections from non-whitelisted countries
- **`log_volume/a1-log-volume.xml`**: Rules that detect anomalous log volume event from webhook
- **`suspicious_login/a3-suspicious-login.xml`**: Rules that identify suspicious authentication patterns (brute force and impossible travel anomalies)

Rules analyze decoded events and generate alerts when suspicious patterns are detected. They integrate with active responses to trigger automated actions.

**Default Rules Philosophy (a0)**: The `default` scenario rules provide a low-friction detection framework applicable to any RADAR deployment. Unlike scenario-specific rules (which may require preprocessing, enrichment, or schema adaptation), Default rules operate on events already present in standard Wazuh installations. This enables rapid threat detection, immediate CTI integration, and extensible case creation without infrastructure investment. The framework is designed to be extended with additional detection rules following the "no-prerequisite" principle.

### `templates/`

Contains OpenSearch index templates that define mappings and settings:

- **`log_volume/radar-template.json`**: Index template defining field mappings, data types, and analyzer configurations for log volume indices

Templates ensure consistent data structures across indices, which is critical for accurate anomaly detection and querying.

A consolidated overview of RADAR scenarios, together with the corresponding manual configuration and deployment instructions, is provided in [the dedicated documentation manual](/docs/manual/radar-scenarios/).