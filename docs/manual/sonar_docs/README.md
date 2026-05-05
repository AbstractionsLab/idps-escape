# SONAR documentation

Comprehensive documentation for SONAR (SIEM-Oriented Neural Anomaly Recognition) - the scenario-based anomaly detection system for IDPS-ESCAPE.

> ⚠️ **All commands should be run from project root** (`/home/alab/soar`)

> 💻 **For Python API reference**: See [sonar/README.md](../../../sonar/README.md) for developer quickstart and programmatic usage examples.

## Documentation overview

| Document | Purpose | Audience |
|----------|---------|----------|
| **[setup-guide.md](./setup-guide.md)** | Installation, configuration, CLI usage, debug mode | Everyone |
| **[scenario-guide.md](./scenario-guide.md)** | Complete scenario system guide with examples | Users & Developers |
| **[data-injection-guide.md](./data-injection-guide.md)** | Inject synthetic data for fast testing | Testers & Developers |
| **[data-shipping-guide.md](./data-shipping-guide.md)** | Ship anomalies to Wazuh data streams (production feature) | Operators & DevOps |
| **[model-naming-guide.md](./model-naming-guide.md)** | Model naming and versioning strategies | Users & Developers |
| **[troubleshooting.md](./troubleshooting.md)** | Error solutions and diagnostics | Everyone |
| **[architecture.md](./architecture.md)** | System design, patterns, and principles | Developers & Architects |
| **[uml-diagrams.md](./uml-diagrams.md)** | Visual system design diagrams | Developers & Architects |

## Getting started

### New users (5 minutes)

```bash
# 1. Install (from project root)
cd /home/alab/soar
poetry install --with sonar

# 2. Run a scenario (from project root)
poetry run sonar scenario --use-case sonar/scenarios/brute_force_detection.yaml --debug
```

Read: [setup-guide.md](./setup-guide.md)

### Understanding scenarios (15 minutes)

1. Review built-in scenarios in `sonar/scenarios/` (from project root):
   - `brute_force_detection.yaml` - SSH/authentication attacks
   - `lateral_movement_detection.yaml` - Network traversal attacks
   - `privilege_escalation_detection.yaml` - Privilege abuse
   - `linux_resource_monitoring.yaml` - Resource utilization anomalies
2. Read scenario structure in [scenario-guide.md](./scenario-guide.md)
3. Create custom scenario following templates

### Troubleshooting issues

Check [troubleshooting.md](./troubleshooting.md) for:
- Connection errors
- Training/detection issues
- Data quality problems
- Performance optimization

### Architecture deep dive

For developers extending the system:
1. Read [architecture.md](./architecture.md) - design principles and module structure
2. Review [uml-diagrams.md](./uml-diagrams.md) - class and sequence diagrams

## Quick reference by task

| Task | Document | Section |
|------|----------|---------|
| Install SONAR | [setup-guide.md](./setup-guide.md) | Installation |
| Configure Wazuh connection | [setup-guide.md](./setup-guide.md) | Configuration |
| Run first scenario | [scenario-guide.md](./scenario-guide.md) | Overview → Example |
| Test with synthetic data | [data-injection-guide.md](./data-injection-guide.md) | Quick start |
| Enable data shipping (production) | [data-shipping-guide.md](./data-shipping-guide.md) | Quick start |
| Integrate with RADAR | [data-shipping-guide.md](./data-shipping-guide.md) | Integration with RADAR |
| View system diagrams | [uml-diagrams.md](./uml-diagrams.md) | All diagrams |

## Key concepts

### Scenario-based approach

SONAR uses **YAML scenarios** to define anomaly detection workflows:

```yaml
name: "Brute Force Detection"
training:
  lookback_hours: 168  # 1 week baseline
  numeric_fields: ["rule.level"]
detection:
  mode: "batch"
  threshold: 0.7
```

See [scenario-guide.md](./scenario-guide.md) for complete details.

### Flexible execution

Scenarios automatically execute based on sections present:

- **Training + Detection**: Full workflow (train model, then detect)
- **Training only**: Build baseline model without detection
- **Detection only**: Use existing model for investigation

See [scenario-guide.md](./scenario-guide.md#execution-modes)

### Debug mode

Test without Wazuh infrastructure:

```bash
poetry run sonar scenario --use-case scenario.yaml --debug
```

Uses local JSON test data for development and CI/CD.

See [setup-guide.md](./setup-guide.md#debug-mode)

### Configuration separation

- **Config files** (`sonar/default_config.yaml`): Infrastructure (Wazuh connection, paths)
- **Scenario files** (`sonar/scenarios/*.yaml`): Detection logic (features, thresholds)

See [setup-guide.md](./setup-guide.md#configuration)

## System architecture

**Conceptual view** (high-level components):

```
CLI Commands (train, detect, scenario, check)
    ↓
Configuration (YAML → Python dataclasses)
    ↓
Data Ingestion (WazuhIndexerClient | LocalDataProvider)
    ↓
Feature Engineering (WazuhFeatureBuilder)
    ↓
ML Engine (MVADModelEngine - Microsoft MVAD)
    ↓
Post-processing (MVADPostProcessor)
    ↓
Storage (Wazuh Indexer / OpenSearch)
```

Details: [architecture.md](./architecture.md)

## Built-in scenarios

| Scenario | Use Case | File (from project root) |
|----------|----------|------|
| Brute Force Detection | Authentication attacks | `sonar/scenarios/brute_force_detection.yaml` |
| Lateral Movement | Cross-host authentication | `sonar/scenarios/lateral_movement_detection.yaml` |
| Privilege Escalation | Unusual sudo/su usage | `sonar/scenarios/privilege_escalation_detection.yaml` |
| Resource Monitoring | CPU/memory anomalies | `sonar/scenarios/linux_resource_monitoring.yaml` |

See [scenario-guide.md](./scenario-guide.md#built-in-scenarios)

## Testing

```bash
# All tests
poetry run pytest tests/

# Specific component
poetry run pytest tests/engine_test.py

# With coverage
poetry run pytest --cov=sonar
```

Test files in `../../tests/`

## Integration

### Wazuh

- **Input**: Reads from `wazuh-alerts-*` indices
- **Output**: Writes anomalies to `wazuh-anomalies-mvad`
- **Authentication**: Basic auth (configurable)

### RADAR

SONAR anomalies trigger RADAR automated responses:
- RADAR monitors anomaly index
- High-confidence anomalies trigger playbooks
- Integration via shared Wazuh Indexer

Details: [setup-guide.md](./setup-guide.md#integration-with-wazuh)

## Project structure

Relative to project root (`/home/alab/soar/`):

```
sonar/
├── README.md                  # SONAR overview
├── scenarios/                 # Built-in detection scenarios
│   ├── brute_force_detection.yaml
│   ├── lateral_movement_detection.yaml
│   ├── privilege_escalation_detection.yaml
│   └── linux_resource_monitoring.yaml
├── test_data/                 # Test datasets for debug mode
│   ├── synthetic_alerts/
│   ├── generated_scenarios/
│   └── resource_monitoring/
├── models/                    # Trained model storage
├── cli.py                     # Command-line interface
├── config.py                  # Configuration system
├── scenario.py                # Scenario loader
├── engine.py                  # MVAD model wrapper
├── features.py                # Feature engineering
├── pipeline.py                # Post-processing
├── wazuh_client.py            # Wazuh API client
└── local_data_provider.py     # Debug mode data provider
```

---

## Quick reference

### Run tests
```bash
# From project root (/home/alab/soar)
poetry run pytest tests/sonartests/ -v
```

### Execute scenario
```bash
# From project root (/home/alab/soar)
poetry run sonar scenario --use-case sonar/scenarios/brute_force_detection.yaml
```
