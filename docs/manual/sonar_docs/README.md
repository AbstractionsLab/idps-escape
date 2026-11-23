# SONAR documentation

Comprehensive documentation for SONAR (SIEM-Oriented Neural Anomaly Recognition) - the scenario-based anomaly detection system for IDPS-ESCAPE.

> Commands below are written for the project root (`/home/alab/soar`), because they name files such as `sonar/scenarios/<file>.yaml`. SONAR itself does not depend on the working directory: paths inside configuration and scenario files are relative to those files, and models go to `sonar/models/` (see [Where SONAR keeps its files](./model-naming-guide.md#where-sonar-keeps-its-files)).

> 💻 **For Python API reference**: See [sonar/README.md](../../../sonar/README.md) for developer quickstart and programmatic usage examples.

## Documentation overview

| Document | Purpose | Audience |
|----------|---------|----------|
| **[setup-guide.md](./setup-guide.md)** | Installation, configuration, CLI usage, debug mode | Everyone |
| **[scenario-guide.md](./scenario-guide.md)** | Complete scenario system guide with examples | Users & Developers |
| **[data-injection-guide.md](./data-injection-guide.md)** | Inject synthetic data for fast testing | Testers & Developers |
| **[data-shipping-guide.md](./data-shipping-guide.md)** | Anomaly output: sinks, the SONAR event sent to the Wazuh manager, rules, data stream, delivery watermarks | Operators & DevOps |
| **[model-naming-guide.md](./model-naming-guide.md)** | Model names, where SONAR keeps its files (`SONAR_HOME`), the model directory format and how to protect it | Users & Operators |
| **[evaluation-guide.md](./evaluation-guide.md)** | Measure detection quality on labelled data, compare backends and other detectors, calibrate thresholds and `anomaly_confidence` | Users & Developers |
| **[radar-comparison-guide.md](./radar-comparison-guide.md)** | Run SONAR on RADAR's resource-utilization data, one model per host, and score both detectors on the same labelled window (`sonar export`) | Users & Researchers |
| **[troubleshooting.md](./troubleshooting.md)** | Error solutions and diagnostics | Everyone |
| **[architecture.md](./architecture.md)** | System design, patterns, and principles | Developers & Architects |
| **[uml-diagrams.md](./uml-diagrams.md)** | Visual system design diagrams | Developers & Architects |

## Getting started

### New users (5 minutes)

```bash
# 1. Install
cd /home/alab/soar
poetry install --with sonar

# 2. Run a scenario on local test data
poetry run sonar scenario --use-case sonar/scenarios/linux_resource_monitoring.yaml --debug
```

`linux_resource_monitoring.yaml` and `radar_linux_resource_utilization.yaml` read their own packaged datasets; the other shipped scenarios read the packaged `sonar/test_data/synthetic_alerts`. `--use-case linux_resource_monitoring` (the packaged example's name) works from any directory.

Read: [setup-guide.md](./setup-guide.md)

### Understanding scenarios (15 minutes)

1. Review built-in scenarios in `sonar/scenarios/`:
   - `brute_force_detection.yaml` - SSH/authentication attacks
   - `lateral_movement_detection.yaml` - Network traversal attacks
   - `privilege_escalation_detection.yaml` - Privilege abuse
   - `linux_resource_monitoring.yaml` - Resource utilization anomalies
   - `radar_linux_resource_utilization.yaml` - RADAR's resource-utilization events and features, for comparison with RADAR ([guide](./radar-comparison-guide.md))
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
| Connect SONAR to the Wazuh manager | [setup-guide.md](./setup-guide.md#wazuh-integration) | Wazuh integration |
| Choose where anomalies go | [data-shipping-guide.md](./data-shipping-guide.md) | Choosing the sinks |
| Measure and calibrate detection | [evaluation-guide.md](./evaluation-guide.md) | Evaluating a scenario |
| Run SONAR on RADAR's resource data and compare the two | [radar-comparison-guide.md](./radar-comparison-guide.md) | All |
| One model per host | [radar-comparison-guide.md](./radar-comparison-guide.md#one-model-per-host) | One model per host |
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
  mode: "historical"
  lookback_minutes: 1440  # window to score; earlier context is fetched automatically
  threshold: null         # optional minimum MVAD severity (0-1)
  min_consecutive: 2
```

A bucket is reported only when the backend's own `is_anomaly` decision (MVAD by default) flags it, its severity is at least `threshold` (when one is set), and it belongs to a run of at least `min_consecutive` flagged buckets.

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
poetry run sonar scenario --use-case sonar/scenarios/linux_resource_monitoring.yaml --debug
```

Uses local JSON test data for development and CI/CD. Only the `--debug` flag switches to local data. Debug runs (`--debug`, or `debug.enabled: true` in YAML, which still reads from Wazuh) print the SONAR events on standard output instead of delivering them (`output.debug_sinks`).

`debug.data_dir` chooses the local data. A relative value is relative to the scenario or configuration file; unset, it is the packaged `sonar/test_data/synthetic_alerts`.

See [setup-guide.md](./setup-guide.md#debug-mode)

### Configuration separation

- **Config files** (`sonar/default_config.yaml`): Infrastructure (Wazuh connection, sinks, models directory, default backend)
- **Scenario files** (`sonar/scenarios/*.yaml`): Detection logic (features, windows, detection mode)

See [setup-guide.md](./setup-guide.md#configuration)

## System architecture

**Conceptual view** (high-level components):

```
CLI Commands (train, detect, scenario, evaluate, export, check, wazuh install-rules)
    ↓
Configuration (YAML → Python dataclasses)
    ↓
Data Ingestion (WazuhIndexerClient | LocalDataProvider)
    ↓
Feature Engineering (WazuhFeatureBuilder)
    ↓
Model engine (ModelEngine) + detector backend (mvad: Microsoft MVAD | pca: linear multivariate | ewma: baseline)
    ↓
Post-processing (MVADPostProcessor)
    ↓
Sinks (Wazuh manager by default; data stream, local files)
```

Details: [architecture.md](./architecture.md)

## Built-in scenarios

| Scenario | Use Case | File |
|----------|----------|------|
| Brute Force Detection | Authentication attacks | `sonar/scenarios/brute_force_detection.yaml` |
| Lateral Movement | Cross-host authentication | `sonar/scenarios/lateral_movement_detection.yaml` |
| Privilege Escalation | Unusual sudo/su usage | `sonar/scenarios/privilege_escalation_detection.yaml` |
| Resource Monitoring | CPU/memory anomalies | `sonar/scenarios/linux_resource_monitoring.yaml` |
| RADAR Linux Resource Utilization | RADAR's CPU/memory events and features, for comparison with RADAR | `sonar/scenarios/radar_linux_resource_utilization.yaml` |
| Example | Minimal template with every section | `sonar/scenarios/example_scenario.yaml` |
| Model naming example | How `model_name` names, keeps and replaces trained models | `sonar/scenarios/example_model_naming.yaml` |

Each detection scenario (all but the two examples) carries its calibrated `threshold`, `min_consecutive` and `anomaly_confidence` (see the [evaluation evidence](../../specs/trp/assets/sonar-evaluation/README.md)). The two resource scenarios name their own packaged debug data; the others use `sonar/test_data/synthetic_alerts`. Fields: [scenario-guide.md](./scenario-guide.md#scenario-structure)

## Testing

The tests need the `test` dependency group: `poetry install --with sonar,test`.

```bash
# SONAR tests
poetry run pytest tests/sonartests

# Skip the tests that use the real MVAD library (slow, import torch)
poetry run pytest tests/sonartests -m "not slow"

# Specific component
poetry run pytest tests/sonartests/test_engine_and_features.py

# With coverage
poetry run pytest tests/sonartests --cov=sonar
```

Test files are in `tests/sonartests/`. 

## Integration

### Wazuh

- **Input**: Reads from `wazuh-alerts-*` by default (`wazuh.alerts_index_pattern`); `radar_linux_resource_utilization` reads RADAR's collector events from `wazuh-archives-*`
- **Output**: Sends anomalies to the Wazuh manager, which raises them as alerts (rules 100500–100519); optionally also to the data stream `sonar_anomalies_mvad_<scenario_id>`. See [Wazuh integration](./setup-guide.md#wazuh-integration) and the [anomaly output guide](./data-shipping-guide.md)
- **Authentication**: Basic auth (configurable)

### RADAR

SONAR alerts carry `data.anomaly_grade` and `data.anomaly_confidence`, the fields RADAR's active response reads for anomaly-detection scenarios, so RADAR can act on them through its `ar.yaml`; SONAR's configuration does not set this up. See [SWD-037](../../specs/swd/SWD-037.md).

To compare SONAR's detection with RADAR's on the same data, see the [RADAR comparison guide](./radar-comparison-guide.md).

## Project structure

SONAR's code is in `sonar/` at the project root; [Module structure](./architecture.md#module-structure) describes each module. The bundled scenarios are in `sonar/scenarios/`, the debug datasets and their generators in `sonar/test_data/`, SONAR's Wazuh rules, `<localfile>` block and compose overlay in `sonar/wazuh/`, and the trained models (one directory each) and delivery watermarks in `sonar/models/`, which git ignores.

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
