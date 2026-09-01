# RADAR: Risk-aware Anomaly Detection-based Automated Response

RADAR is a key part of the SOAR mission of IDPS-ESCAPE, providing anomaly detection scenarios with automated responses. This folder stores all design, development, and implementation artifacts for deploying AD scenarios with dedicated active responses (AR).

Our security orchestration approach provides Risk-aware AD-based AR (**RADAR**) modules aimed at enhancing SOC operations. RADAR modules integrate with the [OpenSearch AD plugin](https://wazuh.com/blog/enhancing-it-security-with-anomaly-detection/) using Amazon's [Random Cut Forest (RCF) algorithm](https://www.amazon.science/publications/robust-random-cut-forest-based-anomaly-detection-on-streams). We recommend a hybrid approach combining SONAR/ADBox with RRCF-based RADAR for [resilience to adversarial interference](#best-practices-for-robust-ad-with-resilience-to-adversarial-interference).

We leverage [OpenSearch's latest advances](https://opensearch.org/anomaly-detection/), including [false positive reductions](https://opensearch.org/blog/reducing-false-positives-through-algorithmic-improvements/) and support for [high-cardinality anomaly detection](https://aws.amazon.com/blogs/big-data/detect-anomalies-on-one-million-unique-entities-with-amazon-opensearch-service/) via slicing, enabling per-user or per-device baseline detectors.

> 📚 **For comprehensive documentation**: See [docs/manual/radar_docs/](../docs/manual/radar_docs/) for learning paths, troubleshooting guides, integration documentation, and architecture deep dives.

## Table of contents

| Document | Description |
|----------|-------------|
| [Getting Started](/docs/manual/radar_docs/radar-getting-started.md) | Prerequisites, setup instructions, deployment modes, configuration |
| [Run RADAR (AD Workflow)](/docs/manual/radar_docs/radar-run-ad.md) | Detector and monitor creation workflow via `run-radar.sh` |
| [Detection Rules](/docs/manual/radar_docs/radar-rules.md) | Wazuh rule definitions for each scenario |
| [Scenarios overview and configuration](/radar/scenarios/README.md) | Detailed documentation of the scenarios folder artifacts |
| [Webhook](/radar/webhook/README.md) | Webhook service deployment and configuration |
| [Web Interface User Manual](/docs/manual/radar_docs/radar-gui-user-manual.md) | User manual of RADAR Web Interface |
| [Operations](/docs/manual/radar_docs/radar-operations.md) | Command-line reference, health checks, and routine administration |
| [Tuning](/docs/manual/radar_docs/radar-tuning.md) | Risk weights, tier thresholds, mitigations, and detector sensitivity |
| [Troubleshooting](/docs/manual/radar_docs/radar-troubleshooting.md) | Diagnosis and resolution of common failures |

## RADAR scenarios

Currently, four production scenarios are implemented, each integrating a decoder, rule, and active response in a deployable solution. **Log Volume Growth** additionally has an OpenSearch detector, monitor, webhook and dataset ingestor (`wazuh_ingest.py`), since it is the only scenario driven by anomaly detection rather than signatures alone.

### Default rules

The **Default** rules provides a low-friction framework for rapid threat detection without prerequisite data preparation. Unlike scenario-specific detections (which may require custom decoders, manager-side enrichment integrations, or index schema modifications), Default rules operate on existing Wazuh data structures and standard event formats. This enables:

- Deploy immediately on any standard Wazuh installation with Sysmon
- Baseline alerts feed directly into DECIPHER for IOC scoring and threat intelligence enrichment
- Seamless integration with Flowintel for incident correlation and response automation

Current rule set focuses on command shell execution detection (PowerShell, CMD.exe, batch scripts), but the framework supports any detection rules operating on standard event formats. The Default scenario demonstrates how signature-based detection integrates with RADAR's risk engine and CTI analysis capabilities.

| Scenario | Status | Data Source | Detection Type | Documentation |
|----------|--------|-------------|----------------|---------------|
| **Default** | ✅ Production | Real Wazuh | Signature | [Guide](/docs/manual/radar_docs/radar-rules.md#0-default-threat-detection) |
| **GeoIP Detection** | ✅ Production | Real Wazuh (SSH + Apache/Nginx) | Signature | [Guide](/docs/manual/radar_docs/radar-scenarios/geoip_detection_explained.md) |
| **Log Volume Growth** | ✅ Production | Real Wazuh | RRCF-based | [Guide](/docs/manual/radar_docs/radar-scenarios/log_volume_explained.md) |
| **Suspicious Login** | ✅ Production | Real Wazuh | Signature[^1] | [Guide](/docs/manual/radar_docs/radar-scenarios/suspicious_login_explained.md#signature-based-approach) |
| **Web Scanning Detection** | ✅ Production | Real Wazuh | Signature | [Guide](/docs/manual/radar_docs/radar-scenarios/scanning_detection_explained.md) |

> **CTI enrichment and incident case creation via DECIPHER** run for every production scenario, not only Suspicious Login: `radar_ar.py` queries DECIPHER's analyze endpoint on every alert regardless of which scenario matched, and creates a FlowIntel incident case whenever DECIPHER is reachable and the computed tier is 1 or above. See the [**DECIPHER deployment guide**](https://github.com/AbstractionsLab/satrap-dl/tree/main/decipher) for setup instructions.

---

## RADAR outcome

Here we provide a screenshot of a successful run of the Suspicious Login detection RADAR scenario:

![Wazuh Dashboard Discover RADAR geo IP detection](/docs/manual/_figures/RADAR-wazuh-dashboard.png "Wazuh Dashboard Discover RADAR Geo IP detection")

The active response sends an email to a designated recipient at every tier from Tier 1 upward, and, depending on the tier and the scenario's `ar.yaml` configuration, can also execute an automated mitigation — blocking the source IP (`firewall-drop`), locking the implicated Linux account (`lock_user_linux.sh`), or terminating the offending service (`terminate_service.sh`). Automated mitigation execution is governed per scenario by `allow_mitigation`.

![](/docs/manual/_figures/RADAR-email-scanning-detection.png)

Additionally, the active response component creates a case in FlowIntel on high risk alerts via the DECIPHER service.

To compute the threat context for that response, RADAR calls DECIPHER's dedicated analysis endpoint — a distinct API endpoint separate from ordinary RADAR flows. It passes an information bundle assembled from the detection of the given scenario: alert metadata, source IP, relevant event fields, and scenario-specific context. DECIPHER processes this bundle and returns a CTI score together with enriched threat intelligence results to RADAR, which feeds the score directly into its risk computation. As part of scoring, DECIPHER performs a series of indicator lookups in MISP via `pymisp` — for example, checking whether a source IP appears as a known malicious attribute on any MISP event — and factors those findings into the final CTI score. The screenshot below shows an example MISP event consulted during this process, recording a malicious `ip-src` indicator that DECIPHER would match against the bundle supplied by RADAR:

![RADAR DECIPHER MISP lookup — ip-src event in MISP](/docs/manual/_figures/RADAR-DECIPHER-MISP-lookup.png "MISP event consulted by DECIPHER during CTI scoring for a RADAR scenario")

![FlowIntel case created by RADAR via DECIPHER](/docs/manual/_figures/RADAR-FlowIntel-case.png)

The RADAR GUI provides a browser-based control panel for the full operational lifecycle across three pages - **RADAR Scenarios** (risk weights, tiers, mitigations), **Connectors** (external service credentials), and **Deployment** (scenario deployment, agent onboarding, the anomaly detector, and health checks).

![RADAR GUI - RADAR Scenarios page](/docs/website/assets/RADAR_GUI_RADAR_Scenarios.png "RADAR GUI RADAR Scenarios page showing risk weight configuration and tier thresholds")

![RADAR GUI - Deployment page](/docs/website/assets/RADAR_GUI_Deploy.png "RADAR GUI Deployment page: scenario selection and live output streaming")

![RADAR Demonstration](/docs/manual/_figures/RADAR_GUI.gif)

---

## RADAR automated test framework

The RADAR subsystem comes with a dedicated test framework aimed at automating the experimentation and validation chain of activities.
More precisely, we provide a pipeline automating the ingestion of datasets, preprocessing,
training and ML model baseline establishment, attack simulation, data collection, followed by post-processing and
computation of statistical measures, which are then reported to the user. Attack simulation runs as standalone
Python scripts (`radar-test-framework/simulate/scenarios/<scenario>.py`) executed directly on the target agent
endpoint, writing agent-realistic attack artifacts so the full Wazuh decoder/rule/active-response pipeline is
exercised the same way it would be in production.

See [RADAR test framework](/radar/radar-test-framework/README.md) for more details.

---

## Best practices for robust AD with resilience to adversarial interference

Adversarial machine learning poses significant challenges to anomaly detection systems. Attackers may attempt to poison training data, evade detection, or manipulate models. We recommend a hybrid approach combining signature-based detection, multivariate AD (SONAR/ADBox), and classical streaming AD (RRCF) for defense in depth.

**Key defensive strategies include:**
- Clean baseline initialization and concept drift detection
- Multi-layer logging and detection across network, host, and application layers
- Synthetic anomaly injection for model hardening
- Human-in-the-loop oversight and transparent model reasoning
- System hardening to protect logs, models, and training pipelines

For comprehensive guidance on implementing these defensive mechanisms, see our dedicated [adversarial ML best practices guide](/docs/manual/radar_docs/adversarial-ml-guidance.md).
