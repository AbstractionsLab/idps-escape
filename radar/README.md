# RADAR: Risk-aware Anomaly Detection-based Automated Response

RADAR is a key part of the SOAR mission of IDPS-ESCAPE, providing anomaly detection scenarios with automated responses. This folder stores all design, development, and implementation artifacts for deploying AD scenarios with dedicated active responses (AR).

Our security orchestration approach provides Risk-aware AD-based AR (**RADAR**) modules aimed at enhancing SOC operations. RADAR modules integrate with the [OpenSearch AD plugin](https://wazuh.com/blog/enhancing-it-security-with-anomaly-detection/) using Amazon's [Random Cut Forest (RCF) algorithm](https://www.amazon.science/publications/robust-random-cut-forest-based-anomaly-detection-on-streams). We recommend a hybrid approach combining SONAR/ADBox with RRCF-based RADAR for [resilience to adversarial interference](#best-practices-for-robust-ad-with-resilience-to-adversarial-interference).

We leverage [OpenSearch's latest advances](https://opensearch.org/anomaly-detection/), including [false positive reductions](https://opensearch.org/blog/reducing-false-positives-through-algorithmic-improvements/) and support for [high-cardinality anomaly detection](https://aws.amazon.com/blogs/big-data/detect-anomalies-on-one-million-unique-entities-with-amazon-opensearch-service/) via slicing, enabling per-user or per-device baseline detectors.

> 📚 **For comprehensive documentation**: See [docs/manual/radar_docs/](../docs/manual/radar_docs/) for learning paths, troubleshooting guides, integration documentation, and architecture deep dives.

## Table of contents

| Document | Description |
|----------|-------------|
| [RADAR Architecture](/docs/manual/radar_docs/radar-architecture.md) | System architecture, design principles, component diagrams, data flows |
| [Getting Started](/docs/manual/radar_docs/radar-getting-started.md) | Prerequisites, setup instructions, deployment modes, configuration |
| [Ansible Playbook](/docs/manual/radar_docs/radar-manager-ansible-playbook.md) | Detailed breakdown of the Wazuh manager automation pipeline |
| [Run RADAR (AD Workflow)](/docs/manual/radar_docs/radar-run-ad.md) | Detector and monitor creation workflow via `run-radar.sh` |
| [Detection Rules](/docs/manual/radar_docs/radar-rules.md) | Wazuh rule definitions for each scenario |
| [Scenarios overview and configuration](/radar/scenarios/README.md) | Detailed documentation of the scenarios folder artifacts |
| [Webhook](/radar/webhook/README.md) | Webhook service deployment and configuration |
| [Active Response](/docs/manual/radar_docs/radar-active-response.md) | Active Response logic flow |
| [Health check](/docs/manual/radar_docs/radar-health-check.md) | Detailed documentation of RADAR health check |

## RADAR scenarios

Currently, anomaly detection coupled with automated response is implemented for the RADAR scenarios listed below. Each scenario integrates a detector, monitor, webhook, decoder, rule, and active response in a deployable solution. They also come with a dataset ingestor (`wazuh_ingest.py`) aimed at populating the Wazuh indexer.

| Scenario | Status | Data Source | Detection Type | Documentation |
|----------|--------|-------------|----------------|---------------|
| **GeoIP Detection** | ✅ Production | Real Wazuh (SSH + Apache/Nginx) | Signature | [Guide](/docs/manual/radar_docs/radar-scenarios/geoip_detection_explained.md) |
| **Log Volume Monitoring** | ✅ Production | Real Wazuh | RRCF-based | [Guide](/docs/manual/radar_docs/radar-scenarios/log_volume_explained.md) |
| **Suspicious Login** (Signature) | ✅ Production | Real Wazuh | Signature | [Guide](/docs/manual/radar_docs/radar-scenarios/suspicious_login_explained.md#signature-based-approach) |
| **Insider Threat** | 🧪 Demo | Synthetic | RRCF-based | [README](/radar/archives/insider_threat/README.md) |
| **Suspicious Login** (Behavior) | 🧪 Demo | Synthetic | RRCF-based | [Guide](/docs/manual/radar_docs/radar-scenarios/suspicious_login_explained.md#behavior-based-approach) |
| **DDoS Detection** | 🧪 Demo | Synthetic | RRCF-based | [README](/radar/archives/ddos_detection/README.md) |
| **C2 Malware Communication** | 🧪 Demo | Synthetic | RRCF-based | [README](/radar/archives/malware_communication/README.md) |

> **Important:** Demo scenarios are not production-ready. Deployment requires adaptation of indices/aliases, field mappings, time/category fields, decoders/ingest pipelines, TLS/hostnames, and detector/monitor parameters to align with your organization's log schema and infrastructure.

> **CTI enrichment and incident case creation via DECIPHER** are currently supported for the **Suspicious Login** scenario. When DECIPHER is reachable, RADAR queries the DECIPHER analyze endpoint to obtain a CTI score used in risk computation, and creates a FlowIntel incident case for all Tier 1 and above responses. See the [**DECIPHER deployment guide**](https://github.com/AbstractionsLab/satrap-dl/tree/main/decipher) for setup instructions.

---

## RADAR outcome

Here we provide a screenshot of a successful run of the Suspicious Login detection RADAR scenario:

![Wazuh Dashboard Discover RADAR geo IP detection](/docs/manual/_figures/RADAR-v0.8-wazuh-dashboard.png "Wazuh Dashboard Discover RADAR Geo IP detection")

The currently implemented active response sends an email to a designated recipient.
![](/docs/manual/_figures/RADAR-v0.8-email-suspicious-login.png)

Additionally, the active response component creates a case in FlowIntel on high risk alerts via the DECIPHER service.

To compute the threat context for that response, RADAR calls DECIPHER's dedicated analysis endpoint — a distinct API endpoint separate from ordinary RADAR flows. It passes an information bundle assembled from the detection of the given scenario: alert metadata, source IP, relevant event fields, and scenario-specific context. DECIPHER processes this bundle and returns a CTI score together with enriched threat intelligence results to RADAR, which feeds the score directly into its risk computation. As part of scoring, DECIPHER performs a series of indicator lookups in MISP via `pymisp` — for example, checking whether a source IP appears as a known malicious attribute on any MISP event — and factors those findings into the final CTI score. The screenshot below shows an example MISP event consulted during this process, recording a malicious `ip-src` indicator that DECIPHER would match against the bundle supplied by RADAR:

![RADAR DECIPHER MISP lookup — ip-src event in MISP](/docs/manual/_figures/RADAR-DECIPHER-MISP-lookup.png "MISP event consulted by DECIPHER during CTI scoring for a RADAR scenario")

![FlowIntel case created by RADAR via DECIPHER](/docs/manual/_figures/RADAR-v0.8-FlowIntel-case.png)

---

## RADAR automated test framework

The RADAR subsystem comes with a dedicated test framework aimed at automating the experimentation and validation chain of activities.
More precisely, powered by Ansible, we provide a pipeline automating the ingestion of datasets, preprocessing, 
training and ML model baseline establishment, attack simulation, data collection, followed by post-processing and 
computation of statistical measures, which are then reported to the user.

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
