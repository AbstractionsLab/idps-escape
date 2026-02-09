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

## RADAR scenarios

Currently, anomaly detection coupled with automated response is implemented for the RADAR scenarios listed below. Each scenario integrates a detector, monitor, webhook, decoder, rule, and active response in a deployable solution. They also come with a dataset ingestor (`wazuh_ingest.py`) aimed at populating the Wazuh indexer.

| Scenario | Status | Data Source | Detection Type | Documentation |
|----------|--------|-------------|----------------|---------------|
| **GeoIP Detection** | ✅ Production | Real Wazuh | Signature | [Guide](/docs/manual/radar_docs/radar-scenarios/geoip_detection_explained.md) |
| **Log Volume Monitoring** | ✅ Production | Real Wazuh | RRCF-based | [Guide](/docs/manual/radar_docs/radar-scenarios/log_volume_explained.md) |
| **Suspicious Login** (Signature) | ✅ Production | Real Wazuh | Signature | [Guide](/docs/manual/radar_docs/radar-scenarios/suspicious_login_explained.md#signature-based-approach) |
| **Insider Threat** | 🧪 Demo | Synthetic | RRCF-based | [README](/radar/archives/insider_threat/README.md) |
| **Suspicious Login** (Behavior) | 🧪 Demo | Synthetic | RRCF-based | [Guide](/docs/manual/radar_docs/radar-scenarios/suspicious_login_explained.md#behavior-based-approach) |
| **DDoS Detection** | 🧪 Demo | Synthetic | RRCF-based | [README](/radar/archives/ddos_detection/README.md) |
| **C2 Malware Communication** | 🧪 Demo | Synthetic | RRCF-based | [README](/radar/archives/malware_communication/README.md) |

> **Important:** Demo scenarios are not production-ready. Deployment requires adaptation of indices/aliases, field mappings, time/category fields, decoders/ingest pipelines, TLS/hostnames, and detector/monitor parameters to align with your organization's log schema and infrastructure.

---

## RADAR outcome

Here we provide a screenshot of a successful run of the Geo IP detection RADAR scenario:

![Wazuh Dashboard Discover RADAR geo IP detection](/docs/manual/_figures/RADAR-GeoIP-detection-Wazuh-Dashboard-result.png "Wazuh Dashboard Discover RADAR Geo IP detection")

The currently implemented active response sends an email to a designated recipient.
![](/docs/manual/_figures/RADAR-GeoIP-detection-Automated-Response-email.png)

Additionally, if FlowIntel is configured the active response creates a case in FlowIntel on high risk alerts.
![](/docs/manual/_figures/RADAR-GeoIP-detection-Automated-Response-flowintel.png)

---

## RADAR automated test framework

The RADAR subsystem comes with a dedicated test framework aimed at automating the experimentation and validation chain of activities.
More precisely, powered by Ansible, we provide a pipeline automating the ingestion of datasets, preprocessing, 
training and ML model baseline establishment, attack simulation, data collection, followed by post-processing and 
computation of statistical measures, which are then reported to the user.

See [RADAR test framework](/radar/radar-test-framework/README.md) for more details.

## Active response modules and SOAR playbooks for Wazuh

The active response modules stored in the respective RADAR scenario implementation folders, i.e., `radar/<RADAR-scenario>/active_responses`, provide 
automated responses and contextual enrichments based on anomalies. 
These reduce manual work for analysts via automation and also benefit from our [CTI integration](/integrations/README.md) support, e.g., [insider threat active responses](/radar/archives/insider_threat/active_responses/).


## Best practices for robust AD with resilience to adversarial interference

Adversarial machine learning poses significant challenges to anomaly detection systems. Attackers may attempt to poison training data, evade detection, or manipulate models. We recommend a hybrid approach combining signature-based detection, multivariate AD (SONAR/ADBox), and classical streaming AD (RRCF) for defense in depth.

**Key defensive strategies include:**
- Clean baseline initialization and concept drift detection
- Multi-layer logging and detection across network, host, and application layers
- Synthetic anomaly injection for model hardening
- Human-in-the-loop oversight and transparent model reasoning
- System hardening to protect logs, models, and training pipelines

For comprehensive guidance on implementing these defensive mechanisms, see our dedicated [adversarial ML best practices guide](/docs/manual/radar_docs/adversarial-ml-guidance.md).
