# RADAR test framework

## **Introduction**

The increasing complexity and scale of modern cyber threats necessitate advanced, automated security solutions that not only detect anomalies but also respond in real time. In this context, the SOAR-RADAR framework (Security Orchestration, Automation, and Response – Risk-Aware Detection-based Active Response) was developed as a modular and extensible testbed for simulating and evaluating anomaly detection capabilities in Security Information and Event Management (SIEM) systems.

This document presents the design and implementation of the **RADAR Test Framework**, a structured and automated evaluation environment built around Wazuh’s anomaly detection capabilities. The framework is designed to support **multiple threat scenarios**, simulating adversarial behavior and measuring detection effectiveness in realistic settings. Specifically, the system evaluates the performance of Wazuh's anomaly detection in identifying:

- **Suspicious Logins**: Unauthorized or anomalous authentication attempts, including brute force and impossible travel patterns.
- **Non-whitelist GeoIP Detection**: Authentication events originating from countries outside a configured whitelist.
- **Log Volume Growth**: Anomalous spikes in filesystem log volume indicative of DDoS, malware outbreak, or data exfiltration.

The following scenarios are archived and not production-ready:

- **Insider Threats**: Malicious or negligent activities by authorized users.
- **Suspicious Logins**: Unauthorized or anomalous authentication attempts in Single Sign-On (SSO) environments.
- **Distributed Denial-of-Service (DDoS)** Attacks: Sudden surges in traffic aimed at exhausting system resources.
- **Malware Communication**: Covert communication with external command-and-control (C2) servers, typically through beaconing behavior.

Each of these scenarios is implemented as an isolated module following a consistent operational pipeline consisting of four key phases:

1. **Ingest**: Preparation and injection of scenario datasets into OpenSearch. This phase is handled by `run-radar.sh` and is outside the scope of RATF. See [Run RADAR documentation](/docs/manual/radar_docs/radar-run-ad.md).
2. **Setup**: Automated deployment of Wazuh configuration, detection pipelines, and active response artifacts. This phase is handled by `build-radar.sh` and is outside the scope of RATF. See [Getting Started documentation](/docs/manual/radar_docs/radar-getting-started.md).
3. **Simulate**: Execution of scenario-specific attack behaviours through agent-realistic artefact generation. This is the currently implemented phase within RATF. See [RADAR simulation](/radar/radar-test-framework/simulate/README.md)
4. **Evaluate**: Analysis of detection outputs against ground truth. This phase is not yet implemented in RATF and is planned for a future release.

The simulation component is orchestrated through `simulate-radar.sh`, which dispatches scenario scripts to local container agents or remote SSH endpoints.