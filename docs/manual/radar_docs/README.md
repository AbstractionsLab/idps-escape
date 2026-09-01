# RADAR — user documentation

RADAR (Risk-aware Anomaly Detection-based Automated Response) is the automated
detection and response subsystem of the IDPS-ESCAPE platform. It correlates
evidence from three independent detection sources — Wazuh signature rules,
OpenSearch Anomaly Detection, and Cyber Threat Intelligence supplied by DECIPHER
— into a single normalised risk score for each alert, and uses that score to
select a proportionate response from a configurable four-tier escalation model.

The subsystem is deployed on top of a Wazuh manager, indexer and dashboard, and
monitors endpoints running the Wazuh agent. Detection use cases are packaged as
**scenarios**: self-contained units comprising decoders, rules, agent
configuration, active-response bindings and risk parameters, which can be
deployed independently and coexist on a single manager.

This documentation set is intended for the engineers and analysts who deploy,
operate and tune RADAR. It describes the system as it is used; the architecture, 
module design and requirements traceability are maintained separately under `docs/specs/`.

---

## Start here

| Document | Purpose |
|----------|---------|
| [Getting started](./radar-getting-started.md) | First-time installation, from prerequisites to a verified deployment |
| [GUI user manual](./radar-gui-user-manual.md) | Complete reference for the RADAR web interface |
| [Operations](./radar-operations.md) | Command-line reference, health checks, and routine administration |
| [Tuning](./radar-tuning.md) | Risk weights, tier thresholds, mitigations, and detector sensitivity |
| [Rules reference](./radar-rules.md) | Every rule each scenario ships: rule IDs, conditions, MITRE mappings |
| [Anomaly detector reference](./radar-run-ad.md) | What `run-radar.sh`'s three stages do and how to configure them |
| [Troubleshooting](./radar-troubleshooting.md) | Diagnosis and resolution of common failures |

---

## Scenarios

A **scenario** is a self-contained detection use case: its own decoders, rules,
active responses, agent configuration, and risk settings.

| Scenario | Type | Detects | Needs |
|----------|------|---------|-------|
| [Suspicious login](./radar-scenarios/suspicious_login_explained.md) | Hybrid | Failed-login bursts, impossible travel, ASN novelty, per-user behavioural outliers | MaxMind key |
| [GeoIP detection](./radar-scenarios/geoip_detection_explained.md) | Signature | SSH logins and web requests from non-approved countries | MaxMind key, country whitelist |
| [Log volume growth](./radar-scenarios/log_volume_explained.md) | Anomaly (ML) | Unusual spikes in log generation, per endpoint | Agent bootstrapped with the `log_volume` group |
| [Web scanning](./radar-scenarios/scanning_detection_explained.md) | Signature | Scanner tool signatures, failed-request bursts, HTTP method abuse | Suricata shipping `eve.json` |

Alongside these, a **default (baseline)** scenario is always active. It carries
fleet-wide PowerShell and command-shell detection, and every other scenario
inherits its risk settings as defaults.

`suspicious_login` and `geoip_detection` are **shared scenarios**: they use a
common `radar_shared` agent group for `auth.log` shipping and manager-side
enrichment, so running both costs nothing extra on the endpoint.

---

## Terminology

| Term | Meaning |
|------|---------|
| **Scenario** | A detection use case with its own rules, response, and risk settings |
| **Bound** | The scenario has an entry in `ar.yaml` and appears on the RADAR Scenarios page |
| **Deployed** | Its artifacts are currently applied to the manager |
| **Shared scenario** | Uses the common `radar_shared` agent group |
| **Tier (T0–T3)** | The response band a risk score falls into |
| **Mitigation** | An executable action: `firewall-drop`, `lock_user_linux`, `terminate_service` |
| **Connector** | An external service RADAR talks to: OpenSearch, Wazuh API, Dashboards, SMTP, DECIPHER, MaxMind, the webhook |
| **Enrollment window** | The time-limited period during which port 1515 accepts new agent enrollments |

---

## Version compatibility

| Component | Version |
|-----------|---------|
| Wazuh manager and agent | 4.14.1 |
| Docker Engine | 20.10+ |
| OpenSearch AD plugin | Installed automatically |

---

## Related documentation

| Location | Contents |
|----------|----------|
| `docs/specs/` | Traceable technical specifications managed with Doorstop: mission and system requirements, high- and low-level architecture, software design, test cases and test reports (MRS → SRS → HARC/LARC → SWD → TST → TRP) |