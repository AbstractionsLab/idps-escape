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
| [Security assumptions and recommendations](#security-assumptions-and-recommendations) | Network exposure, firewall rules to enforce, and what RADAR assumes about its environment |

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
| **Default** | ✅ Production | Real Wazuh | Signature | [Guide](/docs/manual/radar_docs/radar-rules.md#default-rules) |
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

The RADAR GUI provides a browser-based control panel for the full operational lifecycle across four pages - **RADAR Scenarios** (risk weights, tiers, mitigations), **Infrastructure** (registering existing manager, indexer, and dashboard), **Connectors** (external service credentials), and **Deployment** (scenario deployment, agent onboarding, the anomaly detector, and health checks).

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

## Security assumptions and recommendations

RADAR responds to attackers who may already be inside the network, so it treats a compromised monitored endpoint as a realistic threat. RADAR ships safe defaults for everything it can control itself. Some countermeasures can only be applied at the network level: they are listed here so you can enforce them, should you choose to. Read the first subsection before exposing any RADAR port beyond the host it runs on.

### Assumptions

- **Single-operator admin host.** The web GUI, the deploy scripts and `.env` live on a host that only RADAR operators log in to. Operators already hold `sudo` there.
- **The browser reaches the GUI through an SSH tunnel.** Run the browser on your own workstation and forward the port with `ssh -L 5000:127.0.0.1:5000 <gui-host>`. Don't open the GUI in a browser running on the GUI host itself, even if it's a single-operator host. Browsers share cookies across ports on the same host, so a page served from any other local port can read the GUI's login and vault cookies, and any local user can open such a port. With the tunnel, the cookies stay in your workstation's browser.
- **Monitored endpoints can be hostile.** Any local user on an agent can write to its logs (for example with `logger`). RADAR therefore acts only on the triggering alert's own source IP, and it trusts anomaly-detection alerts only when they come from the webhook agent's `/var/log/ad_alerts.log`. Login enrichment is the exception: see the first item under [Known limitations](#known-limitations).
- **Enrollment secrets are sensitive.** Anyone holding a valid enrollment token can register an agent, including one that impersonates the webhook agent. Keep tokens short-lived, which is the default, and share them only with the endpoint being enrolled.
- **Docker bypasses host firewalls.** Ports that Docker publishes are not filtered by `ufw`/`firewalld` INPUT rules. Put restrictions for published ports in the `DOCKER-USER` iptables chain, as in the examples below.

### Firewall rules to enforce

| Port | Service | RADAR default | Recommendation |
|------|---------|---------------|----------------|
| 5000/tcp | Web GUI | Listens on `127.0.0.1` only, with a login token | Reach it only through an SSH tunnel from your workstation (`ssh -L 5000:127.0.0.1:5000 <gui-host>`), as described under [Assumptions](#assumptions). If you set `RADAR_GUI_HOST` to a network address, allow the port from admin hosts only, and list the name operators use in `RADAR_GUI_ALLOWED_HOSTS`. |
| 8080/tcp | AD alert webhook | Published on all interfaces; every request needs the shared secret | Allow 8080 from the indexer host only. On a single host the indexer reaches it over the compose network, so if `WEBHOOK_URL` uses `localhost` you can set `WEBHOOK_BIND_ADDRESS=127.0.0.1`. |
| 9200/tcp | Wazuh indexer | Published on all interfaces, with per-deployment credentials | Allow it from this host and the admin hosts only. RADAR's own clients reach it by this host's LAN address, including the `radar-cli` containers that `run-radar.sh` starts, so don't block this host's own address. `RADAR_MGMT_BIND_ADDRESS=127.0.0.1` is only safe if `OS_URL` and the infrastructure entries all use `localhost`. |
| 55000/tcp | Wazuh API | Published on all interfaces, with per-deployment credentials | Same as 9200: this host and the admin hosts only. |
| 443/tcp | Wazuh dashboard | Published on all interfaces | Allow from the admin subnet only. |
| 1514/tcp | Agent events | Published on all interfaces | Allow from agent subnets only. |
| 1515/tcp | Agent enrollment | Blocked in `DOCKER-USER` except during an enrollment window | Also allow it from agent subnets only. The window rule is not persistent: after a host reboot, port 1515 stays reachable until the next build or `sudo ./radar.sh enrollment close`, so add a persistent rule too. |
| 514/udp | Syslog | Published on all interfaces | Allow only from devices that really send syslog, or remove the mapping from `docker-compose.core.yml` if unused. |

Example with iptables, where `10.20.0.0/24` is the admin subnet and `10.30.0.0/16` the agent subnet. Adapt the addresses, and persist the rules with your distribution's tooling (for example `iptables-persistent`):

```bash
# Dashboard, indexer and Wazuh API: admin subnet only
# (192.168.0.1 stands for this host's own address, which RADAR itself uses)
sudo iptables -I DOCKER-USER -p tcp -m multiport --dports 443,9200,55000 ! -s 10.20.0.0/24 -j DROP
sudo iptables -I DOCKER-USER -p tcp -m multiport --dports 9200,55000 -s 192.168.0.1 -j RETURN
# Webhook: indexer host only (skip if the indexer runs in this compose project)
sudo iptables -I DOCKER-USER -p tcp --dport 8080 ! -s <indexer-host-ip> -j DROP
# Agent ports: agent subnet only
sudo iptables -I DOCKER-USER -p tcp -m multiport --dports 1514,1515 ! -s 10.30.0.0/16 -j DROP
sudo iptables -I DOCKER-USER -p udp --dport 514 -j DROP
```

### Settings to review for your site

- **`global.never_block`** in `scenarios/active_responses/ar.yaml`: add gateways, DNS servers, jump hosts and admin subnets. Loopback, link-local, multicast/broadcast and the manager's own address are always protected.
- **`trusted_proxies`** (`scanning_detection` in `ar.yaml`): list your reverse proxies or load balancers. `X-Forwarded-For` is ignored unless the connecting peer is one of them.
- **`terminable_services`** (`log_volume` in `ar.yaml`): anomaly alerts carry no source IP, and IPs found in logs are never used as targets. With this list empty, tier 3 notifies but takes no mitigation.
- **Credentials**: new deployments get unique passwords in `.env` on the first build. A deployment still on the stock wazuh-docker credentials should run `sudo ./radar.sh rotate-credentials`. Keep `.env`, `.radar-generated/` and `.radar-state/` private; RADAR writes them with owner-only permissions.

### Known limitations

**Enriched logins can be forged from any agent (`suspicious_login`, `geoip_detection`).** The manager copies SSH and web login lines from agents into its own `/var/ossec/logs/radar/enriched_*.log` and reads them back as its own events. Such alerts therefore come from the manager (agent 000), and the originating agent is lost. A local user on any agent can write a fake login line with `logger`. The impossible-travel or country rules then fire, and `firewall-drop` runs on the manager against the IP they wrote, which could be another agent or a gateway. The same user can also shape impossible-travel results for other hosts, because login history is kept per username only. Until this is fixed:

- Keep `allow_mitigation: false` for `suspicious_login` and `geoip_detection` in `scenarios/active_responses/ar.yaml`, so these scenarios notify without blocking.
- Or, if you enable mitigation, add the addresses of your agents and gateways to `global.never_block`.

These medium-severity items from the September 2026 security audit are still open:

- TLS certificate verification is off by default for the indexer, Wazuh API and DECIPHER clients. Turn it on with `OS_VERIFY_SSL`, `WAZUH_VERIFY_SSL` and `DECIPHER_VERIFY_SSL` pointing at `config/wazuh_indexer_ssl_certs/root-ca.pem`.
- Some secrets are still passed as process arguments or shown in deploy output.
- `lock_user_linux.sh` can lock more than the triggering user.
- Agent lookup by name takes the first fuzzy match.
- Indexer and dashboard hostname verification is off.
- Agents enrol without verifying the manager's certificate.

