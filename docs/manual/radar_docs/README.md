# RADAR documentation

Comprehensive documentation for RADAR (Risk-aware Anomaly Detection-based Automated Response) - the automated response system for IDPS-ESCAPE.

> ⚠️ **All commands should be run from project root** (`/home/alab/soar`)

> **For operational quickstart**: See [radar/README.md](../../../radar/README.md) for scenarios overview, deployment outcomes, and visual examples.

---

## Documentation overview

| Document | Purpose | Audience | Est. Time |
|----------|---------|----------|-----------|
| [Getting started](./radar-getting-started.md) | Prerequisites, setup, deployment modes | Everyone | 30 min |
| [Architecture](./radar-architecture.md) | System design, principles, components | Developers & Architects | 45 min |
| [Ansible playbook](./radar-manager-ansible-playbook.md) | Wazuh manager automation pipeline | DevOps & SRE | 60 min |
| [Run RADAR workflow](./radar-run-ad.md) | Detector and monitor creation | Operators & DevOps | 20 min |
| [Active response](./radar-active-response.md) | Response logic, risk engine, tiering | Developers | 40 min |
| [Detection rules](./radar-rules.md) | Wazuh rule definitions | Security Analysts | 25 min |
| [Adversarial ML guidance](./adversarial-ml-guidance.md) | Robustness best practices | Security Teams | 30 min |
| [Risk engine math](./radar-risk-math.md) | Mathematical specification | Researchers | 25 min |
| [Risk engine roadmap](./radar-risk-engine-roadmap.md) | Future CTI integration | Developers | 15 min |
| [Scenario guides](./radar-scenarios/) | Per-scenario deep dives | Operators | 15 min each |

---

## Getting started

### New users (15 minutes)

**Scenario**: Deploy GeoIP detection with automated email alerts

```bash
# From project root (/home/alab/soar)
cd radar

# Deploy Wazuh + RADAR GeoIP scenario (use sudo only if manager local)
sudo ./build-radar.sh geoip_detection --manager local --agent local

# Verify deployment
docker ps | grep wazuh

# Set up detector and monitor
./run-radar.sh geoip_detection
```

**Next steps**: [Getting started guide](./radar-getting-started.md) → [GeoIP scenario](./radar-scenarios/geoip_detection_explained.md)

---

### Deployment modes

RADAR supports flexible deployment topologies combining local and remote Wazuh managers and agents. For detailed information about each deployment mode (local/remote configurations), use cases, and configuration steps, see [Getting started - Deployment modes](./radar-getting-started.md#modes-of-deployment).

---

### Choose your scenario

**Production-ready scenarios:**

| Scenario | Detection Type | Command | Guide |
|----------|----------------|---------|-------|
| **GeoIP Detection** | Signature | `build-radar.sh geoip_detection` | [Guide](./radar-scenarios/geoip_detection_explained.md) |
| **Log Volume** | RRCF-based | `build-radar.sh log_volume` | [Guide](./radar-scenarios/log_volume_explained.md) |
| **Suspicious Login** (Signature) | Signature | `build-radar.sh suspicious_login` | [Guide](./radar-scenarios/suspicious_login_explained.md#signature-based-approach) |

**Demo scenarios** (require adaptation for your environment):
- [Insider Threat](../../../radar/archives/insider_threat/README.md) 🧪 Synthetic data, RRCF-based
- [Suspicious Login (Behavior)](./radar-scenarios/suspicious_login_explained.md#behavior-based-approach) 🧪 RRCF-based
- [DDoS Detection](../../../radar/archives/ddos_detection/README.md) 🧪 Synthetic data, RRCF-based
- [C2 Malware Communication](../../../radar/archives/malware_communication/README.md) 🧪 Synthetic data, RRCF-based

> ⚠️ **Demo scenarios**: Require adaptation of indices/aliases, field mappings, time/category fields, decoders/ingest pipelines, TLS/hostnames, and detector/monitor parameters.

---

## Quick reference by task

| I want to... | Go to | Section |
|--------------|-------|---------|
| Deploy my first scenario | [Getting started](./radar-getting-started.md) | Prerequisites |
| Understand system architecture | [Architecture](./radar-architecture.md) | System components |
| Configure Ansible automation | [Ansible playbook](./radar-manager-ansible-playbook.md) | Overview |
| Create custom detector | [Run RADAR](./radar-run-ad.md) | Detector setup |
| Write new detection rule | [Detection rules](./radar-rules.md) | Rule scenarios |
| Customize active response | [Active response](./radar-active-response.md) | Scenario registry |
| Configure webhook service | [Webhook](../../../radar/webhook/README.md) | Configuration |
| Run automated tests | [Test framework](../../../radar/radar-test-framework/README.md) | Introduction |
| Harden against adversarial ML | [Adversarial ML](./adversarial-ml-guidance.md) | Baseline initialization |
| Integrate with SONAR | [SONAR data shipping](../sonar_docs/data-shipping-guide.md) | RADAR integration |
| Understand risk scoring | [Risk engine math](./radar-risk-math.md) | Risk calculation |
| Manage scenario artifacts | [Scenarios folder](../../../radar/scenarios/README.md) | Folder structure |

---

## Architecture overview

### System components

```
┌─────────────────────────────────────────────────────────┐
│                    RADAR System                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Wazuh Agents  →  Wazuh Manager  →  OpenSearch AD       │
│       ↓                ↓                  ↓             │
│  Log Data      →  Decoders/Rules  →  Detectors          │
│                       ↓                  ↓              │
│                  Active Response  ←  Monitors           │
│                       ↓                                 │
│                  Email / CTI / SOAR                     │
└─────────────────────────────────────────────────────────┘
```

**Key technologies:**
- **Wazuh**: Security monitoring and SIEM platform
- **OpenSearch RCF**: Random Cut Forest anomaly detection algorithm
- **Ansible**: Infrastructure-as-Code deployment automation
- **Docker**: Containerized components and services
- **Flask**: Webhook service for alert routing

**Details**: [Architecture documentation](./radar-architecture.md)

---

## Key concepts

### Detection approaches

- **Signature-based**: Rules match known patterns (e.g., GeoIP whitelist violations, failed login thresholds)
- **Behavior-based**: ML models detect statistical deviations (e.g., unusual log volume spikes, anomalous access patterns)
- **Hybrid**: Combine both for defense in depth and reduced false positives

**See**: [Architecture - Design principles](./radar-architecture.md#design-principles)

### Automation pipeline

```
build-radar.sh  →  Ansible playbook  →  Wazuh deployed
      ↓
run-radar.sh   →  Data ingestion  →  Detector created  →  Monitor configured
      ↓
Anomaly detected  →  Webhook triggered  →  Active Response  →  Email/SOAR/CTI
```

**See**: [Run RADAR workflow](./radar-run-ad.md) | [Ansible playbook](./radar-manager-ansible-playbook.md)

### Risk engine

RADAR calculates normalized risk scores (0.0 to 1.0) combining:
- **RRCF anomaly grade + confidence** (behavior-based scenarios)
- **Signature-based likelihood × impact** (rule-based scenarios)
- **CTI enrichment flags** (optional SATRAP integration)

**See**: [Risk engine mathematical specification](./radar-risk-math.md)

---

## Scenario deep dives

Comprehensive guides for each production scenario:

- **[GeoIP Detection](./radar-scenarios/geoip_detection_explained.md)**: Detect logins from non-whitelisted countries using signature-based rules
- **[Log Volume Monitoring](./radar-scenarios/log_volume_explained.md)**: Monitor for abnormal log generation spikes using RRCF algorithm
- **[Suspicious Login](./radar-scenarios/suspicious_login_explained.md)**: Identify brute force attacks and impossible travel patterns (signature + behavior)

**Each guide includes:**
- Objectives and security use cases
- Detection methodology (signature vs RRCF)
- Active response behavior and risk tiering
- Manual setup instructions (agent + manager)
- OpenSearch detector configuration
- Expected outcomes and validation

---

## Integration

### SONAR → RADAR data flow

SONAR multivariate anomalies can trigger RADAR automated responses via Wazuh data streams:

1. **SONAR detects anomaly** → Ships to `wazuh-anomalies-mvad` data stream  
2. **RADAR monitors index** → Matches high-confidence events based on rules
3. **Active response executes** → Email/CTI/SOAR actions based on risk tier

**Configuration**: [SONAR data shipping guide](../sonar_docs/data-shipping-guide.md#integration-with-radar)

### External integrations

- **Flowintel** (case management): Automatic case creation for high-risk alerts - [Active response](./radar-active-response.md#action-execution)
- **SATRAP CTI** (threat intelligence): IP/domain enrichment via CTI feeds - [Risk engine roadmap](./radar-risk-engine-roadmap.md)
- **Keycloak** (identity management): User authentication context - [Suspicious login scenario](./radar-scenarios/suspicious_login_explained.md)

---

## Troubleshooting

### Common issues

| Problem | Solution | Reference |
|---------|----------|-----------|
| Containers not starting | Check Docker resources (memory/CPU) | [Getting started - Prerequisites](./radar-getting-started.md#prerequisites) |
| Detector not creating | Verify OpenSearch AD plugin installed | [Getting started - Prerequisites](./radar-getting-started.md#prerequisites) |
| Webhook not receiving alerts | Check URL/port in monitor configuration | [Webhook README](../../../radar/webhook/README.md#configuration) |
| Active response not firing | Verify rule trigger conditions and severity | [Detection rules](./radar-rules.md) |
| Email not sending | Check SMTP environment variables | [Active response](./radar-active-response.md#environment-variables) |
| Ansible playbook fails | Review prerequisites and SSH keys | [Ansible playbook - Prerequisites](./radar-manager-ansible-playbook.md#prerequisites) |

### Debug commands

```bash
# From project root (/home/alab/soar)

# Check RADAR containers
docker ps | grep wazuh

# View Wazuh manager logs
docker logs wazuh.manager

# Check webhook service logs
docker logs webhook-server

# Verify OpenSearch indices
curl -k -u admin:admin https://localhost:9200/_cat/indices?v

# Check OpenSearch AD detectors
curl -k -u admin:admin https://localhost:9200/_plugins/_anomaly_detection/detectors

# View active response logs
docker exec wazuh.manager tail -f /var/ossec/logs/active-responses.log
```

---

## Testing

### Test framework

RADAR includes an automated test framework supporting simulation of production scenarios:

- **3 production scenarios**: Suspicious login, GeoIP detection, Log volume growth
- **Simulation phase**: Agent-realistic attack artifact generation via `simulate-radar.sh`
- **Ansible automation**: Infrastructure-as-code test execution

The following scenarios are **archived** (in `radar/archives/`) and require adaptation before use: Insider threat, DDoS detection, Malware C2, and SSO-based suspicious login.

> **Note**: The evaluate phase (TP/FP metrics, precision/recall) is not yet implemented and is planned for a future release.

**Complete guide**: [RADAR test framework README](../../../radar/radar-test-framework/README.md)

**Quick start**:
```bash
# From project root
cd radar/radar-test-framework
ansible-playbook -i inventory.yaml test_scenario.yaml
```

---

## Command reference

### build-radar.sh

Deploy RADAR scenario with Wazuh infrastructure.

**Syntax**:
```bash
./build-radar.sh <scenario> --manager <local|remote> --agent <local|remote> [OPTIONS]
```

**Examples**:
```bash
# Local development deployment
./build-radar.sh geoip_detection --manager local --agent local

# Production with remote agents
./build-radar.sh log_volume --manager local --agent remote

# Use existing manager
./build-radar.sh suspicious_login --manager local --agent local --manager_exists true
```

**Options**:
- `--manager_exists <true|false>`: Skip manager deployment if already exists (default: false)

**Details**: [Getting started](./radar-getting-started.md#deployment)

---

### run-radar.sh

Create OpenSearch detector and monitor for scenario.

**Syntax**:
```bash
./run-radar.sh <scenario>
```

**Examples**:
```bash
# Create log volume detector + monitor
./run-radar.sh log_volume

# Create GeoIP detector + monitor
./run-radar.sh geoip_detection
```

**Outputs**:
- `DET_ID=<detector-id>`: OpenSearch detector identifier
- `MON_ID=<monitor-id>`: OpenSearch monitor identifier

**Details**: [Run RADAR workflow](./radar-run-ad.md)

---

## Glossary

| Term | Definition |
|------|------------|
| **RADAR** | Risk-aware Anomaly Detection-based Automated Response |
| **RRCF** | Robust Random Cut Forest - streaming anomaly detection algorithm |
| **RCF** | Random Cut Forest - AWS/Amazon anomaly detection algorithm base |
| **SOAR** | Security Orchestration, Automation, and Response |
| **AD** | Anomaly Detection |
| **CTI** | Cyber Threat Intelligence |
| **AR** | Active Response |
| **UEBA** | User and Entity Behavior Analytics |
| **IaC** | Infrastructure-as-Code (Ansible-based deployment) |
| **SIEM** | Security Information and Event Management |

---

## FAQ

**Q: Can I deploy RADAR without OpenSearch AD plugin?**  
A: Signature-based scenarios (GeoIP, Suspicious Login signature mode) work without it. RRCF-based scenarios (Log Volume, behavior-based detection) require the OpenSearch AD plugin.

**Q: Which scenarios are production-ready?**  
A: GeoIP Detection, Log Volume Monitoring, and Suspicious Login (signature mode) are production-ready. Demo scenarios in `/radar/archives/` require adaptation to your environment.

**Q: How do I integrate RADAR with SONAR?**  
A: Configure SONAR data shipping to send anomalies to Wazuh data streams. RADAR monitors these streams and triggers automated responses. See [SONAR data shipping guide](../sonar_docs/data-shipping-guide.md#integration-with-radar).

**Q: What Wazuh versions are supported?**  
A: Tested with Wazuh v4.14.1. See [Getting started - Prerequisites](./radar-getting-started.md#prerequisites) for compatibility details.

**Q: Can I run RADAR in Kubernetes?**  
A: Not currently supported. RADAR uses Docker Compose for deployment.

**Q: How do I customize active responses?**  
A: Edit scenario-specific Python scripts in `radar/scenarios/<scenario>/active_responses/`. See [Active response - Scenario registry](./radar-active-response.md#scenario-registry).

---

## Contributing

### Adding a new scenario

1. **Create folder structure** in `radar/scenarios/`:
   ```
   radar/scenarios/my_scenario/
   ├── active_responses/
   ├── decoders/
   ├── rules/
   ├── ingest_scripts/
   └── README.md
   ```

2. **Follow naming conventions**: 
   - Decoders: `radar-<scenario>-decoder.xml`
   - Rules: `radar-<scenario>-rules.xml`
   - Active response: `radar_<scenario>_ar.py`

3. **Add documentation**:
   - Create `docs/manual/radar_docs/radar-scenarios/<scenario>_explained.md`
   - Update `radar/scenarios/README.md`

4. **Register in active response**:
   - Add scenario to registry in `radar_ar.py`
   - Define risk calculation logic

**See**: [Ansible playbook - Extending](./radar-manager-ansible-playbook.md#extending-the-playbook) | [Scenarios folder](../../../radar/scenarios/README.md)

---

## Version compatibility

| RADAR Version | Wazuh | OpenSearch | Docker | Ansible |
|---------------|-------|------------|--------|---------|
| v0.7.x | 4.14.1 | 2.x | 20.10+ | 2.15+ |
| v0.6.x | 4.7.x | 1.3+ | 20.10+ | 2.9+ |

---

## Additional resources

### External documentation
- [Wazuh OpenSearch AD integration blog](https://wazuh.com/blog/enhancing-it-security-with-anomaly-detection/)
- [AWS RCF algorithm paper](https://www.amazon.science/publications/robust-random-cut-forest-based-anomaly-detection-on-streams)
- [OpenSearch anomaly detection](https://opensearch.org/anomaly-detection/)
- [OpenSearch false positive reduction](https://opensearch.org/blog/reducing-false-positives-through-algorithmic-improvements/)

### Project documentation
- [Project root README](../../../README.md)
- [SONAR documentation](../sonar_docs/README.md)
- [Deployment guides](../../../deployment/README.md)