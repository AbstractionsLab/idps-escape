# Getting started

RADAR orchestrates risk-aware anomaly detection (OpenSearch AD) and automated response across several components of the IDPS-ESCAPE architecture (see [HARC-003](https://abstractionslab.github.io/idps-escape/docs/traceability/HARC.html#HARC-003)). Setting up and running RADAR is enabled by two entrypoint scripts:

- `build-radar.sh` – prepares the environment (Wazuh core stack + agents + RADAR dependencies), runs Ansible pipelines for the chosen scenario, and builds various Docker containers.
- `run-radar.sh` – ingests a scenario dataset, ensures/starts an AD detector, and ensures a monitor with a webhook (prints `DET_ID`/`MON_ID`).

Below, we explain the pre-requisites and steps for bringing a scenario to life. At the end you will find a script for testing via a lightweight Docker runner.

For a very detailed breakdown of the Ansible playbook providing the automation pipeline for deploying and setting up the Wazuh manager, see our dedicated [page describing our approach to the automated manager deployment via an Ansible playbook](/docs/manual/radar_docs/radar-manager-ansible-playbook.md).

For a detailed description of the `run-radar.sh` workflow, refer to [the dedicated documentation page](/docs/manual/radar_docs/radar-run-ad.md).

---

## Modes of deployment

The design of RADAR allows for flexibility in terms of the endpoints placement, i.e., where the RADAR components and monitoring elements/agents can be deployed. The following deployment modes are supported:

| Wazuh manager | Wazuh agents |
|---------------|--------------|
| Local         | Local        |
| Local         | Remote       |
| Remote        | Remote       |

`local` and `remote` are used relative to where the runners and bootstrapping scripts are executed, e.g., in a GNU/Linux virtual machine (VM) denoted by `vm-1`, you run `build-radar.sh` and set `--manager local` and `--agent remote` with the `inventory.yaml` file specifying coordinates (IP, sudo user, SSH key file path, etc.) for other VMs in which agents are to be deployed, e.g. `edge-vm-2` and `edge-vm-3`. The Wazuh manager gets deployed on `vm-1` and the agents on `edge-vm-2` and `edge-vm-3`.

Alternatively, if the `--manager remote` is set and `build-radar.sh` is run from `vm-1`, the runner will look for the coordinates of some other VM in which the manager is to be deployed, e.g. `vm-2` defined in the `inventory.yaml` for the remote docker host.

The host node/endpoint is where the RADAR controller is located. The Wazuh manager and agents can be deployed either in the same node (local) or in a different one (remote).

The deployment of RADAR supports also:
- an existing Wazuh manager running (i.e. enhances Wazuh with RADAR by adding the required artifacts and setting up dependencies),
- existing agents as long as they do not run in containers.

See the [Usage](README.md#1-deploy-the-radar-infrastructure) section for details.

## Prerequisites

Verify your environment meets the requirements:

```bash
docker --version     # Should be 20.10+
ansible --version    # Should be 2.15+
```

- [Docker Engine](https://docs.docker.com/engine/install/) and [Docker Compose](https://docs.docker.com/compose/install) installed in endpoints where Wazuh agents/manager are deployed
- A controller host/node is available:
    - A Linux machine/VM (the Ansible control node) is available.
    - OS: recent GNU/Linux distribution, preferably an Ubuntu distribution (22.04+).
- Ideally, a second agent node (accessible via the controller node) is available: GNU/Linux distro e.g. Debian GNU/Linux 13 (trixie)
- **Ansible 2.15+** installed on the host node *(required by `build-radar.sh`)*
    - Installation reference:
        - if `pipx` is available, follow the instruction` in [Ansible Installation Documentation using pipx](https://docs.ansible.com/projects/ansible/latest/installation_guide/intro_installation.html#pipx-install).
        - otherwise, follow the [official instructions for Linux distributions](https://docs.ansible.com/projects/ansible/latest/installation_guide/installation_distros.html).
        - Minimum version: Ansible `2.15+`.
- Targeted Wazuh manager and agent versions: `4.14.1` (automatically handled by our deployment artifacts)
- **Optional**: If automatic CTI enrichment and incident case creation are desired, a DECIPHER instance must be running, with a connection between DECIPHER and the Wazuh Manager. To bring up the supporting services for DECIPHER, MISP and FlowIntel integration, follow the [**DECIPHER deployment guide**](https://github.com/AbstractionsLab/satrap-dl/tree/main/decipher). To enable the connection, configure the `DECIPHER_*` variables in `.env`.
- Environment values such as `OS_URL`, `OS_USER`, `OS_PASS`, `DASHBOARD_URL`, `DASHBOARD_USER`, `DASHBOARD_PASS` and SMTP credentials are available to the tester. The tester has network access (SSH) from the test controller node to controlled endpoints.
- If either the Wazuh agent (aka agent) or the Wazuh manager (aka manager) is chosen to be `remote`:
    - the remote agent/manager needs to have Docker and Docker Compose installed following the official documentations for [Docker](https://docs.docker.com/engine/install/) and [Docker Compose](https://docs.docker.com/compose/install).
    - an available user in remote agent or manager with sudo access, and tester needs to have SSH access to the user from test controller host.
- If the agents are to be deployed on `remote` nodes, the Wazuh agents must be installed in the monitored endpoints using [the official documentation](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html).
- The agent must be registered with the Wazuh manager following [the official documentation](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/enrollment-methods/via-agent-configuration/linux-endpoint.html).
- [OpenSearch AD plugin integrated into Wazuh](https://wazuh.com/blog/enhancing-it-security-with-anomaly-detection/): As of version 0.6, our RADAR deployment solution automatically installs the anomaly detection plugin from OpenSearch to enable AD in RADAR using the RRCF algorithm. See our dedicated [installation page](/deployment/opensearch-ad-plugin.md) for a Docker-based integration. The latest release (`v0.7`) has been tested with Wazuh `v4.14.1`.

## Setup

### 1. Setup connection and authorization variables

Create a **`.env`** file at `idps-escape/radar/` with endpoint URLs, credentials, and SSL flags. This file is read by `detector.py` and `monitor.py` inside the `radar-cli` container.

**Essential configuration (modify IPs and credentials):**

```bash
# OpenSearch Configuration
OS_URL=https://192.168.0.28:9200
OS_USER=admin
OS_PASS=SecretPassword
OS_VERIFY_SSL="/app/config/wazuh_indexer_ssl_certs/root-ca.pem"

# Wazuh Configuration
WAZUH_API_URL=https://192.168.0.28:55000
WAZUH_AUTH_USER=wazuh-wui
WAZUH_AUTH_PASS=MyS3cr37P450r.*-
WAZUH_MANAGER_ADDRESS=192.168.0.28

# Webhook
WEBHOOK_URL=http://192.168.0.28:8080/notify

# SMTP (for email alerts)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=user@example.com
SMTP_PASS=password
EMAIL_TO=recipient@example.com

# DEIPHER (for CTI enrichment and incident case creation)
DECIPHER_BASE_URL=http://localhost:8000  # Change accordingly
DECIPHER_VERIFY_SSL=VERIFY_SSL           # Change accordingly
DECIPHER_TIMEOUT_SEC=30                  # Change accordingly

```

See the [complete .env template](/radar/env.example) for all available configuration options including logging, DECIPHER, and advanced settings.

### 2. Configure users in remote endpoints

If either the manager or the agent are set to be remote:

(i) Edit the `inventory.yaml` file with the corresponding endpoint information.
For a remote manager, update:
```
wazuh_manager_ssh:
    hosts:
```
For remote agents, update: 
```
wazuh_agents_ssh:
    hosts:
```


(ii) Add valid endpoint login credentials into the encrypted Ansible vault:
```bash
ansible-vault create host_vars/**HOST_NAME**.yml
```
In this step: 
- **HOST_NAME** is the name of hosts defined in the `inventory.yaml` in (i).
- set a strong vault password.
- save the remote endpoint credentials in the vault with these variables:
```
ansible_become_password: <sudo-password>
```

### 3. Configure volume mappings

The **`volumes.yml`** file defines bind-mount mappings between host directories and Wazuh manager container paths. This file is critical for RADAR's Ansible playbook to locate and modify Wazuh configuration files on the host filesystem.

**Default `volumes.yml`:**
```yaml
version: "3.7"

services:
  wazuh.manager:
    volumes:
      - /srv/wazuh/manager/api/configuration:/var/ossec/api/configuration
      - /srv/wazuh/manager/etc:/var/ossec/etc
      - /srv/wazuh/manager/logs:/var/ossec/logs
      - /srv/wazuh/manager/queue:/var/ossec/queue
      - /srv/wazuh/manager/var/multigroups:/var/ossec/var/multigroups
      - /srv/wazuh/manager/integrations:/var/ossec/integrations
      - /srv/wazuh/manager/active-response/bin:/var/ossec/active-response/bin
      - /srv/wazuh/manager/filebeat/etc:/etc/filebeat
      - /srv/wazuh/manager/filebeat/var:/var/lib/filebeat
```

**When to update `volumes.yml`:**

- **Existing Wazuh installation**: If you have an existing Wazuh manager with different volume paths, update `volumes.yml` to match your current bind-mount configuration. The Ansible playbook reads this file to determine where to deploy decoders, rules, active responses, and configuration files on the host.

- **Custom deployment paths**: If you prefer different host directories (e.g., `/opt/wazuh/` instead of `/srv/wazuh/`), modify the left side of each mapping accordingly.

**How to find your existing Wazuh volumes:**

If Wazuh is already running, inspect the current volume mappings with correct `MANAGER_CONTAINER_NAME`:
```bash
docker inspect MANAGER_CONTAINER_NAME --format '{{range .Mounts}}{{.Source}}:{{.Destination}}{{"\n"}}{{end}}'
```

Then update `volumes.yml` to match the output.

**Required mappings:**

The Ansible playbook validates that these container paths have corresponding bind-mounts:
- `/var/ossec/etc` — for `ossec.conf`, decoders, rules, lists
- `/var/ossec/active-response/bin` — for active response scripts
- `/etc/filebeat` — for Filebeat configuration (log volume scenario)

If any required mapping is missing, the playbook will fail with a validation error.


### 4. Configure scenario specifications (for ML-based detection)

The **`config.yaml`** file is essential for ML-based (behavior-based) anomaly detection scenarios. It defines how OpenSearch anomaly detectors and monitors are configured for each scenario. If you are using signature-based detection only (e.g., GeoIP detection), this file requires no changes. However, for ML-based scenarios (log volume, suspicious login behavioral, insider threat, DDoS, malware communication), proper configuration is critical.


**Key parameters explained:**

| Parameter | Description | Impact |
|-----------|-------------|--------|
| `categorical_field` | Field used for high-cardinality detection (e.g., per-user, per-agent baselines) | Enables UEBA-style detection where each entity has its own baseline |
| `shingle_size` | Number of consecutive data points the RCF algorithm considers | Higher values detect longer-term patterns; lower values are more sensitive to sudden changes |
| `detector_interval` | How often the detector runs (in minutes) | Affects detection latency and resource usage |
| `anomaly_grade_threshold` | Minimum anomaly score to trigger an alert (0.0-1.0) | Lower = more sensitive (more alerts); Higher = fewer false positives |
| `confidence_threshold` | Minimum confidence level required (0.0-1.0) | Higher values require more certainty before alerting |
| `features` | OpenSearch aggregation queries defining what metrics to analyze | Determines what behavioral patterns the detector learns |

**Feature aggregation types:**

Features use OpenSearch aggregation queries to extract metrics:
- `value_count`: Count of documents/events
- `sum`: Total of a numeric field
- `avg`: Average of a numeric field  
- `max`: Maximum value of a numeric field
- `cardinality`: Count of unique values (useful for detecting anomalous diversity)

**Tuning recommendations:**

- **High false positive rate**: Increase `anomaly_grade_threshold` and `confidence_threshold`
- **Missing detections**: Decrease thresholds, add more features, or reduce `detector_interval`
- **Per-entity detection**: Ensure `categorical_field` points to the correct entity identifier (user, host, IP)
- **Seasonal patterns**: Increase `shingle_size` to capture longer behavioral cycles


### 5.Configure active response parameters

The **`scenarios/active_responses/ar.yaml`** file configures the risk-aware active response system for each scenario. This file is located at the path specified by `AR_RISK_CONFIG` in your `.env` file and should be customized according to your operational requirements and risk tolerance.

**Key parameters explained:**

| Parameter | Description | Example Values |
|-----------|-------------|----------------|
| `ad.rule_ids` | Rule IDs from ML-based anomaly detection | `["100021", "100309"]` |
| `signature.rule_ids` | Rule IDs from signature-based detection | `["210012", "210013"]` |
| `w_ad` | Weight for anomaly detection in risk score (0.0-1.0) | `0.3` for 30% weight |
| `w_sig` | Weight for signature-based detection in risk score (0.0-1.0) | `0.4` for 40% weight |
| `w_cti` | Weight for cyber threat intelligence in risk score (0.0-1.0) | `0.3` for 30% weight |
| `delta_ad_minutes` | Time window for AD alerts correlation (minutes) | `10` |
| `delta_signature_minutes` | Time window for signature alerts correlation (minutes) | `1` |
| `signature_impact` | Impact score for signature detections (0.0-1.0) | `0.7` |
| `signature_likelihood` | Likelihood score for signature detections (0.0-1.0) or weighted rules | `0.8` or rule-specific weights |
| `tiers.tier1_min` | Minimum risk score to enter Tier 1; scores below fall into Tier 0 (0.0-1.0) | `0.0` |
| `tiers.tier1_max` | Maximum risk score for Tier 1 (0.0-1.0) | `0.33` |
| `tiers.tier2_max` | Maximum risk score for Tier 2 (0.0-1.0) | `0.66` |
| `mitigations_tier2` | List of mild/reversible active response actions executed at Tier 2 | `["firewall-drop"]` |
| `mitigations_tier3` | List of harsh/permanent active response actions executed at Tier 3 | `["firewall-drop", "lock_user_linux.sh"]` |
| `allow_mitigation` | Whether to execute automated mitigations at Tier 2 and Tier 3 | `true` or `false` |

**Tuning recommendations:**

- **Adjust weights** (`w_ad`, `w_sig`, `w_cti`) based on confidence in each detection method - they must sum to 1.0
- **Lower `risk_threshold`** for more aggressive automated response
- **Set `allow_mitigation: false`** for alert-only mode without automated actions
- **Configure tier boundaries** to match your organization's risk strategy
- **Use rule-specific likelihood weights** when different signature rules have varying confidence levels


### 6. Configure DECIPHER

RADAR can optionally create cases/tasks and push investigation context to a FlowIntel instance. To enable this, we must have **DECIPHER running and reachable** from the Wazuh manager / active response context, and we must configure the `DECIPHER_*` variables in `.env`. DECIPHER is a subsystem of SATRAP-DL responsible of supporting automated workflows for handling diverse types of incidents, informed by CTI and relying on open-source tools. Further details can be found in [DECIPHER page](https://github.com/AbstractionsLab/satrap-dl/tree/main/decipher).


# Usage

## 1) Deploy the RADAR infrastructure

Run `build-radar.sh` to bring up core services, optionally agent containers, run the Ansible playbook limited to the manager + agent group for the selected scenario, and build docker containers.

**Usage:**
```bash
build-radar.sh <scenario> --agent <local|remote> --manager <local|remote> 
                          --manager_exists <true|false> [--ssh-key </path/to/private_key>]

Scenarios:
  suspicious_login | insider_threat | ddos_detection | malware_communication | geoip_detection | log_volume

Flags:
  --agent           Where agents live:      local (docker-compose.agents.yml) | remote (SSH endpoints)
  --manager         Where manager lives:    local (docker-compose.core.yml)   | remote (SSH host)
  --manager_exists  Whether the manager already exists at that location:
                      - true  : do not bootstrap a manager
                      - false : bootstrap (local: docker compose up; remote: let Ansible bootstrap)
  --ssh-key         Optional: path to the SSH private key used for remote manager/agent access.
                    If not provided, defaults to: $HOME/.ssh/id_ed25519
```

**Examples**:

- Suspicious login scenario set up for a customer: local manager does not exist (single node or multi node), deploy Wazuh agents on remote endpoints.
```
./build-radar.sh suspicious_login --agent remote --manager local --manager_exists false
```
  
- Geo IP detection setup for a customer: no remote manager exists (bootstrap it via Ansible), remote SSH agents
```
./build-radar.sh geoip_detection --agent remote --manager remote --manager_exists false --ssh-key "$HOME/.ssh/mykeys/id_ed25519"
```
> **Local manager:** When `--manager local`, `build-radar.sh` should be run with sudo to eliminate permission conflicts for volume mounts. 
> **Existing (ansible) hosts supported:** Ansible can target **already-running** Wazuh manager and agents (agents not running in containers). Configure the `inventory.yaml` file with information about your host and edge node groups (e.g., `wazuh_manager_ssh` and `wazuh_agents_ssh`), ensure SSH connectivity, and use `--agent remote`  or `--manager remote` with `build-radar.sh`. 
>
> You must have an appropriate authorized user with sudo privileges on each endpoint where a Wazuh agent is already installed.


## 2) Run a scenario end-to-end

```bash
./run-radar.sh log_volume
```

This script ingests the scenario dataset, then ensures/starts an AD **detector** (prints `DET_ID`), and finally sets up a **monitor** with a webhook (prints `MON_ID`).

