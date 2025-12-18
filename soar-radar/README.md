# RADAR: Risk-aware Anomaly Detection-based Automated Response

As a key part of the overall SOAR mission of IDPS-ESCAPE, in this folder, 
we store all design, development and implementation artifacts required for 
deploying our anomaly detection (AD) scenarios, along with their dedicated 
active responses (AR). Our security orchestration approach provides a series of Risk-aware AD-based AR (**RADAR**) modules aimed at enhancing SOC operations.

Our RADAR modules are currently geared towards an [Amazon AWS implementation](https://github.com/aws/random-cut-forest-by-aws/) of the classical [Random Cut Forest (RCF) AD on streams algorithm](https://www.amazon.science/publications/robust-random-cut-forest-based-anomaly-detection-on-streams), which can be integrated into Wazuh by installing the [OpenSearch AD plugin](https://wazuh.com/blog/enhancing-it-security-with-anomaly-detection/). We recommend a hybrid approach combining our [ADBox subsystem](/docs/manual/README.md) with our RCF-based [RADAR subsystem](/soar-radar/README.md) for a more robust setup, providing [resilience to adversarial interference](#best-practices-for-robust-ad-with-resilience-to-adversarial-interference).

We make use of the latest advances in the [OpenSearch implementation](https://opensearch.org/anomaly-detection/), namely [false positive reductions](https://opensearch.org/blog/reducing-false-positives-through-algorithmic-improvements/) and support for categorical features and [high-cardinality anomaly detection](https://aws.amazon.com/blogs/big-data/detect-anomalies-on-one-million-unique-entities-with-amazon-opensearch-service/) via slicing, allowing for separate baseline detectors that avoid statistical artifacts, e.g., UEBA model baselines per user or device to avoid deviations in one user behavior to be masked by another's when performing AD in a group setting.

We recommend adopting our hybrid method aimed at robustness and resilience to adversarial interference involving three elements: 
(i) signature-based detection with 
(ii) AD based on deep learning models via MTAD-GAT using ADBox, relying on state-of-the-art advances in artificial intelligence (AI) and machine learning (ML) such as the *attention mechanism* and 
(iii) a classical algorithm for AD on streams such as the Robust Random Cut Forest (RRCF) algorithm supporting categorical features.

Below we provide a mapping of each key feature to their corresponding scripts, configurations, and components in the repository.

## RADAR scenarios

Currently, anomaly detection coupled with automated response is implemented for the RADAR scenarios listed below. Each scenario integrates a detector, monitor, webhook, decoder, rule, and active response in a deployable solution. They also come with a dataset ingestor (`wazuh_ingest.py`) aimed at populating the Wazuh indexer, e.g. for training models or running experiments.

### Signature-based AD 

_Ready to be used with real data from Wazuh:_

- [Non-whitelist GeoIP detection](/soar-radar/geoip_detection/README.md)
- [Suspicious login](/soar-radar/suspicious_login/README.md#signature-based-approach)

### ML-based AD with RRCF

_Variant in `v0.5` partially ready to be used with real data from Wazuh:_
- [Log volume growth detection](/soar-radar/log_volume/README.md): before `build-radar.sh` and `run-radar.sh`, requires a `./stop-radar.sh --all --purge`, thus currently only recommended for testing on real data but in a test/dev environments, but **not** in production environments.

_The runner in `v0.5.1` is broken._

_Scenarios currently working with demo datasets only follow:_

- [Insider threat](/soar-radar/insider_threat/README.md)
- [Suspicious login](/soar-radar/suspicious_login/README.md#behavior-based-approach)
- [DDoS](/soar-radar/ddos_detection/README.md)
- [C2 malware communication](/soar-radar/malware_communication/README.md)

> **Important:** These scenarios are demonstration-oriented and not directly suitable for real-world Wazuh environments. Deployment to production requires adaptation of indices/aliases, field mappings, time/category fields, decoders/ingest pipelines, TLS/hostnames, and detector/monitor parameters to align with your organization’s actual log schema and infrastructure.

## Getting started

RADAR orchestrates risk-aware anomaly detection (OpenSearch AD) and automated response across several components of the IDPS-ESCAPE architecture (see [HARC-003](https://abstractionslab.github.io/idps-escape/docs/traceability/HARC.html#HARC-003)). Setting up and running RADAR is enabled by two entrypoint scripts:

- `build-radar.sh` – prepares the environment (Wazuh core stack + agents + RADAR dependencies), runs Ansible pipelines for the chosen scenario, and builds various Docker containers.
- `run-radar.sh` – ingests a scenario dataset, ensures/starts an AD detector, and ensures a monitor with a webhook (prints `DET_ID`/`MON_ID`).

Below, we explain the pre-requisites and steps for bringing a scenario to life. At the end you will find a script for testing via a lightweight Docker runner.

For a very detailed breakdown of the Ansible playbook providing the automation pipeline for deploying and setting up the Wazuh manager, see our dedicated [page describing our approach to the automated manager deployment via an Ansible playbook](/docs/manual/radar-manager-ansible-playbook.md).

For a detailed description of the `run-radar.sh` workflow, refer to [the dedicated documentation page](/docs/manual/radar-run-ad.md).

---

### Modes of deployment

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

### Prerequisites

- [Docker Engine](https://docs.docker.com/engine/install/) and [Docker Compose](https://docs.docker.com/compose/install) installed in the endpoints where the Wazuh agents/manager are to be deployed.
- **Ansible 2.15+** installed in the host node *(required by `build-radar.sh`)*
    - Used for configuring the scenarios in manager and agents (rules, decoders, AR) in an idempotent and repeatable way.
    - If `pipx` is available, follow the instruction in [Ansible Installation Documentation using pipx](https://docs.ansible.com/projects/ansible/latest/installation_guide/intro_installation.html#pipx-install).
    - Otherwise, follow the [official installation instructions](https://docs.ansible.com/projects/ansible/latest/installation_guide/installation_distros.html) for your OS.
- The [OpenSearch AD plugin integrated into Wazuh](https://wazuh.com/blog/enhancing-it-security-with-anomaly-detection/)
  - See our dedicated [installation page](/deployment/opensearch-ad-plugin.md) for a Docker-based integration of the OpenSearch AD plugin into Wazuh. The latest release (`v0.5`) has been tested and validated against Wazuh manager and agents `v4.12.0`.
- Optionally, our [ADBox](/docs/manual/README.md) subsystem for a hybrid approach to AD.
    
### Setup

#### 1. Setup connection and authorization variables. 

Create a **`.env`** file at this path (i.e., `idps-escape/soar-radar`) to define endpoint URLs, credentials, and SSL flags (for Wazuh OpenSearch and the Wazuh Dashboard). This file is read by `detector.py` and `monitor.py` inside the `radar-cli` container.

A sample of `.env` with default IPs and credentials is given next. Make sure to modify it according to your settings.

```
# =======================
# OpenSearch Configuration
# =======================
OS_URL=https://192.168.5.4:9200
OS_USER=admin
OS_PASS=SecretPassword
OS_VERIFY_SSL="/app/config/wazuh_indexer_ssl_certs/root-ca.pem"

DASHBOARD_URL=https://192.168.5.4
DASHBOARD_USER=admin
DASHBOARD_PASS=SecretPassword
DASHBOARD_VERIFY_SSL="/app/config/wazuh_indexer_ssl_certs/root-ca.pem"

WAZUH_API_URL=https://192.168.5.4:55000
WAZUH_AUTH_USER=wazuh-wui
WAZUH_AUTH_PASS=MyS3cr37P450r.*-

WAZUH_AGENT_VERSION=4.12.0-1
WAZUH_MANAGER_ADDRESS=192.168.5.4

WEBHOOK_NAME="RADAR_Webhook"
WEBHOOK_URL=http://192.168.5.4:8080/notify

# =======================
# Logging
# =======================

AR_LOG_FILE=/var/ossec/logs/active-responses.log

# =======================
# SMTP
# =======================

SMTP_HOST=SMTP_HOST # Change accordingly
SMTP_PORT=SMTP_PORT # Change accordingly
SMTP_USER=SMTP_USER # Change accordingly
SMTP_PASS=SMTP_PASS # Change accordingly
EMAIL_TO=RECEIVER_EMAIL@example.com # Change accordingly
SMTP_STARTTLS=yes
```

#### 2. Configure users in remote endpoints

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

> **Network note**: `run-radar.sh` connects to the Docker network `soar-radar_soar-radar`. If your docker compose project names networks differently, adapt the compose file accordingly.

### Other files
- **`config.yaml`** Scenario specifications, including
    scenario names, index patterns, time/categorical fields, features, thresholds, webhook defaults. Used to build detector/monitor payloads.

## Usage

### 1) Deploy the RADAR infrastructure

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

> **Existing (ansible) hosts supported:** Ansible can target **already-running** Wazuh manager and agents (agents not running in containers). Configure the `inventory.yaml` file with information about your host and edge node groups (e.g., `wazuh_manager_ssh` and `wazuh_agents_ssh`), ensure SSH connectivity, and use `--agent remote`  or `--manager remote` with `build-radar.sh`. 
>
> You must have an appropriate authorized user with sudo privileges on each endpoint where a Wazuh agent is already installed.


### 2) Run a scenario end-to-end

```bash
./run-radar.sh log_volume
```

This script ingests the scenario dataset, then ensures/starts an AD **detector** (prints `DET_ID`), and finally sets up a **monitor** with a webhook (prints `MON_ID`).

## Testing

A slim test image is provided, enabling the setup to be validated with a single Docker command, without local Python or bats installations:

```bash
./test.sh
```
---

## RADAR automated test framework

The RADAR subsystem comes with a dedicated test framework aimed at automating the experimentation and validation chain of activities.
More precisely, powered by Ansible, we provide a pipeline automating the ingestion of datasets, preprocessing, 
training and ML model baseline establishment, attack simulation, data collection, followed by post-processing and 
computation of statistical measures, which are then reported to the user.

See [RADAR test framework](/soar-radar/radar-test-framework/README.md) for more details.

## Active response modules and SOAR playbooks for Wazuh

The active response modules stored in the respective RADAR scenario implementation folders, i.e., `soar-radar/<RADAR-scenario>/active_responses`, provide 
automated responses and contextual enrichments based on anomalies. 
These reduce manual work for analysts via automation and also benefit from our [CTI integration](/integrations/README.md) support, e.g., [insider threat active responses](/soar-radar/insider_threat/active_responses/).

## Best practices for robust AD with resilience to adversarial interference

In a future update, we will provide a detailed report on how to implement the main defensive mechanisms based on state-of-the-art research on adversarial machine learning and anomaly detection. Here we provide some concise notes on how to tackle this following our recommended hybrid approach combining the use of both our MTAD-GAT paradigm in the ADBox subsystem as well as the classical RCF-based AD solution available via an OpenSearch plugin.

### Practical implementation considerations

Translating the latest research findings into practice within SIEM and SOC operations would involve the following considerations:

#### Baseline initialization

We recommend initializing anomaly detection models on data believed to be clean. For example, train on logs from a honeypot-free period or using a gold-standard dataset. If there is any suspicion that an attacker was present historically, those time segments or hosts should be excluded or given lower weight in initial training. Some organizations perform “digital clean room” exercises – temporarily locking down systems to capture a clean baseline. While not always feasible, the cleaner the start, the more reliable the model.
    
#### Continuous retraining with caution

Anomaly models based on deep learning often need retraining or updating as systems and usage patterns evolve. However, blindly retraining on recent data can incorporate an attacker’s ongoing behavior. A practical compromise is to use a rolling training window but with **concept drift detection**. If the baseline shifts too quickly or in a strange way, freeze the model and have an analyst examine the change before accepting it. This prevents an attacker from gradually shifting the baseline (“boiling the frog”) without notice.
    
#### Use of contamination parameter

Some of the off-the-shelf anomaly detection algorithms (e.g., IsolationForest in Python’s scikit-learn or the PyOD library) allow specifying an expected contamination rate. We can leverage this by setting a small contamination fraction (based on threat modelling – perhaps 1-5%). This ensures the model inherently treats the top few percent most abnormal training points as outliers. It is a simple safeguard: even if an attacker’s data got in, the model might naturally down-rank it as part of that fraction. One must be careful to neither underestimate nor grossly overestimate this fraction; tuning on validation data or known-clean subsets can help. **Note**: Our current release does not provide an immediate way of enforcing the above, but if you feel inclined to do so, the ingredients are all available in the repository.
    
#### Synthetic anomaly injection

To test and improve the detector’s sensitivity, security teams can inject simulated anomalies or red-team activities during training or evaluation. If the model fails to flag these injections, that indicates an overfitting or poisoned baseline problem. Some organizations periodically run adversarial drills (e.g., a benign worm simulation) and check if the anomaly detector catches it. Such tests, inspired by adversarial training, can expose weaknesses in the model’s learned normalcy and prompt retraining with the injected anomalies included as “anomalous”. Essentially, this is a way to vaccinate the model against certain attacks.
    
#### Multi-layer logging and detection

Ensuring that logs from different layers (network, OS, application) are available and anomaly detection is applied to each can reveal inconsistencies. For example, an attacker might manage to poison host logs but not network flows. If the SIEM aggregates and compares both, the anomaly in one can reveal the stealth in the other. Implementing a unified view (via user and entity behavior analytics – UEBA – that spans multiple log types) is a practical way to achieve the hybrid approach discussed. Our approach already provides UEBA modules that learn behavior baselines per user or device across diverse activities; these can act as a backstop if any single log source is compromised.
    
#### Alert fusion and analyst workflows

In practice, dealing with outputs from these advanced anomaly detectors requires good workflow design. If robust methods are used, they might produce a lot of information – e.g., which points were considered outliers and dropped, or which small anomaly set was used. This information should be exposed to analysts (possibly as explanations for why something is deemed normal or anomalous). For instance, if an alert is suppressed because the model thinks “this is normal for that host,” an analyst might want to see what baseline data supports that belief. Transparency can help catch cases where the model was tricked.
    
#### System hardening

Adversaries sometimes try not just to poison data but to tamper with the detection system (for example, by altering log integrity or even the model files if they gain access). So traditional security controls are important: ensure **log integrity** (cryptographic hashing, append-only logging) to prevent an attacker from retroactively sanitizing their traces; restrict access to the ML model and training pipeline (only authorized administrators can initiate retraining, etc.). These measures do not directly solve the ML challenge but create additional hurdles for an attacker attempting to carry out a poisoning attack.

#### Additional remarks

In general, we recommend a combination of _technical controls_ (robust algorithms, multi-source detection) and _process controls_ (human oversight, data validation procedures).

Over the past decade, we have been observing a trend: awareness of adversarial threats to IDS has risen, and solutions are becoming more sophisticated – from simply cleaning the data to proactively _learning_ in the presence of malicious influence. The overarching goal is to ensure that an attacker cannot easily hide in the “noise” of normalcy nor quietly teach our defenses to ignore them. 

While there is still a need for more robust and resilient AD solutions and a gap in fully addressing adaptive adversaries, the strategies outlined above – data sanitization, robust training (with help from a few labelled anomalies or adversarial learning), hybrid detection layers, and human-in-the-loop (HITL) oversight – collectively form a basis to meet the challenge of adversaries corrupting anomaly detection systems. With such measures being in place, turning an AD system against itself can be made harder for an infiltrator.