# RADAR GUI

A Flask-based web interface for managing, deploying, and monitoring RADAR scenarios. It covers the full operational lifecycle: connector configuration, infrastructure inventory, active response tuning, deployment, and health checking.

## Table of contents

- [Running the GUI](#running-the-gui)
- [Pages](#pages)
- [Architecture](#architecture)

---

## Running the GUI

### Prerequisites

- Python 3.10 or later
- The RADAR repository

### Setup

Create and activate a virtual environment, then install the dependencies:

```bash
cd radar/gui
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Starting the server

```bash
python app.py
```

The server listens on `http://localhost:5000` by default. 

---

## Pages

### RADAR Scenarios (`/active-responses`)

Configures the active response logic per bound scenario. Settings cover:

- **Risk weights** - `w_ad`, `w_sig`, `w_cti`: relative contribution of anomaly detection, signature scoring, and CTI lookup to the final risk score. Must sum to 1.0.
- **Signature scoring** - `signature_impact` and `signature_likelihood` parameters fed into the risk engine.
- **Anomaly detection scoring** - AD score thresholds and scaling.
- **Time windows** - `delta_ad_minutes` controls how far back the AD correlation looks; `delta_signature_minutes` controls the look-back window used for both signature correlation and CTI lookups (RADAR queries the CTI tool for threat intelligence hits on the alerting entity within that many minutes).
- **Risk tiers** - score boundaries [0–1] for T1 (alert only), T2 (escalate + Flowintel case), T3 (mitigate), T4 (hard mitigate).
- **Mitigations** - per-tier lists of active response actions (`firewall-drop`, `lock_user_linux`, `terminate_service`). Requires `allow_mitigation: true` to execute.

All changes are saved immediately to `ar.yaml` on submit.

### Infrastructure (`/infrastructure`)

Displays the full Ansible inventory: managers and agents, their connection type, IP, and credential status. Provides forms for adding, editing, and deleting managers and agents. For remote nodes, you can store an Ansible `become` password encrypted in an Ansible Vault file under `host_vars/`.

### Connectors (`/connectors`)

Manages credentials and URLs for all external integrations. Values are written to the `.env` file at `RADAR_ROOT`. TLS certificates are stored under `.certs/`. Connectors:

| Name | Fields |
|------|--------|
| OpenSearch | URL, user, password, SSL |
| Wazuh API | URL, user, password, manager address |
| Wazuh Dashboard | URL, user, password, SSL |
| SMTP | Host, port, user, password, recipient |
| DECIPHER | URL, API token, SSL, timeout |
| Webhook | Name, URL |

Each connector has a **Test** button that performs a live connectivity check.

### Deploy (`/deploy`)

Three sub-tabs:

**Build & deploy** - runs `build-radar.sh` to deploy a scenario via Ansible. Selects manager location (local docker-compose or remote SSH) and agent location (local containers or SSH agents). Streams Ansible output in real time.

**Run Anomaly Detector** - runs `run-radar.sh` to create the OpenSearch detector and monitor for a hybrid or ML scenario. Optionally ingests the training dataset first.

**Status** - polls all inventory nodes for health and shows per-check results inline.

---

## Architecture

```
gui/
├── app.py                  Flask application, all routes
├── requirements.txt        Python dependencies
├── templates/              Jinja2 HTML templates
│   ├── base.html
│   ├── infrastructure.html
│   ├── active_responses.html
│   ├── connectors.html
│   └── deploy.html
├── static/
│   ├── js/                 Frontend JavaScript
│   │   ├── main.js         Vault / SSH modal logic, global nav
│   │   ├── infrastructure.js
│   │   ├── active_responses.js
│   │   ├── connectors.js
│   │   └── deploy.js
│   └── css/
│       └── main.css
└── orchestrator/           Backend modules
    ├── inventory.py        Read/write inventory.yaml
    ├── ar_config.py        Read/write ar.yaml
    ├── connectors.py       Read/write .env, connectivity tests
    ├── deploy.py           Build command assembly, process streaming
    ├── health.py           Per-node health checks
    └── vault.py            Ansible Vault encryption, SSH passphrase session store
```

Vault passwords and SSH passphrases are held in a short-lived in-process session dictionary keyed by a random cookie (`radar_vault_sid`). They are never written to disk.

---

## REST API

The GUI exposes a JSON REST API under `/api/`. All endpoints are served by the same Flask process on port 5000. The API is used exclusively by the GUI's own JavaScript and is intended for internal use, but it can be exercised directly for scripting or automation.

### Endpoint groups

| Prefix | Responsibility |
|--------|---------------|
| `/api/scenarios` | List scenarios, read and write AR config, bind / unbind |
| `/api/connectors` | Read, write, and test connector settings |
| `/api/infrastructure` | CRUD for managers and agents, credential management, health checks |
| `/api/deploy` | Build, run AD, health-check, preview, and stream status |
| `/api/vault` | Vault status, create, unlock, lock |
| `/api/ssh` | SSH passphrase status, set, clear |
