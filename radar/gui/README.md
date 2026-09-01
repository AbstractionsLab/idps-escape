# RADAR GUI

A Flask-based web interface for managing, deploying, and monitoring RADAR scenarios. It covers the operational lifecycle: connector configuration, active response tuning, deployment, agent/group management, and health checking.

## Table of contents

- [Running the GUI](#running-the-gui)
- [Pages](#pages)
- [Architecture](#architecture)
- [REST API](#rest-api)

---

## Running the GUI

### Prerequisites

- Python 3.10 or later
- The RADAR repository

### Setup

From RADAR root `radar/`:

```bash
./radar.sh gui
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

Six tabs, two of which have their own second-level sub-tabs:

**Scenario Management** — *Deploy scenario* sub-tab runs `build-radar.sh` for the selected scenario (with a **Plain Wazuh only** option for `--core-only`, no scenario applied). *Undeploy scenario* sub-tab reverses a scenario's manager-side deployment (group config, `ossec.conf` block, and any decoder/rule/list file no longer shared by another deployed scenario).

**Agent Management** — *Onboard agent* sub-tab mints a short-lived enrollment token (also opening the port 1515 firewall window for its lifetime) and shows a ready-to-run `bootstrap-agent.sh` command with a copy button. *Deregister agent* sub-tab removes an agent's registration from the manager entirely. *Enrollment Window* sub-tab opens/closes/checks the port 1515 firewall rule independently.

**Group Management** — assigns an already-enrolled agent to a scenario's group(s) from the manager side (no SSH needed), or unenrolls it (leaving `default` untouched).

**Anomaly Detector** — runs `run-radar.sh` to create the OpenSearch detector and monitor for a Hybrid or Anomaly ML scenario. Optionally ingests the training dataset first. Only scenarios that use the OpenSearch AD pipeline appear here.

**Status** — runs `health-radar.sh` (filesystem/container checks plus Wazuh API checks) and streams the result.

**Teardown** — stops (and optionally purges) the manager/indexer/dashboard/webhook containers.

Deploying/undeploying, minting a token, opening/closing the enrollment window, and tearing down all need the sudo password — the GUI prompts for it once per session and holds it in memory only.

### Not currently reachable: Infrastructure (`/infrastructure`)

`templates/infrastructure.html` and `static/js/infrastructure.js` still exist on disk, but the `/infrastructure` route and every `/api/infrastructure/*` endpoint are commented out in `app.py`.

---

## Architecture

```
gui/
├── app.py                  Flask application, all routes
├── requirements.txt        Python dependencies
├── templates/              Jinja2 HTML templates
│   ├── base.html
│   ├── active_responses.html
│   ├── connectors.html
│   ├── deploy.html
│   └── infrastructure.html
├── static/
│   ├── js/                 Frontend JavaScript
│   │   ├── main.js         Sudo-password / vault modal logic, global nav, SSH badge
│   │   ├── active_responses.js
│   │   ├── connectors.js
│   │   ├── deploy.js
│   │   └── infrastructure.js
│   └── css/
│       └── main.css
└── orchestrator/           Backend modules
    ├── ar_config.py        Read/write ar.yaml
    ├── connectors.py       Read/write .env, connectivity tests
    ├── deploy.py           Command assembly, process streaming, Wazuh API calls for some steps
    ├── health.py           Per-node health checks (used by the dead /infrastructure page's own health button; the live Status tab under Deploy calls into wazuh_api directly instead)
    └── vault.py            Sudo-password session store (used for all privileged Deploy-page actions)
```

The sudo password is held in a short-lived in-process session dictionary keyed by a random cookie (`radar_vault_sid`). They are never written to disk.

---

## REST API

The GUI exposes a JSON REST API under `/api/`. All endpoints are served by the same Flask process on port 5000. The API is used exclusively by the GUI's own JavaScript and is intended for internal use, but it can be exercised directly for scripting or automation.

### Endpoint groups

| Prefix | Responsibility |
|--------|---------------|
| `/api/scenarios` | List scenarios, read and write AR config, bind / unbind |
| `/api/connectors` | Read, write, and test connector settings |
| `/api/deploy` | Build, undeploy, onboard/deregister agent, assign/unassign group, enrollment window, run AD, health-check, teardown, preview, and stream status for each |
