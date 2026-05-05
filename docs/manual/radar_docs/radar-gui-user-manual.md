# RADAR GUI - User Manual

## Overview

The RADAR GUI is a web-based control panel for deploying, configuring, and monitoring RADAR detection scenarios. It has four pages accessible from the left sidebar: **RADAR Scenarios**, **Infrastructure**, **Connectors**, and **Deploy**.

Two persistent status badges appear in the top-right corner of every page: one for the vault lock state and one for the SSH passphrase. Their meaning is explained in [Vault and credentials](#vault-and-credentials).

![RADAR Demonstration](/docs/manual/_figures/RADAR_GUI.gif)

---

## First-time setup checklist

If you are starting from scratch, work through these steps in order:

1. [Configure connectors](#connectors) - set URLs and credentials for OpenSearch, Wazuh API, SMTP, and DECIPHER.
2. [Add infrastructure](#infrastructure) - register the Wazuh manager and any agents.
3. [Set the vault password](#vault-and-credentials) - required before storing sudo credentials for remote nodes.
4. [Store node credentials](#credentials) - one per remote manager or SSH agent.
5. [Configure active responses](#active-responses) - tune risk weights, time windows, tier thresholds, and mitigations for each bound scenario.
6. [Deploy](#deploy) - run Ansible to push the scenario to your infrastructure.

---

## RADAR Scenarios

![RADAR GUI - RADAR Scenarios page](/docs/website/assets/RADAR_GUI_RADAR_Scenarios.png "RADAR GUI RADAR Scenarios page showing risk weight configuration and tier thresholds")

RADAR Scenarios is where you tune the risk engine for each bound scenario. The page has a left sidebar listing all bound scenarios - each appears as a tab. Click a tab to load its configuration into the right panel. A green **Mitigations ON** badge on a tab indicates that automatic mitigation execution is currently enabled for that scenario.

All changes take effect immediately on **Save**.

### Risk weights

Three weights control how the final risk score [0–1] is computed:

| Weight | Source |
|--------|--------|
| `w_ad` | Anomaly detector score (`anomaly_grade × confidence`) |
| `w_sig` | Signature rule score (`impact × likelihood`) |
| `w_cti` | CTI threat intelligence lookup score from DECIPHER |

The three values must sum to **1.0**. For **Signature** scenarios, set `w_ad` to 0. For **Anomaly ML** scenarios, set `w_sig` to 0. For **Hybrid** scenarios, all three can be non-zero.

### Signature scoring

Shown for Signature and Hybrid scenarios.

- **`signature_impact`** - how severe this signature rule is considered (0–1).
- **`signature_likelihood`** - estimated true-positive rate for this rule (0–1).

### Anomaly detection scoring

Shown for Anomaly ML and Hybrid scenarios. The fields `anomaly_grade` and `confidence` are supplied at runtime by the OpenSearch anomaly detector.

### Time windows

Controls how far back RADAR looks when correlating evidence at alert time.

- **`delta_ad_minutes`** - look-back window for AD event correlation. When an anomaly fires, RADAR searches this many minutes of history for related AD events.
- **`delta_signature_minutes`** - look-back window for signature event correlation and CTI lookup. When an alert fires, RADAR queries Wazuh for threat intelligence hits on the alerting entity (IP, user, hostname) within this many minutes.

### Risk tiers and thresholds

Risk scores map to four response tiers based on the normalized risk calculation (see [radar-risk-math.md](./radar-risk-math.md) for the complete mathematical specification). The upper boundary of T1, T2, and T3 is configurable; boundaries must be strictly increasing. T4 always extends to 1.0.

| Tier | Default upper boundary | Response |
|------|----------------------|----------|
| T1 | 0.33 | Email notification only |
| T2 | 0.66 | Email + Flowintel case + tier-2 mitigations |
| T3 | 0.85 | Full response + tier-3 mitigations |
| T4 | 1.0 | Immediate containment + tier-4 mitigations |

**Tuning guidance.** To reduce false-positive automated actions, raise T1 and T2 boundaries. To respond more aggressively at lower confidence, lower them. After a boundary change, review the audit log at `/var/ossec/logs/active-responses.log` to verify that recent alerts would have landed in the intended tier.

### Mitigations per tier

Tier 1 produces only an email notification - no executable actions are available for it. For tiers 2, 3, and 4, assign actions using the **+ Add action** dropdown in each column.

Available actions:

| Action | Effect |
|--------|--------|
| `firewall-drop` | Blocks the source IP on the affected agent via `iptables` |
| `lock_user_linux` | Locks the Linux user account involved in the alert |
| `terminate_service` | Terminates the suspicious process or service |

**Allow automatic mitigation execution** - when this checkbox is off, RADAR plans and logs mitigation actions but does not execute them. This is the safe default. Enable only after testing.

### Bound rule IDs

Read-only display at the bottom of the panel showing the Wazuh rule IDs associated with this scenario, split into AD rule IDs and signature rule IDs.

---

## Infrastructure

![RADAR GUI - Infrastructure page](/docs/website/assets/RADAR_GUI_Infrastructure.png "RADAR GUI Infrastructure page showing Wazuh manager and agent inventory cards")

The Infrastructure page manages the Ansible inventory (`inventory.yaml`). The page subtitle shows the total manager and agent count. Two sections are displayed: **Wazuh Manager** and **Agents**.

Two buttons appear in the top-right: **+ Manager** and **+ Agent**.

If the inventory file cannot be read, a red error banner is shown: "Could not read inventory.yaml: …". If no managers exist, an amber banner reads "No managers in inventory.yaml. Use + Manager to add one." The same pattern applies for agents.

### Manager cards

Each manager card shows:
- A **Local** or **Remote SSH** connection badge, and a **docker** or **host** kind badge.
- The inventory hostname as the card title.
- A table with IP / host, container name, service name (docker kind only), SSH user, and SSH port (remote only).
- Four action buttons: **Health**, **Edit**, **Set credential** (or **Change credential** if one is stored), **Delete**.

### Agent cards

Each agent card shows:
- A **Container** or **SSH** badge.
- For SSH agents: IP / host, SSH user, SSH port.
- Three action buttons: **Health**, **Edit**, **Delete**. SSH agents also have **Set credential** / **Change credential**. 

### Adding a manager

Click **+ Manager**. The modal title is "Add Manager".

| Field | Notes |
|-------|-------|
| Inventory hostname | Unique Ansible host key, e.g. `wazuh.manager` |
| Kind | **docker** - manager runs in a container; **host** - manager is installed bare-metal |
| This machine (no SSH needed) | Checkbox - check if the manager is on the same host as RADAR |
| IP address | Required for remote managers |
| SSH user | System user Ansible connects as |
| SSH port | Default 22 |
| Container name | Docker container name, default `wazuh.manager` |
| Service name | docker-compose service key - leave blank to reuse container name |
| Sudo password | Optional - encrypted into `host_vars/<name>.yml`. If the vault is not yet unlocked you will be prompted. |

Submit button: **Add manager**.

### Adding an agent

Click **+ Agent**. The modal title is "Add Agent".

| Field | Notes |
|-------|-------|
| Inventory hostname | Unique Ansible host key, e.g. `edge.vm` |
| Agent mode | **SSH - remote host** or **Container - local Docker** |
| IP address | Required for SSH agents |
| SSH user | System user Ansible connects as |
| SSH port | Default 22 |
| Docker container name | Required for container agents, e.g. `agent.custom` |
| Sudo password | SSH agents only - label includes "(saved to host_vars/)" |

Submit button: **Add agent**.

### Credentials

**Set credential** / **Change credential** opens a modal titled "Set sudo password". It stores the `ansible_become_password` for a node, encrypted with `ansible-vault` into `host_vars/<name>.yml` (chmod 0600).

**Remove stored** appears when a credential already exists - clicking it deletes the `host_vars/<name>.yml` file.

### Health checks

The **Health** button on any card runs a targeted Ansible health-check playbook against that single node and shows per-check results in a panel directly below the card. Each entry shows a status (`ok` / `warn` / `fail`) and a detail message.

If a health check fails to reach the node at all, verify that the IP address and SSH port in the inventory card are correct, that the SSH key is loaded (see [SSH passphrase badge](#ssh-passphrase-badge)), and that the vault is unlocked if the node has a stored credential.

---

## Connectors

![RADAR GUI - Connectors page](/docs/website/assets/RADAR_GUI_Connectors.png "RADAR GUI Connectors page with credential fields and live test buttons for all external services")

The Connectors page manages credentials and URLs for every external service RADAR integrates with. Values are written to the `.env` file at the RADAR root. TLS certificates are stored under `.certs/`.

**Test all** in the top-right runs connectivity checks against all connectors in sequence.

Each connector card has a status indicator in the header: gray = not tested this session; green = last test passed; red = last test failed. A **Show** button appears next to password fields that already have a value stored. Each card has individual **Test** and **Save** buttons.

### OpenSearch / Wazuh Indexer

Subtitle: "Anomaly detection, log queries, context correlation"

| Field | Notes |
|-------|-------|
| URL | e.g. `https://192.168.0.28:9200` |
| User | OpenSearch admin username |
| Password | Secret - stored in `.env` |
| SSL verification | Checkbox. When enabled, a CA certificate file upload appears (.pem / .crt) |

Button: **Test connection**

### Wazuh API

Subtitle: "Agent management, rule queries, active response dispatch"

| Field | Notes |
|-------|-------|
| API URL | e.g. `https://192.168.0.28:55000` |
| Manager address | IP or hostname used internally by the AR pipeline |
| Auth user | Typically `wazuh-wui` |
| Auth password | Secret - stored in `.env` |

Button: **Test connection**

### OpenSearch Dashboards

Subtitle: "Dashboard access and anomaly detector management UI"

| Field | Notes |
|-------|-------|
| URL | e.g. `https://192.168.0.28` |
| User | Dashboard admin username |
| Password | Secret - stored in `.env` |
| SSL verification | Checkbox with CA certificate upload |

Button: **Test connection**

### SMTP / Email

Subtitle: "Tier-1+ email notifications to security team"

| Field | Notes |
|-------|-------|
| SMTP host | Mail server hostname, e.g. `smtp.office365.com` |
| Port | Default 587 |
| SMTP user | Sender account |
| SMTP password | Secret - stored in `.env` |
| Recipient (EMAIL_TO) | Destination address for alert emails |
| STARTTLS | Dropdown: **Enabled** (default) or **Disabled** |

Button: **Send test email** - attempts an SMTP login without sending a message.

### DECIPHER

Subtitle: "Tier-2+ incident case creation and investigation tracking"

| Field | Notes |
|-------|-------|
| Base URL | DECIPHER service URL |
| API token | Secret bearer token - stored in `.env` |
| SSL verification | Checkbox with CA certificate upload |
| Timeout (seconds) | Default 30 |

Button: **Test connection**

### Webhook

Subtitle: "OpenSearch monitor alert receiver - bridges AD monitors to the AR pipeline"

| Field | Notes |
|-------|-------|
| Webhook name | Monitor destination name registered in OpenSearch, e.g. `RADARWebhook` |
| Webhook URL | Full URL the monitor POSTs alerts to, e.g. `http://192.168.0.28:8080/notify` |

Button: **Send ping** - POSTs `{"ping": true}` to confirm reachability.

---

## Deploy

![RADAR GUI - Deploy page](/docs/website/assets/RADAR_GUI_Deploy.png "RADAR GUI Deploy page with scenario selection, mode options, and real-time Ansible output streaming")

The Deploy page has three tabs in a sub-navigation bar: **Build & deploy**, **Run Anomaly Detector**, and **Status**. An **Output** panel on the right streams Ansible output line by line. **Clear** and **Copy** buttons appear in the Output panel header.

### Build & deploy

Card title: "Build & deploy a scenario". Runs `build-radar.sh`.

| Field | Notes |
|-------|-------|
| Scenario | Scenario selection. |
| Manager location | **local - docker-compose.core.yml on this host** or **remote - SSH to a Wazuh manager/worker** |
| Agents location | **local - container agents via docker-compose** or **remote - SSH-managed agents** |
| Manager already exists | Checkbox, checked by default. Uncheck to bootstrap the manager from scratch. |
| SSH private key (optional) | Path on the server. Defaults to `~/.ssh/id_ed25519`. Only used when manager or agents are remote. |

Buttons: **Preview command**, **Deploy**, **Stop streaming**.

### Run Anomaly Detector

Card title: "Run Anomaly Detector". Runs `run-radar.sh`. Only Hybrid and Anomaly ML scenarios appear in the dropdown - Signature scenarios do not use the OpenSearch anomaly detector.

| Field | Notes |
|-------|-------|
| Scenario | Hybrid and Anomaly ML only |
| Ingest training dataset | Ingests synthetic training data into the Wazuh indexer to pre-populate the model baseline |

Buttons: **Preview command**, **Run**, **Stop streaming**.

### Status

Card title: "Infrastructure health check". Runs `health-radar.sh`.

| Field | Notes |
|-------|-------|
| Manager location | local or remote |
| Agents location | local or remote |
| Scenario filter | **all (every bound scenario)** or a specific scenario |
| SSH private key (optional) | Path to SSH key for remote nodes |

Buttons: **Preview command**, **Run health check**, **Stop streaming**.

---

## Vault and credentials

### What the vault is

RADAR uses Ansible Vault to encrypt sudo passwords stored in `host_vars/`. A single vault password covers all remote node credentials. The vault password is never written to disk - it is held in a short-lived server-side session tied to the `radar_vault_sid` cookie for the duration of your browser session. The session is lost when the Flask server restarts, the vault needs to be unlocked again after any restart.

### Vault badge

The vault badge appears in the top-right corner of every page:

| Badge state | Meaning |
|-------------|---------|
| Not shown | No encrypted credentials exist yet |
| Vault locked (amber) | Encrypted credentials exist but the vault is not unlocked in this session |
| Vault unlocked (green) | The vault password is active in this session |

Clicking the badge opens the vault unlock prompt.

### Setting up the vault for the first time

If no `host_vars/*.yml` files are encrypted yet:

1. Go to **Infrastructure** - a vault banner appears with a **Create vault** button.
2. Click **Create vault**. A modal titled "Set vault password" appears - enter and confirm a password.
3. Click **Set vault password**. The vault is now active for this session. Store the password securely - there is no recovery path.

### Unlocking the vault

If encrypted credentials already exist and the vault shows as locked:

1. Click the vault badge or **Unlock vault** in the Infrastructure banner.
2. Enter the vault password. RADAR verifies it against an existing encrypted file.

The session stays unlocked until the server restarts.

### SSH passphrase badge 

If your SSH private key has a passphrase, a separate SSH key badge appears next to the vault badge. This passphrase is required whenever Ansible connects to remote nodes - if it is not set, Ansible will hang or fail at the SSH handshake for any remote manager or agent. Click the badge to store or clear the passphrase. RADAR spawns a temporary `ssh-agent` process for the duration of each Ansible run, loads the key into it via `ssh-add`, and kills the agent when the run completes.

The SSH passphrase is separate from the vault password. You need to set both if your deployment uses remote nodes with a passphrase-protected key and stored sudo credentials.

---

## Troubleshooting

### Connector test fails

Common causes and fixes:

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Connection refused | Wrong port or service not running | Verify the URL and port; confirm the service is up |
| SSL certificate error | Self-signed cert without CA upload | Enable SSL verification and upload the CA `.pem` / `.crt` file |
| 401 Unauthorized | Wrong credentials | Re-enter and save the username and password, then test again |
| Timeout | Firewall blocking the connection | Check network rules between the RADAR host and the target service |

### Run Anomaly Detector tab does not show my scenario

The **Run Anomaly Detector** tab only lists Hybrid and Anomaly ML scenarios. Signature scenarios (such as GeoIP Detection) do not use an OpenSearch anomaly detector and will never appear in this dropdown. Run `build-radar.sh` via the Build & deploy tab instead.

### Saved changes on RADAR Scenarios are lost after a server restart

The GUI writes directly to `ar.yaml` on every **Save**. If `ar.yaml` is also edited manually on disk, the file on disk takes precedence on startup. Avoid concurrent manual edits to `ar.yaml` while the GUI is running.

### Health check cannot reach a node

Verify the following in order: the IP address and SSH port in the Infrastructure card are correct; the SSH private key path on the Deploy / Status form matches the key authorised on the remote node; the SSH passphrase badge is set if the key is passphrase-protected; the vault is unlocked if the node has a stored credential.
