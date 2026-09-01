# Getting started

This guide takes a clean Linux host to a fully operational RADAR deployment:
detection running against a monitored endpoint, with automated response
configured and verified. It is written for a security engineer or system
administrator carrying out a first-time installation.

The procedure has six stages, and should be followed in order. Steps that can be
performed either through the RADAR web interface or from the command line are
given both ways; the web interface is the recommended path for a first
deployment, since it validates each external service connection as it is
configured.

| Stage | Outcome |
|-------|---------|
| 1. [Configure connectors](#1-configure-connectors) | RADAR can reach OpenSearch, the Wazuh API, the dashboard, SMTP and, where required, MaxMind and DECIPHER |
| 2. [Deploy a scenario](#2-deploy-a-scenario) | The Wazuh stack is running with one detection use case applied to the manager |
| 3. [Onboard an endpoint](#3-onboard-an-endpoint) | A monitored host is enrolled, assigned to the scenario's group, and shipping logs |
| 4. [Start the anomaly detector](#4-start-the-anomaly-detector) | ML-based scenarios have a trained detector and an alerting monitor |
| 5. [Verify](#5-verify) | Every component reports healthy |
| 6. [Tune the response](#6-tune-the-response) | Risk thresholds and mitigations reflect the deployment's environment and risk appetite |

Terminology, an overview of the detection pipeline, and the scenario catalogue
are in the [documentation index](./README.md).

---

## Prerequisites

**Manager host**

- Recent GNU/Linux, Ubuntu 22.04+ recommended
- Docker Engine 20.10+ and Docker Compose
- `sudo` access
- Enough disk for the indexer under `/srv/wazuh/`

```bash
docker --version        # 20.10 or newer
docker compose version
```

**Endpoints**

- GNU/Linux, with a user that has `sudo`
- Reachable from the manager on the Wazuh agent ports

The Wazuh agent is not installed or enrolled by hand — [`bootstrap-agent.sh`](#3-onboard-an-endpoint) performs both steps.

**Required credentials**

| For | What |
|-----|------|
| OpenSearch / Dashboards | URL, user, password |
| Wazuh API | URL, user, password, and the manager's reachable address |
| Email alerts | SMTP host, port, user, password, recipient |
| `suspicious_login`, `geoip_detection` | A free [MaxMind GeoLite2](https://www.maxmind.com/en/geolite2/signup) license key |
| CTI enrichment and case creation *(optional)* | A running [DECIPHER](https://github.com/AbstractionsLab/satrap-dl/tree/main/decipher) instance |

Wazuh manager and agent version `4.14.1` is targeted and handled automatically.
The OpenSearch anomaly-detection plugin is installed as part of deployment.

---

## 1. Configure connectors

```bash
cd radar
cp env.example .env
./radar.sh gui
```

Open `http://localhost:5000`, go to **Connectors**, fill in each card.

`.env` can be edited directly instead of `env.example`. `env.example` documents every key.

---

## 2. Deploy a scenario

Pick one:

| Scenario | Detects |
|----------|---------|
| [`suspicious_login`](./radar-scenarios/suspicious_login.md) | Brute force and impossible travel |
| [`geoip_detection`](./radar-scenarios/geoip_detection.md) | Logins from non-approved countries |
| [`log_volume`](./radar-scenarios/log_volume.md) | Unusual spikes in log generation |
| [`scanning_detection`](./radar-scenarios/scanning_detection.md) | Web-layer scanning and vulnerability probes |

**GUI:** Deployment → Scenario Management → **Deploy scenario**.

**CLI:**

```bash
sudo ./build-radar.sh suspicious_login
```

This brings up the core stack if it is not already running, then pushes the
scenario's decoders, rules, active responses, and enrichment to the manager. Use
`--core-only` to bring up plain Wazuh with no scenario applied.

`sudo` is needed for the bind mounts under `/srv/wazuh/`, and to apply the
firewall rule that closes agent-enrollment port 1515 by default.

---

## 3. Onboard an endpoint

Three steps: mint a token on the manager, run the bootstrap script on the
endpoint, confirm the group from the manager.

### Mint a token

**GUI:** Deployment → Agent Management → **Onboard agent**. Pick the scenario,
set an expiry, click **Mint token**. Copy the printed command.

**CLI:**

```bash
./radar.sh mint-token default,suspicious_login,radar_shared 60
```

Include `radar_shared` for `suspicious_login` and `geoip_detection`; the other
two scenarios need only `default,<scenario>`. The GUI adds it automatically.

Both print a ready-to-run `bootstrap-agent.sh` command and open the port-1515
enrollment window for the token's lifetime.

The token is a one-time shared password. It is revoked automatically when it
expires — a background job overwrites it and restarts Wazuh.

### Run the bootstrap script on the endpoint

Since this runs as root on a monitored machine, do not pipe a download into a
shell. Download, verify, then run:

```bash
curl -fsSL <release-url>/bootstrap-agent.sh -o bootstrap-agent.sh
echo "<sha256sum>  bootstrap-agent.sh" | sha256sum -c
sudo ./bootstrap-agent.sh --manager <address> --token <token> \
     --group default --group suspicious_login
```

Use the checksum published alongside the release in question on our [GitHub Releases page](https://github.com/AbstractionsLab/idps-escape/releases). The script installs the agent
package, enrolls with the token, assigns the groups, and starts the service.
Re-running it on an already-enrolled endpoint is safe.

> **Already using Ansible, Puppet, Intune, or SCCM?** Wrap
> `bootstrap-agent.sh` — it is the supported integration point. As an Ansible
> task:
>
> ```yaml
> - name: Onboard this host into RADAR
>   ansible.builtin.command:
>     cmd: >
>       ./bootstrap-agent.sh --manager {{ radar_manager }}
>       --token {{ radar_token }} --group default --group {{ radar_scenario }}
>     creates: /var/ossec/etc/client.keys
> ```

### Confirm the group

**GUI:** Deployment → Group Management → **Assign group**.

**CLI:**

```bash
./radar_deploy/manager-assign-agent-group.sh --scenario suspicious_login --agent-ip <ip>
```

Only needed if the endpoint was already enrolled before running the bootstrap
script against it — group assignment at enrollment time applies to genuinely
new agents only.

---

## 4. Start the anomaly detector

Only for scenarios that use ML (`log_volume`, and `suspicious_login` in hybrid
mode). Skip it for pure signature scenarios.

**GUI:** Deployment → Anomaly Detector.

**CLI:**

```bash
./radar.sh run log_volume --ingest true
```

`--ingest true` loads a synthetic training dataset so the detector has a
baseline. It is used only in testing environment.

---

## 5. Verify

**GUI:** Deployment → Status.

**CLI:**

```bash
./radar.sh health --scenario suspicious_login --agent-name edge-vm-01
```

Every check is marked `OK`, `WARN`, or `FAIL`. See
[Operations](./radar-operations.md#health-check) for how to read the report.

---

## 6. Tune the response

RADAR ships with automatic mitigation **disabled** for the baseline scenario. See [Tuning](./radar-tuning.md).

---

## Working with an existing Wazuh installation

RADAR can enhance an existing manager rather than bootstrapping a new one. Two
things need to match the existing setup:

- **`volumes.yml`** — the bind mounts RADAR uses to reach manager files. If the
  manager uses different host paths, update the left side of each mapping.
  These container paths must be bind-mounted or deployment fails validation:

  | Container path | Used for |
  |---|---|
  | `/var/ossec/etc` | `ossec.conf`, decoders, rules, CDB lists |
  | `/var/ossec/logs` | Reading `active-responses.log` and enrichment output from the host |
  | `/var/ossec/active-response/bin` | `radar_ar.py` and the mitigation scripts |
  | `/etc/filebeat` | Filebeat configuration |
  | `/usr/share/filebeat/module/wazuh/archives/ingest/pipeline.json` | Archive ingest pipeline — `build-radar.sh` aborts if this one is missing |
- **Existing agents** — enroll them into the scenario group with
  [Group Management](./radar-gui-user-manual.md#group-management) rather than
  re-bootstrapping.

> In this release this feature is not supported.