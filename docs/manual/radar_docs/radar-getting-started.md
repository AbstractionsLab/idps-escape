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

Open the login URL printed in the terminal (`http://127.0.0.1:5000/?token=…`),
go to **Connectors**, fill in each card.

The GUI only accepts connections from the machine it runs on. Open it from a
browser on your own workstation, not on the RADAR host: open an SSH tunnel
first, then use the same URL. The README's
[security assumptions](/radar/README.md#security-assumptions-and-recommendations)
explain why.

```bash
ssh -L 5000:127.0.0.1:5000 <user>@<radar-host>
```

Leave the indexer, dashboard, and Wazuh API passwords empty: the first
deployment generates unique ones and saves them in `.env`.

`.env` can be edited directly instead of `env.example`. `env.example` documents every key.

---

## 2. Deploy a scenario

Pick one:

| Scenario | Detects |
|----------|---------|
| [`suspicious_login`](./radar-scenarios/suspicious_login_explained.md) | Brute force and impossible travel |
| [`geoip_detection`](./radar-scenarios/geoip_detection_explained.md) | Logins from non-approved countries |
| [`log_volume`](./radar-scenarios/log_volume_explained.md) | Unusual spikes in log generation |
| [`scanning_detection`](./radar-scenarios/scanning_detection_explained.md) | Web-layer scanning and vulnerability probes |
| [`linux_resource_utilization`](./radar-scenarios/linux_resource_utilization_explained.md) | Anomalous CPU/memory utilization on Linux endpoints |

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

If an existing deployment still uses the stock Wazuh passwords, the build warns
you. Replace them with `sudo ./radar.sh rotate-credentials`.

---

## 3. Onboard an endpoint

Three steps: mint a token on the manager, run the bootstrap script on the
endpoint, confirm the group from the manager.

### Mint a token

**GUI:** Deployment → Agent Management → **Onboard agent**. Pick the scenario,
set an expiry, click **Mint token**. Copy the printed command.

**CLI:**

```bash
sudo ./radar.sh mint-token default,suspicious_login,radar_shared 60
```

Include `radar_shared` for `suspicious_login` and `geoip_detection`: their
`auth.log` shipping is configured in that group. The other scenarios need only
`default,<scenario>`. The GUI adds it automatically.

Both print a ready-to-run `bootstrap-agent.sh` command and open the port-1515
enrollment window for the token's lifetime. Opening the window needs root:
without `sudo`, the CLI only prints a note and port 1515 stays closed.

The token is a one-time shared password. It is revoked automatically when it
expires, even if the manager or the host restarts in the meantime.

### Run the bootstrap script on the endpoint

Copy the whole `radar/radar-agent/` folder to the endpoint and run the script
from inside it. The folder holds the scripts and files the bootstrap installs,
so the script alone is not enough:

```bash
scp -r radar/radar-agent <user>@<endpoint>:~/
# on the endpoint
cd ~/radar-agent
sudo ./bootstrap-agent.sh --manager <address> --token <token> \
     --group default --group suspicious_login --group radar_shared
```

Pass the same groups the token was minted for (`--group` also accepts a
comma-separated list).

The script installs the agent package, enrolls with the token, assigns the
groups, and starts the service. Re-running it on an already-enrolled endpoint
is safe. To remove the agent later, run `sudo ./uninstall-agent.sh` from the
same folder.

> **Already using Ansible, Puppet, Intune, or SCCM?** Wrap
> `bootstrap-agent.sh` — it is the supported integration point. As an Ansible
> task:
>
> ```yaml
> - name: Onboard this host into RADAR
>   ansible.builtin.command:
>     cmd: >
>       ./bootstrap-agent.sh --manager {{ radar_manager }}
>       --token {{ radar_token }} --group {{ radar_groups }}
>     chdir: <path to the radar-agent folder on the endpoint>
>     creates: /var/ossec/etc/client.keys
> ```
>
> `radar_groups` is the comma-separated group list the token was minted for,
> for example `default,suspicious_login,radar_shared`.

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

Only for scenarios that use ML: `log_volume`, `linux_resource_utilization` and
`suspicious_login`. For `suspicious_login` this step is optional: it sets up
off-hours activity detection against the working hours declared in
`config.yaml` (see [Off-hours activity](./radar-scenarios/off-hours-activity.md)),
and RADAR combines those alerts with the scenario's signature alerts for the
same user. Without it, `suspicious_login` scores signature alerts alone. Skip this step for pure signature scenarios.

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

RADAR ships with automatic mitigation **disabled** for the baseline scenario and
`scanning_detection`, but **enabled** (`allow_mitigation: true` in `ar.yaml`)
for `geoip_detection`, `suspicious_login`, `log_volume` and
`linux_resource_utilization`. With the shipped settings, `geoip_detection` runs
`firewall-drop` at T2. Turn **Allow automatic mitigation execution** off for
these scenarios until you have checked their tiering. See [Tuning](./radar-tuning.md#tuning-workflow).

---

## 7. Secure the deployment

Before using RADAR outside a lab, read [Security assumptions and recommendations](/radar/README.md#security-assumptions-and-recommendations):
which ports to restrict with firewall rules, and which settings to review for
your site.

---

## Working with an existing Wazuh installation

RADAR can enhance an existing manager rather than bootstrapping a new one. Three
things need to match the existing setup:

- **[Infrastructure](./radar-gui-user-manual.md#infrastructure)** — register the
  existing manager, indexer, dashboard, and webhook with their real addresses
  and container names. RADAR resolves between them using what is registered
  here, falling back to the container name if a declared address is not
  reachable from another component.
- **Connectors** — enter the existing installation's own indexer and Wazuh API
  credentials. RADAR generates passwords only for a stack it deploys itself.
- **`volumes.yml`** — the bind mounts RADAR uses to reach manager files. If the
  manager uses different host paths, update the left side of each mapping. For
  named Docker volumes, use the host paths shown by `docker inspect <manager-container>`.
  These container paths must be bind-mounted or deployment fails validation:

  | Container path | Used for |
  |---|---|
  | `/var/ossec/etc` | `ossec.conf`, decoders, rules, CDB lists |
  | `/var/ossec/logs` | Reading `active-responses.log` and enrichment output from the host |
  | `/var/ossec/integrations` | Enrichment integration scripts |
  | `/var/ossec/active-response/bin` | `radar_ar.py` and the mitigation scripts |
  | `/etc/filebeat` | Filebeat configuration |
  | `/usr/share/filebeat/module/wazuh/archives/ingest/pipeline.json` | Archive ingest pipeline. `build-radar.sh` aborts if it is missing when it brings up its own stack. With an existing manager it only warns, and `suspicious_login` off-hours flagging then does not work |
- **Existing agents** — enroll them into the scenario group with
  [Group Management](./radar-gui-user-manual.md#group-management) rather than
  re-bootstrapping.