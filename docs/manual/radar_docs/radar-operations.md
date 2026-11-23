# Operations

Everything the GUI does is also available from the command line. `radar.sh` is
the single front door.

```bash
./radar.sh gui                                          # start the Web GUI
./radar.sh gui-url                                      # print the running GUI's login URL
./radar.sh build <scenario>                             # = sudo ./build-radar.sh
./radar.sh run <scenario> [--ingest true]               # = ./run-radar.sh
./radar.sh health [--scenario …] [--agent-name …]       # = ./health-radar.sh
./radar.sh stop [--purge]                               # = ./stop-radar.sh
sudo ./radar.sh mint-token <group>[,<group>…] [minutes] # mint new token
sudo ./radar.sh enrollment open [--minutes N] | close | status
./radar.sh rotate-credentials                      # new indexer and API passwords
./radar.sh repair-permissions                      # fix file permissions left by older builds
```

On first use it creates a virtualenv and installs the GUI's dependencies; after
that it reuses them unless `gui/requirements.txt` changes.

Valid scenarios: `suspicious_login`, `geoip_detection`, `log_volume`,
`scanning_detection`, `linux_resource_utilization`.

---

## Deploy a scenario

```bash
sudo ./build-radar.sh <scenario>
sudo ./build-radar.sh --core-only
```

Brings up the core stack if needed, then pushes the scenario's decoders, rules,
active responses, enrichment, and group config to the manager over the Wazuh
REST API. `--core-only` gives you plain Wazuh with no scenario applied.

Needs `sudo`: the bind mounts under `/srv/wazuh/` and the firewall rule that
closes port 1515.

**Undeploy** is not wired into `radar.sh`. Use the GUI (Scenario Management →
Undeploy scenario), or call the script directly:

```bash
sudo ./radar_deploy/manager-undo-scenario.sh <scenario>
```

---

## Run the anomaly detector

```bash
./run-radar.sh <scenario> [--ingest true|false]
```

Three stages, in order: optionally ingest a training dataset, create or reuse
the OpenSearch detector (prints `DET_ID`), then create the monitor and its
webhook destination, or update an existing monitor whose configuration changed
(prints `MON_ID`). Each stage runs in the `radar-cli`
container, which is built on the fly.

Only scenarios with an ML component apply. `--ingest true` is needed the first
time, before real traffic exists.

`suspicious_login` runs `off_hours.py` instead: it deploys the off-hours ingest
pipeline, marks the archived history after the optional ingest, then creates or
updates the rule-mode monitor and the model-mode detector and monitor. See
[Off-hours activity](./radar-scenarios/off-hours-activity.md#commands).

---

## Agent enrollment

```bash
sudo ./radar.sh mint-token <group>[,<group>…] [expiry_minutes]  # default 60
sudo ./radar.sh enrollment open [--minutes N]                  # default 30
sudo ./radar.sh enrollment close
sudo ./radar.sh enrollment status
```

Minting a token with `sudo` already opens the enrollment window for the
token's own lifetime (without root it only prints a note and the window stays
closed), so the `enrollment` subcommands are only for opening, closing, or
checking it independently — for instance to onboard several endpoints in one
window, or to close it early.

All three need `sudo`: they read or change the host firewall, and without root
`status` cannot read the rule and always reports `OPEN`. `status` reports
`OPEN`/`CLOSED` plus the auto-close timer's PID.

A token is revoked when it expires. If that is missed, for example because the
host was rebooted, the next health check or build revokes it.

Then, on the endpoint, from inside the `radar-agent` folder copied there:

```bash
sudo ./bootstrap-agent.sh --manager <address> --token <token> \
     --group default --group <scenario> [--agent-name <name>] \
     [--allow-service <name>]
```

Pass the groups the token was minted for: `suspicious_login` and
`geoip_detection` also need `--group radar_shared`, which carries their
`auth.log` shipping.

For `log_volume` and `linux_resource_utilization`, `--allow-service` (repeatable
or comma-separated) lists the services `terminate_service.sh` may stop on this
endpoint. Without it, no service can be stopped there. The scenario's
`terminable_services` in `ar.yaml` must list the service too; the shipped
`linux_resource_utilization` block has no such key, so add it there. See [Mitigations](radar-tuning.md#mitigations).

To remove the agent from an endpoint, run `sudo ./uninstall-agent.sh
[--purge-data]` from the same folder.

Manager-side agent operations:

```bash
./radar_deploy/manager-assign-agent-group.sh   --scenario <s> --agent-ip <ip>
./radar_deploy/manager-unassign-agent-group.sh --scenario <s> --agent-ip <ip>
./radar_deploy/manager-deregister-agent.sh     --agent-name <name>
```

---

## Health check

```bash
./health-radar.sh [--scenario <name|all>] [--agent-name name1,name2]
```

Read-only, with one exception: an enrollment token that has outlived its expiry
is revoked, which restarts the Wazuh manager processes. Three groups of checks
run in order:

| Group | Covers |
|-------|--------|
| **Manager (filesystem/container)** | Manager container up; decoders, rules, lists, AR scripts, and enrichment artifacts present for the selected scenario(s) |
| **Manager (API)** | Wazuh management API, OpenSearch, and the alert webhook all reachable over HTTP |
| **Agents** *(only with `--agent-name`)* | Each named agent's status and group membership as the manager sees it |

Each line is `OK`, `WARN`, or `FAIL`. Treat `WARN` as "deployed but idle" —
typically a scenario whose detector has not run yet. `FAIL` means the component
is missing or unreachable.

Same thing in the GUI: Deployment → **Status**.

---

## Credentials

The first deployment generates unique passwords for the indexer, the dashboard,
and the Wazuh API, and stores them in `.env`. To replace them on a running
deployment:

```bash
sudo ./radar.sh rotate-credentials
```

The containers restart with the new passwords; restart the GUI afterwards. Log
in to the Wazuh dashboard as `admin` with the new `OS_PASS`. This command only
manages a stack RADAR deployed itself, not an existing Wazuh installation.

---

## Stop and tear down

```bash
./stop-radar.sh            # stop containers, keep data on disk
./stop-radar.sh --purge    # also delete the indexer data and dashboard volumes
```

`--purge` is not reversible. It removes only the core stack's named Docker
volumes (indices and dashboard settings); the manager's data under `/srv/wazuh/`
(rules, agent keys, logs) and the certificates under `config/` stay. Without
`--purge`, everything comes back when you next run `build-radar.sh`.

The GUI's Deployment → **Teardown** does the same. Its **Delete all data**
checkbox goes further than `--purge`: it also deletes the manager's host
directories listed in `volumes.yml` and marks every scenario as not deployed.
Certificates are kept in both cases.

---

## Where to look when something fires

Paths below are given as the manager container sees them. With the shipped
`volumes.yml`, `/var/ossec/logs/…` is `/srv/wazuh/manager/logs/…` on the host,
so you can tail them without entering the container.

| What | Where |
|------|-------|
| Active response decisions, mitigations and audit entries | `/var/ossec/logs/active-responses.log` |
| Wazuh manager log | `/var/ossec/logs/ossec.log` |
| Enriched auth / web logs | `/var/ossec/logs/radar/enriched_auth.log`, `enriched_web_access.log` |
| Detector results, alerts | Wazuh dashboard, or the `opensearch-ad-plugin-result-*` indices |
| Webhook service | `docker logs ad-webhook` |

---

## Testing detections

The RADAR test framework generates attack traffic against an onboarded endpoint
so you can confirm a scenario end to end without waiting for a real event.
Simulation scripts live under `radar-test-framework/simulate/scenarios/` and run
directly on the target endpoint.