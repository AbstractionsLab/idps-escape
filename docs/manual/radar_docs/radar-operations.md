# Operations

Everything the GUI does is also available from the command line. `radar.sh` is
the single front door.

```bash
./radar.sh gui                                          # start the Web GUI
./radar.sh build <scenario>                             # = sudo ./build-radar.sh
./radar.sh run <scenario> [--ingest true]               # = ./run-radar.sh
./radar.sh health [--scenario …] [--agent-name …]       # = ./health-radar.sh
./radar.sh stop [--purge]                               # = ./stop-radar.sh
./radar.sh mint-token <group>[,<group>…] [minutes]
./radar.sh enrollment open [--minutes N] | close | status
```

On first use it creates a virtualenv and installs the GUI's dependencies; after
that it reuses them unless `gui/requirements.txt` changes.

Valid scenarios: `suspicious_login`, `geoip_detection`, `log_volume`,
`scanning_detection`.

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
the OpenSearch detector (prints `DET_ID`), then create or reuse the monitor and
its webhook destination (prints `MON_ID`). Each stage runs in the `radar-cli`
container, which is built on the fly.

Only scenarios with an ML component apply. `--ingest true` is needed the first
time, before real traffic exists.

---

## Agent enrollment

```bash
./radar.sh mint-token <group>[,<group>…] [expiry_minutes]     # default 60
sudo ./radar.sh enrollment open [--minutes N]                  # default 30
sudo ./radar.sh enrollment close
./radar.sh enrollment status
```

Minting a token already opens the enrollment window for the token's own
lifetime, so the `enrollment` subcommands are only for opening, closing, or
checking it independently — for instance to onboard several endpoints in one
window, or to close it early.

`open` and `close` need `sudo` (they touch the host firewall); `status` does not
and reports `OPEN`/`CLOSED` plus the auto-close timer's PID.

Then, on the endpoint:

```bash
sudo ./bootstrap-agent.sh --manager <address> --token <token> \
     --group default --group <scenario> [--agent-name <name>]
```

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

Read-only — it never restarts services or fixes anything. Three groups of
checks run in order:

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

## Stop and tear down

```bash
./stop-radar.sh            # stop containers, keep data on disk
./stop-radar.sh --purge    # also delete volumes: indices, dashboards, enrollment state, certs
```

`--purge` is not reversible. Without it, everything comes back when you next
run `build-radar.sh`.

Same thing in the GUI: Deployment → **Teardown**, where `--purge` is the
**Delete all data** checkbox.

---

## Where to look when something fires

Paths below are given as the manager container sees them. With the shipped
`volumes.yml`, `/var/ossec/logs/…` is `/srv/wazuh/manager/logs/…` on the host,
so you can tail them without entering the container.

| What | Where |
|------|-------|
| Active response decisions and mitigations | `/var/ossec/logs/active-responses.log` |
| RADAR AR audit entries | `/var/ossec/logs/radar/radar_ar_audit.log` |
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