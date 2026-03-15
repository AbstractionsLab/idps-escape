# RADAR Health Check

The RADAR Health Check is a lightweight Ansible-based tool for validating that a RADAR deployment is correctly configured and all required components are present and operational. It is invoked through a single entry point (`health-radar.sh`) and produces a consolidated summary report at the end of execution.

## Overview

The health check runs two sequential Ansible plays against the target environment: one targeting the Wazuh manager, one targeting the configured agent endpoints. Each play accumulates check results into an in-memory report list and writes its summary to a timestamped file on the controller. After both plays complete, `health-radar.sh` concatenates and prints all summary files so the full report is always visible as the final output — regardless of how many agents were checked or how long the playbook ran.

Summary lines are prefixed with `OK`, `WARN`, or `FAIL`. Only `WARN` and `FAIL` lines appear in the summary box body; the `OK` count is shown in the footer. This keeps the report signal-focused and scannable.

## Directory structure

```
radar/roles/radar_health/
├── health-check.yml          # Top-level Ansible playbook (2 plays)
├── tasks/
│   ├── main.yml              # Manager play orchestrator + summary writer
│   ├── check_manager.yml     # 7 manager check groups
│   └── check_agents.yml      # 4 agent check groups
```

The entry point script lives alongside the other RADAR scripts:

```
radar/
└── health-radar.sh           # Entry point
```

## Usage

```bash
./health-radar.sh --manager <local|remote> --agent <local|remote> \
                  --scenario <scenario|all> [--ssh-key <path>]
```

| Argument | Required | Values | Default |
|----------|----------|--------|---------|
| `--manager` | Yes | `local`, `remote` | — |
| `--agent` | Yes | `local`, `remote` | — |
| `--scenario` | No | `log_volume`, `geoip_detection`, `suspicious_login`, `all` | `all` |
| `--ssh-key` | No | path to private key | `~/.ssh/id_ed25519` |

**Example — remote manager, remote agents, log_volume scenario only:**
```bash
./health-radar.sh --manager remote --agent remote --scenario log_volume
```

**Example — local manager and agents, all scenarios:**
```bash
./health-radar.sh --manager local --agent local
```

The script passes a timestamped `summary_file` path as an extra variable to the playbook. After `ansible-playbook` exits the script prints all summary files to stdout, making the consolidated report the last thing visible in the terminal.

## Manager checks (`check_manager.yml`)

| Group | What is verified |
|-------|-----------------|
| **Containers / service** | `wazuh.manager` and `ad-webhook` containers running (docker modes); Wazuh service process count (host_remote) |
| **Key files** | Existence and `wazuh` group ownership of `radar_ar.py`, `ar.yaml`, `active_responses.env`, `ossec.conf`, `agent.conf` |
| **Decoders and rules** | Per-scenario decoder and rule files present, `wazuh` group ownership; `log_volume` notes the opensearch_ad webhook decoder is used instead of a dedicated file |
| **Python dependencies** | `python3`, `pyyaml`, `requests` available inside the manager container or on the host |
| **Connectivity** | OpenSearch cluster health (green/yellow/red); Wazuh API JWT authentication; Webhook endpoint reachable |
| **log_volume specific** | Filebeat archives pipeline patch present; `radar-log-volume` index template present in OpenSearch |
| **geoip_detection specific** | `whitelist_countries` list file present with `wazuh` group ownership |

## Agent checks (`check_agents.yml`)

| Group | What is verified |
|-------|-----------------|
| **Wazuh agent service** | `wazuh-agentd` process running (SSH and container modes) |
| **RADAR helper** | `radar-helper.py` present at `/opt/radar/`; `radar-helper.service` active; `maxminddb` importable in `/opt/radar/venv` |
| **GeoIP databases** | `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` present under `/usr/share/GeoIP/` |
| **AR scripts** | At least one `.sh` active response script present in `/var/ossec/active-response/bin/` |

## Summary report format

Only FAIL and WARN lines appear in the summary body. If all checks pass the body shows `All checks passed.`

## Deployment modes

| `--manager` | `--agent` | Behaviour |
|-------------|-----------|-----------|
| `local` | `local` | Manager via `docker exec wazuh.manager`; agents via `docker exec` |
| `local` | `remote` | Manager via `docker exec`; agents via SSH |
| `remote` | `remote` | Manager and agents via SSH |

The `--manager remote` mode requires `wazuh_manager_ssh` to be defined in `inventory.yaml`. The `--agent remote` mode requires `wazuh_agents_ssh` entries.