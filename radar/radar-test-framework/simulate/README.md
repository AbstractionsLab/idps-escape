# RADAR Scenario Simulation 

The RADAR simulation provides automated, agent-realistic attack
simulation for validating RADAR detection scenarios end-to-end. Rather than
injecting synthetic documents directly into OpenSearch, it generates real
artefacts at the agent level — writing SSH log entries or growing the
filesystem — so that the full Wazuh decoder, rule, and active response
pipeline is exercised under conditions identical to production.

## Supported scenarios

| Scenario | Method | Target rules |
|----------|--------|--------------|
| `geoip_detection` | SSH success log entry from non-whitelisted IP | 100900, 100901 |
| `suspicious_login` | SSH failure burst + success from diverse IPs | 210012, 210013, 210020, 210021 |
| `log_volume` | Exponential filesystem growth in monitored directory | 100309 |

## Repository layout
```
radar-test-framework/
  simulate/
    scenarios/
      common.py               # shared utilities
      geoip_detection.py      # geoip simulation script
      suspicious_login.py     # suspicious login simulation script
      log_volume.py           # log volume simulation script

simulate-radar.sh             # entry point

roles/wazuh_agent/
  playbooks/
    simulate.yml              # Ansible playbook for remote agent execution
```

## Prerequisites

- RADAR built and running for the target scenario (`build-radar.sh` completed)
- Python 3 with PyYAML installed on the agent endpoint
- For local mode: Docker running with the agent container active
- For remote mode:
  - Ansible 2.15+ on the controller
  - SSH access to remote agents with sudo privileges
  - Ansible Vault credentials configured in `host_vars/`
  - Remote agents registered under `wazuh_agents_ssh` in `inventory.yaml`

## Configuration

All simulation parameters are defined in `radar/config.yaml` under each scenario's optional `simulate:` section. No values are hardcoded in the scripts.

**Example configuration structure in `radar/config.yaml`:**

```yaml
scenarios:
  log_volume:
    # ... detector/monitor configuration ...
    simulate:
      timezone_offset: "+01:00"     # adjust to your agent timezone
      hostname: "edge.vm"           # must match your agent hostname
      target_dir: "/var/log"
      spike_filename: "ratf_log_volume_spike.log"
      steps: 10
      start_bytes: 268435456
      growth_factor: 1.5
      cleanup_minutes: 5             # set to 0 to disable auto-cleanup

  suspicious_login:
    # ... detector/monitor configuration ...
    simulate:
      timezone_offset: "+01:00"
      hostname: "edge.vm"
      log_path: "/var/log/auth.log"
      ip_pool:
        - "8.8.8.8"
        - "1.0.136.99"
        # ... (must contain ≥5 entries)

  geoip_detection:
    simulate:
      timezone_offset: "+01:00"
      hostname: "edge.vm"
      log_path: "/var/log/auth.log"
      # ... (other params)
```

For complete parameter documentation and examples, see [Run RADAR documentation](../../../docs/manual/radar_docs/radar-run-ad.md) and [Getting Started guide](../../../docs/manual/radar_docs/radar-getting-started.md).

## Usage
```bash
./simulate-radar.sh <scenario> --agent <local|remote> [--ssh-key <path>]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `scenario` | Yes | One of: `suspicious_login`, `geoip_detection`, `log_volume` |
| `--agent` | Yes | `local` (docker exec) or `remote` (Ansible over SSH) |
| `--ssh-key` | No | Path to SSH private key (default: `~/.ssh/id_ed25519`) |

### Examples

Run geoip detection simulation on a local container agent:
```bash
./simulate-radar.sh geoip_detection --agent local
```

Run suspicious login simulation on remote SSH agents:
```bash
./simulate-radar.sh suspicious_login --agent remote --ssh-key ~/.ssh/id_ed25519
```

Run log volume simulation on remote SSH agents:
```bash
./simulate-radar.sh log_volume --agent remote --ssh-key ~/.ssh/id_ed25519
```

## Execution paths

### Local mode (`--agent local`)

1. Resolves `container_name` from `config.yaml` for the selected scenario
2. Copies scenario scripts into the container at `/tmp/ratf-simulate/scenarios/`
3. Executes the scenario script inside the container via `docker exec`
4. Exits with the docker exec return code

### Remote mode (`--agent remote`)

1. Starts or reuses an `ssh-agent` session and loads the SSH key
2. Runs `simulate.yml` via `ansible-playbook` against `wazuh_agents_ssh`
3. Ansible copies scenario scripts to `/tmp/ratf-simulate/scenarios/` on the agent
4. Ansible executes the scenario script and prints stdout
5. Ansible removes `/tmp/ratf-simulate` on the agent unconditionally after completion
6. Exits with the ansible-playbook return code

## Cleanup behaviour

| Scenario | What is generated | Cleanup |
|----------|-------------------|---------|
| `geoip_detection` | Entry appended to `/var/log/auth.log` | Not removed; persists in auth log |
| `suspicious_login` | Entries appended to `/var/log/auth.log` | Not removed; persists in auth log |
| `log_volume` | Spike file created in `target_dir` | Removed automatically after `cleanup_minutes` (async); or manually if `cleanup_minutes: 0` |

On the remote path, Ansible removes `/tmp/ratf-simulate` synchronously
after script execution. This covers the copied scenario scripts only.
The spike file (log_volume) and auth log entries (geoip_detection,
suspicious_login) are outside this directory and are not affected by
Ansible cleanup.

## Verifying results

After simulation, check the following:

1. **Wazuh Dashboard → Discovery**: filter by the expected rule ID for
   your scenario (see table above). The alert should appear for the
   agent matching `common.hostname` in `config.yaml`.

2. **Email**: the address configured in `EMAIL_TO` (`.env`) should
   receive a RADAR alert notification.

3. **FlowIntel** (if configured): a case should appear in the Cases
   menu of the FlowIntel instance at `FLOWINTEL_BASE_URL`.

For the `log_volume` scenario, allow up to one full detector interval
(default 5 minutes, set by `detector_interval` in `config.yaml`) before
expecting the alert to appear.
