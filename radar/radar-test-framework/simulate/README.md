# RADAR Scenario Simulation 

The RADAR simulation provides automated, agent-realistic attack
simulation for validating RADAR detection scenarios end-to-end. Rather than
injecting synthetic documents directly into OpenSearch, it generates real
artefacts at the agent level — writing SSH log entries, growing the
filesystem, writing web access log entries, or putting real CPU/memory
load on the endpoint.

Each scenario is a standalone script, run directly on the target agent
endpoint.

## Supported scenarios

| Scenario | Script | Method | Target rules |
|----------|--------|--------|--------------|
| `geoip_detection` | `scenarios/geoip_detection.py` | SSH success log entry from non-whitelisted IP | 100900, 100901, 100902, 100903 |
| `suspicious_login` | `scenarios/suspicious_login.py` | SSH failure burst + success from diverse IPs | 210013, 210020, 210021, 210022 |
| `log_volume` | `scenarios/log_volume.py` | Exponential filesystem growth in monitored directory | 100309 |
| `scanning_detection` | `scenarios/scanning_detection.py` | Volumetric requests, suspicious HTTP method, from distinct IPs | web scanning/enumeration rules |
| `suspicious_login` (anomaly side) | `scenarios/inject_ad_alert.py` | Posts one off-hour anomaly for a user to the RADAR webhook, as the detector's monitor would. Run on the manager host, not the agent | 210040 |
| `linux_resource_utilization` | `scenarios/linux_resource_utilization.sh` | Real CPU load and/or resident memory held by `stress-ng` for `DURATION_SECONDS`; or `inject` mode writing synthetic `resource_usage_metric` lines | 100321 |

## Repository layout
```
radar-test-framework/
  simulate/
    scenarios/
      geoip_detection.py      # geoip simulation script
      suspicious_login.py     # suspicious login simulation script
      log_volume.py           # log volume simulation script
      scanning_detection.py   # web scanning simulation script
      linux_resource_utilization.sh  # CPU/memory load simulation script (stress-ng)
      inject_ad_alert.py      # anomaly alert injection through the webhook (fusion tests)
```

## Prerequisites

- RADAR built and running for the target scenario (`build-radar.sh` completed)
- Python 3 on the agent endpoint (standard library only — no extra packages needed)
- For `linux_resource_utilization` only: `bash` and `stress-ng` on the agent endpoint (`sudo apt-get install -y stress-ng` on Debian/Ubuntu, `sudo dnf install -y stress-ng` on RHEL/Fedora)
- Write access to the log path/directory the script targets

## Configuration

Each script has its own parameters hardcoded at the top of the file — there is no command-line argument parsing and no external config file read. To adapt a script to your environment, edit them directly before running it (target hostname, log paths, IP pools, thresholds, etc.).

**Example — the top of `scenarios/suspicious_login.py`:**

```python
CONFIG = {
    "log_path": "/var/log/auth.log",
    "hostname": "edge.vm",
    "sshd_pid": 1169457,
    "fail_port": 1045,
    "success_port": 60850,
    "key_fail": "ED25519 SHA256:A.",
    "key_success": "ED25519 SHA256:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "fail_threshold": 5,
    "fail_margin": 1,
    "burst_window_seconds": 60,
    "case_gap_seconds": 2,
    "sudo_tee": False,
}
```

## Usage

Copy the script for your scenario to the target agent endpoint (or run it directly if you're already on that machine), then run it with no arguments:

```bash
sudo python3 suspicious_login.py
```

### Examples

```bash
sudo python3 geoip_detection.py
sudo python3 suspicious_login.py
sudo python3 log_volume.py
sudo python3 scanning_detection.py
sudo bash linux_resource_utilization.sh
```

Each script prints a completion message (e.g. `suspicious_login simulation completed`) on success, or an `ERROR: ...` message and a non-zero exit code on failure. Set `RATF_DEBUG=1` in the environment to get the full Python traceback instead of the short error message (for `linux_resource_utilization.sh`, it traces every command the script runs).

## Testing signature and anomaly fusion

`suspicious_login` combines a user's signature alerts with their off-hour
anomalies. The real detector needs a baseline of normal login times before it
fires, so inject the anomaly instead. `inject_ad_alert.py` posts it to the
webhook (`http://127.0.0.1:8080/notify` by default) with the
`WEBHOOK_SHARED_SECRET` from the environment or `radar/.env`. Its default
entity, `test01`, is the burst case's user.

Anomaly first, then signature (the signature decision combines):

```bash
# on the manager host
python3 scenarios/inject_ad_alert.py
# on the agent, within 30 minutes
python3 scenarios/suspicious_login.py burst
```

Signature first, then anomaly (the anomaly decision combines):

```bash
# on the agent
python3 scenarios/suspicious_login.py burst
# on the manager host, within 30 minutes
python3 scenarios/inject_ad_alert.py
```

Check `/var/ossec/logs/active-responses.log` on the manager: the second
decision logs `Fusion: counterpart matched` with the first alert's ID, and its
`Risk computed` score includes both terms. The email and the Flowintel case
show the match under the scenario details, as `fusion`. Inject for a different
user (edit `entity` in the script's `CONFIG`) to check that nothing is
combined.

## Cleanup behaviour

| Scenario | What is generated | Cleanup |
|----------|-------------------|---------|
| `geoip_detection` | Entries appended to `auth_log_path` (default `/var/log/auth.log`) and `web_log_path` (default `/var/log/apache2/access.log`) | Not removed; persists in the auth/access logs |
| `suspicious_login` | Entries appended to `log_path` (default `/var/log/auth.log`) | Not removed; persists in the auth log |
| `log_volume` | Spike file created in `target_dir` | Removed automatically after `cleanup_minutes` (a detached background process spawned by the script itself; set to `0` to disable and clean up manually) |
| `scanning_detection` | Entries appended to `log_path` (default `/var/log/apache2/access.log`) | Not removed; persists in the access log |
| `linux_resource_utilization` | `cpu`/`mem`/`both`: `stress-ng` CPU and memory workers started by the script. `inject`: lines appended to `INJECT_LOG_PATH` (default `/var/log/radar/resource_usage_metric.log`) | Load is released when the script exits, including on Ctrl-C; if the script is killed, `stress-ng` still stops after `DURATION_SECONDS`. Injected lines are not removed; they rotate out with the collector log |

## Verifying results

After simulation, check the following:

1. **Wazuh Dashboard → Discovery**: filter by the expected rule ID for
   your scenario (see table above). The alert should appear for the
   agent matching the script's configured `hostname`.

2. **Email**: the address configured in `EMAIL_TO` (`.env`) should
   receive a RADAR alert notification.

3. **FlowIntel** (if configured): a case should appear in the Cases
   menu of the FlowIntel instance at `FLOWINTEL_BASE_URL`.

For the `log_volume` scenario, allow up to one full detector interval
(default 5 minutes, set by `detector_interval` in `config.yaml`) before
expecting the alert to appear.
