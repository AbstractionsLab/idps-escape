# RADAR Scenario Simulation 

The RADAR simulation provides automated, agent-realistic attack
simulation for validating RADAR detection scenarios end-to-end. Rather than
injecting synthetic documents directly into OpenSearch, it generates real
artefacts at the agent level — writing SSH log entries, growing the
filesystem, or writing web access log entries.

Each scenario is a standalone Python script, run directly on the target
agent endpoint.

## Supported scenarios

| Scenario | Script | Method | Target rules |
|----------|--------|--------|--------------|
| `geoip_detection` | `scenarios/geoip_detection.py` | SSH success log entry from non-whitelisted IP | 100900, 100901 |
| `suspicious_login` | `scenarios/suspicious_login.py` | SSH failure burst + success from diverse IPs | 210012, 210013, 210020, 210021 |
| `log_volume` | `scenarios/log_volume.py` | Exponential filesystem growth in monitored directory | 100309 |
| `scanning_detection` | `scenarios/scanning_detection.py` | Volumetric requests, suspicious HTTP method, from distinct IPs | web scanning/enumeration rules |

## Repository layout
```
radar-test-framework/
  simulate/
    scenarios/
      geoip_detection.py      # geoip simulation script
      suspicious_login.py     # suspicious login simulation script
      log_volume.py           # log volume simulation script
      scanning_detection.py   # web scanning simulation script
```

## Prerequisites

- RADAR built and running for the target scenario (`build-radar.sh` completed)
- Python 3 on the agent endpoint (standard library only — no extra packages needed)
- Write access to the log path/directory the script targets

## Configuration

Each script has its own parameters hardcoded as a `CONFIG` dictionary at the top of the file — there is no command-line argument parsing and no external config file read. To adapt a script to your environment, edit its `CONFIG` dict directly before running it (target hostname, log paths, IP pools, thresholds, etc.).

**Example — the top of `scenarios/suspicious_login.py`:**

```python
CONFIG = {
    "timezone_offset": "+01:00",
    "hostname": "edge.vm",
    "log_path": "/var/log/auth.log",
    "user": "test01",
    "ip_pool": ["8.8.8.8", "1.0.136.99", "89.31.143.90", "47.91.170.222", "150.95.255.38", "84.32.84.32"],
    "window_seconds": 60,
    "sudo_tee": False,
}
```

## Usage

Copy the script for your scenario to the target agent endpoint (or run it directly if you're already on that machine), then run it with no arguments:

```bash
python3 suspicious_login.py
```

### Examples

```bash
python3 geoip_detection.py
python3 suspicious_login.py
python3 log_volume.py
python3 scanning_detection.py
```

Each script prints a completion message (e.g. `suspicious_login simulation completed`) on success, or an `ERROR: ...` message and a non-zero exit code on failure. Set `RATF_DEBUG=1` in the environment to get the full Python traceback instead of the short error message.

## Cleanup behaviour

| Scenario | What is generated | Cleanup |
|----------|-------------------|---------|
| `geoip_detection` | Entry appended to `auth_log_path` (default `/var/log/auth.log`) | Not removed; persists in the auth log |
| `suspicious_login` | Entries appended to `log_path` (default `/var/log/auth.log`) | Not removed; persists in the auth log |
| `log_volume` | Spike file created in `target_dir` | Removed automatically after `cleanup_minutes` (a detached background process spawned by the script itself; set to `0` to disable and clean up manually) |
| `scanning_detection` | Entries appended to `log_path` (default `/var/log/apache2/access.log`) | Not removed; persists in the access log |

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
