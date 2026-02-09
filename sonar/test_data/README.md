# SONAR test data

This directory contains sample Wazuh alert data files for use with SONAR debug mode.

## Directory structure

```
test_data/
├── generated_scenarios/         # Generated attack and training data
│   ├── normal_training.json    # 14 days normal baseline (~12,000 alerts)
│   └── attack_scenarios.json   # 2 days with attack patterns (~2,000 alerts)
├── synthetic_alerts/            # Legacy synthetic data
│   ├── normal_baseline.json    # 30 days simple training data (~12,000 alerts)
│   └── with_anomalies.json     # 30 days with anomalies (~6,000 alerts)
├── generate_attack_data.py      # Data generation script
├── inject_wazuh_data.py         # Inject synthetic data into Wazuh Indexer
└── README.md                    # This file
```

## Files overview

| Subdirectory | File | Purpose | Alerts | Time span |
|--------------|------|---------|--------|-----------|
| `generated_scenarios/` | `normal_training.json` | Normal baseline for training | ~12,000 | 14 days |
| `generated_scenarios/` | `attack_scenarios.json` | Detection testing with attacks | ~2,000 | 2 days |
| `synthetic_alerts/` | `normal_baseline.json` | Legacy simple training data | ~12,000 | 30 days |
| `synthetic_alerts/` | `with_anomalies.json` | Legacy detection test data | ~6,000 | 30 days |

## Attack scenarios

The `generated_scenarios/attack_scenarios.json` file contains realistic attack patterns:

### 1. Brute force attack (Hour 8)
- **Pattern:** 200 rapid failed login attempts from external IP
- **Target:** Single server
- **Indicators:** Failed SSH logins, brute_force rule triggers
- **Rule IDs:** 5710, 5711, 5712

### 2. Lateral movement (Hour 14)
- **Pattern:** Sequential authentication across 5 servers
- **Source:** Compromised internal host
- **Indicators:** Success after failures on each hop, sudo attempts
- **Rule IDs:** 5710, 5715, 5402

### 3. Privilege escalation (Hour 26)
- **Pattern:** Failed sudo attempts followed by user creation
- **Target:** Workstation
- **Indicators:** sudo failures, new user added, password changed
- **Rule IDs:** 5401, 5403, 5901, 5902

### 4. Password spray (Hour 38)
- **Pattern:** One password against all users on all agents
- **Source:** External attacker IP
- **Indicators:** Slow, distributed failed logins
- **Rule IDs:** 5710

## Quick start

### 1. Generate fresh test data

```bash
cd /home/alab/soar/sonar/test_data
python generate_attack_data.py
```

This creates:
- `generated_scenarios/normal_training.json` - 14 days of normal activity
- `generated_scenarios/attack_scenarios.json` - 2 days with injected attacks

### 2. Choose your testing mode

#### Option A: Debug mode (no Wazuh required)

Train with normal baseline (using local JSON files):

```bash
cd /home/alab/soar/sonar
poetry run sonar train --debug --lookback-hours 168
```

**Note:** By default, `--debug` mode uses data from `test_data/synthetic_alerts/`. To use generated scenarios instead, configure `data_dir` in your config YAML or use the LocalDataProvider with a custom path.

#### Option B: Production mode (with Wazuh Indexer)

For testing against a real Wazuh instance without waiting for data accumulation:

**Step 1:** Inject synthetic data into Wazuh Indexer

```bash
cd /home/alab/soar/sonar/test_data

# Inject last 24 hours of normal baseline
python inject_wazuh_data.py --config ../default_config.yaml --hours 24

# Or inject 14 days for comprehensive training
python inject_wazuh_data.py --config ../default_config.yaml --days 14 --source generated_scenarios/normal_training.json

# Or inject attack scenarios for detection testing
python inject_wazuh_data.py --config ../default_config.yaml --hours 48 --source generated_scenarios/attack_scenarios.json
```

**Step 2:** Train SONAR (production mode)

```bash
cd /home/alab/soar/sonar
poetry run sonar train --scenario scenarios/brute_force_detection.yaml
```

**Step 3:** Run detection (production mode)

```bash
poetry run sonar detect --scenario scenarios/brute_force_detection.yaml
```

### Train with normal baseline (using synthetic alerts)

```bash
cd /home/alab/soar/sonar
poetry run sonar train --debug --lookback-hours 168
```

**Note:** By default, `--debug` mode uses data from `test_data/synthetic_alerts/`. To use generated scenarios instead, configure `data_dir` in your config YAML or use the LocalDataProvider with a custom path.

### Run detection on generated attack data

To detect attacks using the generated scenarios, point the `data_dir` to `test_data/generated_scenarios/`:

```bash
cd /home/alab/soar/sonar
# Modify config or use custom LocalDataProvider setup
```

### Use scenario-based execution

```bash
cd /home/alab/soar/sonar
poetry run sonar scenario --use-case scenarios/brute_force_detection.yaml --debug
```

## Generated data details

### Normal training data characteristics

- **Time range:** 14 days of simulated enterprise activity
- **Activity pattern:** Higher during business hours (9-17), lower at night
- **Agents:** 10 servers/workstations (web, DB, app, file, dev, admin, jump)

## Injecting data into Wazuh Indexer

The `inject_wazuh_data.py` tool populates a Wazuh installation with synthetic alerts for:
- **Fast testing**: No need to wait 24+ hours for data accumulation
- **Integration testing**: Validate full production pipeline
- **Demos**: Controlled scenarios with known attack patterns
- **Development**: Realistic data volumes without real infrastructure

### Basic usage

```bash
# Preview what would be injected (safe, no changes)
python inject_wazuh_data.py --config ../default_config.yaml --hours 24 --dry-run

# Inject last 24 hours of data
python inject_wazuh_data.py --config ../default_config.yaml --hours 24

# Inject 14 days of baseline for training
python inject_wazuh_data.py --config ../default_config.yaml --days 14 --source generated_scenarios/normal_training.json

# Inject attack scenarios for detection testing
python inject_wazuh_data.py --config ../default_config.yaml --hours 48 --source generated_scenarios/attack_scenarios.json
```

### Advanced options

```bash
# Custom time range
python inject_wazuh_data.py --config ../default_config.yaml \
  --range "2025-12-29 00:00:00" "2025-12-30 23:59:59"

# Override Wazuh connection details
python inject_wazuh_data.py --host wazuh.example.com --port 9200 \
  --username admin --password secret --hours 24

# Adjust bulk size for performance tuning
python inject_wazuh_data.py --config ../default_config.yaml --hours 24 --bulk-size 5000
```

### How it works

1. **Loads** synthetic alerts from JSON file
2. **Adjusts** timestamps to fit target time range (maintains temporal distribution)
3. **Validates** connection to Wazuh Indexer (OpenSearch)
4. **Indexes** alerts using bulk API for performance
5. **Groups** by daily indices (e.g., `wazuh-alerts-4.x-2025.12.30`)

### Requirements

- Wazuh Indexer accessible at configured host:port
- Valid credentials (admin/admin by default)
- SSL verification can be disabled with `--no-verify-ssl`
- Requires `requests` and `pyyaml` Python packages (already in Poetry dependencies)

### Troubleshooting

**Connection refused:**
```bash
# Check if Wazuh Indexer is running
curl -k -u admin:admin https://localhost:9200

# Verify config file has correct host/port
grep -A5 "wazuh_indexer:" ../default_config.yaml
```

**SSL certificate errors:**
```bash
# Disable SSL verification (dev/test only)
python inject_wazuh_data.py --config ../default_config.yaml --hours 24 --no-verify-ssl
```

**Not enough data after injection:**
- Check if alerts were indexed: `curl -k -u admin:admin https://localhost:9200/wazuh-alerts-*/_count`
- Verify time range matches your scenario's `lookback_minutes`
- Ensure `lookback_minutes / bucket_minutes ≥ 200` for MVAD

### Complete workflow example

```bash
# 1. Generate fresh attack scenarios
cd /home/alab/soar/sonar/test_data
python generate_attack_data.py

# 2. Inject 14 days of normal baseline for training
python inject_wazuh_data.py --config ../default_config.yaml --days 14 \
  --source generated_scenarios/normal_training.json

# 3. Wait a few seconds for indexing
sleep 5

# 4. Train SONAR (production mode)
cd /home/alab/soar/sonar
poetry run sonar train --scenario scenarios/brute_force_detection.yaml

# 5. Inject 2 days with attacks
cd test_data
python inject_wazuh_data.py --config ../default_config.yaml --hours 48 \
  --source generated_scenarios/attack_scenarios.json

# 6. Run detection
cd /home/alab/soar/sonar
poetry run sonar detect --scenario scenarios/brute_force_detection.yaml
```
- **Event mix:** 85% success, 10% session events, 5% sudo/failures
- **Source IPs:** Internal network ranges (192.168.x.x, 10.0.0.x)

### Attack data characteristics

- **Base activity:** 2 days of normal traffic (same patterns)
- **Attack injections:** 4 distinct attack scenarios
- **Attacker IPs:** External ranges (203.0.113.x, 198.51.100.x)
- **Target users:** admin, root, administrator, test, guest

## Rule definitions

The generated data uses realistic Wazuh rule IDs:

| Rule ID | Level | Description | Groups |
|---------|-------|-------------|--------|
| 5715 | 3 | SSH authentication success | authentication_success, sshd, ssh |
| 5710 | 5 | Non-existent user login attempt | authentication_failed, sshd, ssh |
| 5711 | 5 | Denied user login attempt | authentication_failed, sshd, ssh, invalid_login |
| 5712 | 10 | Brute force attempt | authentication_failed, sshd, ssh, brute_force |
| 5402 | 3 | Successful sudo to ROOT | pam, syslog, sudo |
| 5401 | 5 | Failed sudo attempt | pam, syslog, sudo, authentication_failed |
| 5901 | 8 | New user added | syslog, account_changed, user_management |
| 5902 | 8 | Password changed | syslog, account_changed |
| 5403 | 14 | Privilege escalation attempt | pam, privilege_escalation, attack |
| 5501 | 3 | PAM session opened | pam, syslog, session_opened, authentication_success |

## Categorical features available

The following categorical fields can be used in scenario YAML files:

- **`rule.groups`**: Event type classification (authentication_success, failed_login, brute_force, sudo, etc.)
- **`agent.id`**: Target host identifier (001-010)
- **`agent.name`**: Human-readable host name (web-server-01, db-server-01, etc.)
- **`decoder.name`**: Log source (sshd, pam)

## Customization

Edit `generate_attack_data.py` to customize:

- **AGENTS**: Add/remove target hosts
- **NORMAL_SRCIPS**: Internal source IP ranges
- **MALICIOUS_SRCIPS**: Attacker IP addresses
- **USERS**: Normal user accounts
- **ATTACK_USERS**: Users targeted in attacks
- **RULES**: Wazuh rule definitions and groups

## See also

- [scenarios/](../scenarios/) - Pre-built detection scenarios
- [debug-mode.md](../docs/debug-mode.md) - Complete debug mode guide
- [README.md](../README.md) - SONAR main documentation
