# Active Response

This document provides comprehensive documentation for the RADAR Active Response system, which implements automated threat detection and response capabilities. The Active Response module is located at `/radar/scenarios/active_responses/radar_ar.py` and follows a structured workflow to identify, assess, and respond to security events.

> **Production Scenario Support:** The active response script's scenario registry (`Registry` class in `radar_ar.py`) currently supports four production scenarios: `default`, `geoip_detection`, `suspicious_login`, and `log_volume`. Archived demo scenarios (`insider_threat`, `ddos_detection`, `malware_communication`) in `/radar/archives/` use different active response implementations and require adaptation for production use.

## Table of Contents

- [High-Level Workflow](#high-level-workflow)
- [Integration with Wazuh](#integration-with-wazuh)
- [Scenario Identification](#scenario-identification)
- [Scenario-Specific Behavior](#scenario-specific-behavior)
- [Context Collection](#context-collection)
- [SATRAP CTI Integration](#satrap-cti-integration)
- [Risk Engine](#risk-engine)
- [Tiering](#tiering)
- [Action Planning](#action-planning)
- [Action Execution](#action-execution)
- [Decision ID Generation](#decision-id-generation)
- [Mitigation Safety Gates](#mitigation-safety-gates)
- [Error Handling & Logging](#error-handling--logging)
- [Environment Variables](#environment-variables)
- [Configuration](#configuration)

---

## High-Level Workflow

The RADAR Active Response system follows a structured execution pipeline implemented in the `RadarActiveResponse.run()` method:

1. **Input Reading**: Parse Wazuh alert JSON from stdin
2. **Scenario Identification**: Match alert rule ID to configured scenario
3. **Context Collection**: Query OpenSearch for correlated events and extract IOCs
4. **CTI Enrichment**: Query SATRAP for threat intelligence on extracted IOCs
5. **Risk Calculation**: Compute risk score using anomaly, signature, and CTI components
6. **Decision ID Generation**: Create unique identifier for idempotency tracking
7. **Action Planning**: Determine actions based on tier and configuration flags
8. **Action Execution**: Execute planned actions (email, Flowintel case, mitigations)
9. **Audit Logging**: Record complete decision trail with execution results

**Exit codes:**
- `0`: Success (scenario matched and processed)
- `1`: No alert received or no scenario match
- `2`: Critical unhandled exception

---

## Integration with Wazuh

### Wazuh Active Response Framework

The script integrates with Wazuh's Active Response framework by:

1. **Reading alerts from stdin**: Wazuh sends alert JSON to the script's standard input
2. **Processing the alert**: Execute the full workflow pipeline
3. **Logging results**: Write structured JSON logs to `/var/ossec/logs/active-responses.log`
4. **Executing mitigations**: Call back to Wazuh API to dispatch active response commands to agents

### Input Format

Expected JSON structure from stdin:

```json
{
  "id": "1234567890.123456",
  "timestamp": "2026-02-06T10:15:30.123+00:00",
  "rule": {
    "id": "210012",
    "level": 10,
    "description": "Multiple failed SSH login attempts",
    "groups": ["authentication_failed", "sshd"]
  },
  "agent": {
    "id": "001",
    "name": "web-server-01"
  },
  "data": {
    "srcip": "203.0.113.42",
    "dstuser": "admin",
    "anomaly_grade": 0.85,
    "anomaly_confidence": 0.92
  },
  "full_log": "..."
}
```

### Wazuh Active Response Command Dispatch

When mitigations are enabled, the script uses `WazuhApiClient` to dispatch active response commands via Wazuh API:

```python
PUT /active-response?agents_list={agent_id}&wait_for_complete=true
Authorization: Bearer {token}
{
  "command": "firewall-drop",
  "arguments": ["203.0.113.42"],
  "alert": {"data": {...}}
}
```

---

## Scenario Identification

### Input: Wazuh Alert

We expect:
- `rule.id`, `rule.level`, `rule.groups`
- `timestamp`
- `agent.id`, `agent.name`
- `full_log` 


### Rule-based mapping
We maintain `ar.yaml` at `/radar/scenarios/active_responses/ar.yaml`:

- Map `rule.id` → `scenario`
- Map `rule.id` → `detection_type` (signature vs ad)

The `ScenarioIdentifier` class iterates through configured scenarios and returns:

```python
{
  "name": "geoip_detection",
  "detection": "signature",
  "alert": {...},
  "config": {...}  # Scenario-specific configuration from ar.yaml
}
```

If no scenario matches the rule ID, the script logs a warning and exits with code 0 (no-op).

---

## Scenario-Specific Behavior

The system uses a strategy pattern with scenario-specific classes that extend `BaseScenario`. Each scenario can override behavior for time window resolution, agent name resolution, and AD score extraction.

### BaseScenario (Default)

**Time Window Resolution:**
- For AD-based detection: Uses `delta_ad_minutes` (default: 10) from configuration
- For signature-based detection: Uses `delta_signature_minutes` (default: 1) from configuration
- Window: `[alert_timestamp - delta, alert_timestamp]`

**Effective Agent Resolution:**
- For AD-based detection: Returns `None` (query all agents)
- For signature-based detection: Returns alert's `agent.name`

**AD Score Extraction:**
- Extracts `anomaly_grade` and `anomaly_confidence` from `alert.data`
- Returns `(grade_float, confidence_float)` or logs error if missing/invalid

### Default Scenario

**Strategic Purpose**: Provide a low-friction baseline detection framework that enables rapid threat detection without prerequisite data preparation work. The Default scenario demonstrates how RADAR detection rules can operate on standard Wazuh event streams — no custom decoders, no radar-helper enrichment, no index schema modifications — while remaining fully integrated with CTI analysis and automated case creation workflows.

- Rules operate on events already present in standard Wazuh installations
- Baseline alerts can be immediately enriched with DECIPHER intelligence 
- Acts as a template showing how signature-based detection integrates with risk computation and automated action planning

**Configuration** (`ar.yaml`):
```yaml
default:
  signature:
    rule_ids: ["100401", "100402", "100404", "100405"]
  w_ad: 0.0
  w_sig: 0.7
  w_cti: 0.3
  signature_likelihood: 0.6
  signature_impact: 0.5
  delta_signature_minutes: 5
  allow_mitigation: false
```

**Current Rule Coverage**:
- **PowerShell/CMD detection** (6 rules, IDs 100400–100405): Command shell execution detection on Windows hosts
- **Extensible to other threats**: Future rules can detect network-based threats, log injection patterns, access anomalies, or any event types available in standard Wazuh indices without requiring preprocessing

### GeoipDetection

Inherits all default behavior from `BaseScenario`. No custom overrides.

### SuspiciousLogin

Inherits all default behavior from `BaseScenario`. No custom overrides.

### LogVolume

**Custom Time Window Resolution:**
- Attempts to extract `period_start` and `period_end` from `alert.data`
- If both present: Uses exact period from SONAR detector
- Otherwise: Falls back to `BaseScenario` delta-based calculation

**Custom Effective Agent Resolution:**
- Extracts `entity_keyword` from `alert.data` (SONAR detector's entity field)
- If present: Uses entity value as agent name filter
- Otherwise: Falls back to `BaseScenario` behavior

This allows log volume anomalies to use the exact detection period and target agent from SONAR's alert metadata.

---

## Context Collection

### OpenSearch Query

We query OpenSearch around the triggering event time:
- time window: `T - Δ_before` to `T`
- filter by:
  - agent id/name
  - scenario-specific fields (e.g., user)

We extract all events per entity within `T - Δ_before` and `T`, where `Δ_before` are detection interval for AD. While for signature-based, it is a configurable value.


> For AD-based detection, `Δ` follows the detector interval.
> For signature-based detection, `Δ` is **minute-based and configurable via YAML (default: 1 minute)**.

### IOC Extraction

We identify IOCs from:
- Wazuh alert fields
- correlated OpenSearch events

Typical IOCs:
- `ip`: src_ip, dst_ip
- `user`: username, account id
- `domain`: hostnames, urls
- `hash`: file hashes 
- `service`: service name
- `asn`, `country`, `agent`

---

## SATRAP CTI Integration

The active response script integrates with the SATRAP-DL DECIPHER subsystem via `DecipherClient`. DECIPHER performs CTI analysis on extracted IOCs and optionally creates FlowIntel incident cases.

### DECIPHER Health Check

Before any CTI operation, the script calls `DecipherClient.health_check()`. If DECIPHER is unreachable or `DECIPHER_BASE_URL` is not configured:
- CTI score is set to `T = 0.0`
- No FlowIntel case is created
- A warning is logged and execution continues with AD + signature components only

### What DECIPHER returns

We define a minimal normalized CTI contract:

- `cti_threat_score` in [0..1]
- `cti_confidence` in [0..1]
- `labels`: `botnet`, `scanner`, `ransomware`, `vpn_exit_node`

---

## Risk Engine

The risk engine combines anomaly detection, signature-based detection, and CTI indicators into a normalized risk score ∈ [0, 1]. See [radar-risk-math.md](radar-risk-math.md) for complete mathematical specification.

### Unified Risk Formula

$$
R = w_A \cdot A + w_S \cdot S + w_T \cdot T
$$

where A = G×C (anomaly intensity), S = L×I (signature risk), T = CTI score, and weights satisfy w_A + w_S + w_T = 1.

**Scenario weight configurations** (from ar.yaml):

- **geoip_detection**: w_A=0.0, w_S=0.6, w_T=0.4 (signature-focused)
- **suspicious_login**: w_A=0.3, w_S=0.4, w_T=0.3 (hybrid)
- **log_volume**: w_A=0.9, w_S=0.0, w_T=0.1 (AD-focused)

---

### Signature Likelihood Configuration

The likelihood value can be configured in two ways:

**Scalar mode** (single value for all rules in scenario):
```yaml
signature_likelihood: 0.8
```

**List mode** (rule-based mapping for fine-grained control):
```yaml
signature_likelihood:
  - rule_id: [210012, 210013]
    weight: 0.5
  - rule_id: [210020, 210021]
    weight: 0.7
```

If no match is found in list mode, likelihood defaults to 0.0.

### CTI Score Calculation

CTI indicators are aggregated using the formula T = 1 - ∏(1 - w_i) with hardcoded weights (IP: 0.6, Domain: 0.4, Hash: 0.7, User: 0.5). See [radar-risk-math.md](radar-risk-math.md#cti-subsystem) for detailed specification and examples.

---

### Risk Components Breakdown

The risk engine returns detailed component information for explainability:

```python
{
  "risk_score": 0.4795,
  "tier": 2,
  "components": {
    "anomaly_component": 0.1835,     # w_A × A
    "anomaly_intensity_A": 0.4588,   # G × C
    "signature_component": 0.144,    # w_S × S
    "signature_risk_S": 0.36,        # L × I
    "cti_component": 0.152,          # w_T × T
    "cti_score_T": 0.76,
    # ... plus individual G, C, L, I values
  }
}
```

For complete calculation examples, see [radar-risk-math.md](radar-risk-math.md#concrete-example-calculation).

---

## Tiering

The system implements a four-tier response framework. Default boundaries (configurable in `ar.yaml` per scenario):
- **tier1_min**: 0.0 (scores below this fall into Tier 0)
- **tier1_max**: 0.33
- **tier2_max**: 0.66

### Tier 0: Below Threshold
**Threshold:** `R < tier1_min`

**Actions:**
- Audit log entry only

**Rationale:** Risk score too low to warrant any notification or action.

### Tier 1: Low Risk
**Threshold:** `tier1_min ≤ R < tier1_max`

**Mandatory Actions:**
- Email notification to security operations team
- FlowIntel case creation via DECIPHER incident endpoint

**Rationale:** Low-risk events require awareness and tracking but do not warrant automated remediation.

### Tier 2: Medium Risk
**Threshold:** `tier1_max ≤ R < tier2_max`

**Mandatory Actions:**
- Email notification to security operations team
- FlowIntel case creation via DECIPHER incident endpoint

**Optional Mitigations** (if `allow_mitigation: true` and `mitigations_tier2` is non-empty):
  - GeoIP: `firewall-drop` (with timeout)
  - Log volume: notify only (no `mitigations_tier2` entries)
  - Suspicious login: `firewall-drop`

### Tier 3: High Risk
**Threshold:** `tier2_max ≤ R ≤ 1.0`

**Mandatory Actions:**
- Email notification to security operations team
- FlowIntel case creation via DECIPHER incident endpoint

**Mitigation Actions** (if `allow_mitigation: true`):
- GeoIP: `firewall-drop`
- Suspicious login: `firewall-drop` + `lock_user_linux.sh`
- Log volume: `terminate_service.sh`

---

## Action Planning

After risk calculation, the `ActionPlanner` determines which actions to execute based on tier and configuration flags.

### Planning Logic (`ActionPlanner.plan()`)

**Input:** Decision dictionary containing scenario, risk, context, and CTI data

**Output:** Planned actions dictionary:

```python
{
  "notify_email": bool,   # True for tier >= 1
  "mitigations": [str]    # List of mitigation commands (tier 2: mitigations_tier2, tier 3: mitigations_tier3)
}
```

**Decision Tree:**

1. **Email Notification**: Enabled for tier ≥ 1
2. **FlowIntel Case**: Created automatically via DECIPHER for tier ≥ 1
3. **Mitigations**: Enabled only if:
   - Tier is 2 (uses `mitigations_tier2` list), OR tier is 3 (uses `mitigations_tier3` list), AND
   - `allow_mitigation: true` in scenario configuration

**Safety**: The planner respects the `allow_mitigation` flag (default: `false`) to prevent unintended automated actions in production.

---

## Action Execution

The `ActionExecutor` orchestrates the execution of planned mitigations and handles failures gracefully.

### Execution Flow (`ActionExecutor.execute()`)

1. **Mitigation Commands** (if planned):
   - For each command in the selected tier's mitigation list:
     - Resolve target agent ID
     - Build command-specific arguments
     - Dispatch via Wazuh API
     - Capture result or error

2. **Result Aggregation**:
   - Return dictionary with mitigation results
   - Failures are logged but don't stop other mitigations

> **Note**: FlowIntel case creation is handled separately in `RadarActiveResponse.run()` via `DecipherClient.create_incident()`, not by `ActionExecutor`.

### Mitigation Command Execution

#### Agent ID Resolution (`_resolve_agent_id()`)

**Strategy:**
1. **Primary**: Use `effective_agent` from context (if available)
   - Query Wazuh API `/agents?search={effective_agent}`
   - Extract agent ID from response
2. **Fallback**: Use `alert.agent.id` if API lookup fails or effective_agent is None
3. **Error**: Return `None` if both methods fail (mitigation skipped)

This allows targeting the correct agent even when SONAR's detected entity differs from the alert's origin agent.

#### Argument Construction (`_build_args()`)

Each mitigation command requires specific arguments extracted from IOCs:

| Command | Argument Source | Example |
|---------|----------------|---------|
| `firewall-drop` | First IP from `iocs.ip` | `["203.0.113.42"]` |
| `lock_user_linux.sh` | First user from `iocs.user` | `["admin"]` |
| `terminate_service.sh` | First service from `iocs.service` | `["apache2"]` |

**Safety**: If required IOCs are missing, arguments return `None` and mitigation is skipped with error log.

#### Wazuh API Dispatch

**API Call:**
```
PUT /active-response?agents_list={agent_id}&wait_for_complete=true
Content-Type: application/json
Authorization: Bearer {token}

{
  "command": "firewall-drop",
  "arguments": ["203.0.113.42"],
  "alert": {
    "data": {...}  # Original alert data
  }
}
```

**Response Handling:**
- Success: Log and return response JSON
- Failure: Log error, return error details in result dict
- Timeout: Controlled by `WAZUH_TIMEOUT_SEC` (default: 30s)

### Execution Results Structure

```python
{
  "mitigations": [
    {
      "command": "firewall-drop",
      "agent_id": "001",
      "args": ["203.0.113.42"],
      "result": {...}  # Wazuh API response
    },
    {
      "command": "lock_user_linux.sh",
      "agent_id": "001",
      "args": ["admin"],
      "error": "Wazuh API timeout"
    }
  ]
}
```

---

## Decision ID Generation

The `DecisionId.build()` method creates a unique, deterministic identifier for each active response decision using SHA256 hashing.

### Purpose

- **Idempotency**: Prevent duplicate actions for the same alert
- **Audit Trail**: Link logs and actions to specific decisions
- **Deduplication**: Identify when the same scenario is triggered multiple times

### Hash Input Components

```python
{
  "alert_id": "1234567890.123456",
  "timestamp": "2026-02-06T10:15:30.123+00:00",
  "rule_id": "210012",
  "agent_id": "001",
  "scenario": "geoip_detection",
  "detection": "signature",
  "window": {
    "start": "2026-02-06T10:14:30.123+00:00",
    "end": "2026-02-06T10:15:30.123+00:00"
  },
  "effective_agent": "web-server-01"
}
```

The hash is computed as: `SHA256(JSON.dumps(components, sort_keys=True))`

### Example Decision ID

```
decision_id: "a3f5b2c8d9e1f4a7b6c3d8e2f5a9b4c7d1e8f3a6b9c2d5e8f1a4b7c0d3e6f9a2"
```

This ID appears in:
- Structured logs
- Email notifications
- FlowIntel case descriptions
- Execution result records

---

## Mitigation Safety Gates

Mitigations obey:

1. **Flags**
   - `allow_mitigation = false` by default

2. **Time limits**
   - actions should have timeouts (for custom AR these require additional code for reverse action)

3. **Idempotency**
   - actions must be safe if repeated

4. **Audit**
   - decision record must include action outcome and executor logs

---

## Error Handling & Logging

The system implements comprehensive error handling and structured logging throughout the execution pipeline.

### Logging Format

All logs use structured JSON format written to `/var/ossec/logs/active-responses.log`:

```
2026-03-05T15:20:55Z [INFO] RADAR Active Response started
2026-03-05T15:20:55Z [INFO] Config loaded {"scenarios":["geoip_detection","suspicious_login","log_volume"]}
2026-03-05T15:21:00Z [INFO] Alert parsed {"rule_id":"210020"}
2026-03-05T15:21:00Z [INFO] Scenario identified {"scenario":"suspicious_login","detection":"signature","rule_id":"210020"}
2026-03-05T15:21:01Z [INFO] Events {"events":[],"iocs":{"ip":["185.220.100.1"],"user":["admin"],"domain":["edge.vm"],"hash":[],"service":[],"country":["Russia"],"asn":["AS12345"],"agent":["edge.vm"]}}
2026-03-05T15:21:01Z [INFO] DECIPHER health check passed {"url":"http://localhost:8000"}
2026-03-05T15:21:01Z [INFO] DECIPHER analyze completed {"scenario":"suspicious_login","cti_score_T":0.0,"case_id":"0","case_url":""}
2026-03-05T15:21:01Z [INFO] Risk computed {"risk_score":0.13999999999999999,"tier":0,"threshold":0.51}
2026-03-05T15:21:01Z [INFO] DECIPHER incident created {"case_id":"5","case_url":"http://flowintel:7006/case/5"}
2026-03-05T15:21:01Z [INFO] Actions planned {"tier":0,"allow_mitigation":true,"mitigations":[]}
2026-03-05T15:21:01Z [INFO] RADAR Active Response completed {"decision_id":"4ebe114ad8ad424c526f39700786d947aae76683f77ed4e8cf7ade2223e16108","exec_results":{"mitigations":[]}}
```

### Log Levels

| Level | Usage | Examples |
|-------|-------|----------|
| `INFO` | Normal operation milestones | Config loaded, risk computed, actions executed |
| `WARNING` | Recoverable issues | No scenario matched, API lookup fallback, missing optional config |
| `ERROR` | Failed operations (non-critical) | Mitigation skipped, email send failed, DECIPHER API error |
| `CRITICAL` | Unhandled exceptions | System-level failures that prevent execution |

### Error Handling Strategies

#### 1. Input Validation Errors
**Scenario**: Invalid or missing alert JSON from stdin
- **Action**: Log ERROR and exit with code 1
- **Recovery**: None (wait for next alert)

#### 2. Configuration Errors
**Scenario**: Missing or invalid `ar.yaml`
- **Action**: Log ERROR with file path
- **Recovery**: None (requires manual fix)

#### 3. External Service Failures

**OpenSearch Connection:**
- **Scenario**: Cannot connect to OpenSearch
- **Action**: Log ERROR during initialization
- **Recovery**: Script continues but context collection will fail

**Wazuh API:**
- **Scenario**: API timeout or authentication failure
- **Action**: Log ERROR, use fallback agent ID from alert
- **Recovery**: Partial degradation (may target wrong agent)

**DECIPHER/CTI:**
- **Scenario**: DECIPHER service unavailable
- **Action**: Log WARNING, set CTI score to 0, skip FlowIntel case creation
- **Recovery**: Risk calculation uses only AD + signature components

**Email/SMTP:**
- **Scenario**: SMTP connection failure
- **Action**: Log ERROR with SMTP details
- **Recovery**: Continue with other actions (DECIPHER, mitigations)

**DECIPHER / FlowIntel:**
- **Scenario**: Incident creation API error
- **Action**: Log ERROR with API response
- **Recovery**: Continue with other actions (email, mitigations)

#### 4. Mitigation Execution Errors
**Scenario**: Missing IOCs for command arguments
- **Action**: Log ERROR, skip mitigation
- **Recovery**: Continue with other planned mitigations

**Scenario**: Wazuh Active Response dispatch fails
- **Action**: Log ERROR with command details, capture error in results
- **Recovery**: Continue with other planned mitigations

### Critical Exception Handler

Unhandled exceptions are caught at the top level (`main()` try-except):

```python
except Exception as e:
    Logger(...).log(
        "CRITICAL",
        "Unhandled exception",
        error=str(e),
        trace=traceback.format_exc()
    )
    sys.exit(2)
```

This ensures all failures are logged even if the logging system itself has issues.

---

## Environment Variables

The script loads environment variables from `active_responses.env` file located at:
1. `/var/ossec/active-response/bin/active_responses.env` (production)
2. `{script_directory}/active_responses.env` (development)

The `EnvLoader` class parses the file and sets default values if not specified.

### Environment File Format

```bash
# OpenSearch Configuration
OS_URL=https://opensearch.example.com:9200
OS_USER=admin
OS_PASS=SecurePassword123
OS_VERIFY_SSL=false
OS_INDEXES=wazuh-alerts-*,wazuh-archives-*

# Email/SMTP Configuration
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USER=radar@example.com
SMTP_PASS=EmailPassword123
EMAIL_FROM=radar@example.com
EMAIL_TO=soc-team@example.com
SMTP_STARTTLS=yes

# Wazuh API Configuration
WAZUH_API_URL=https://wazuh-manager.example.com:55000
WAZUH_AUTH_USER=admin
WAZUH_AUTH_PASS=WazuhPassword123
WAZUH_VERIFY_SSL=false
WAZUH_TIMEOUT_SEC=30

# DECIPHER Configuration
DECIPHER_BASE_URL=https://decipher.example.com
DECIPHER_VERIFY_SSL=false
DECIPHER_TIMEOUT_SEC=30

# Script Configuration
AR_LOG_FILE=/var/ossec/logs/active-responses.log
AR_RISK_CONFIG=/var/ossec/active-response/ar.yaml
```

### Variable Reference

#### OpenSearch Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OS_URL` | `https://localhost:9200` | OpenSearch cluster URL |
| `OS_USER` | `admin` | OpenSearch authentication username |
| `OS_PASS` | `""` | OpenSearch authentication password |
| `OS_VERIFY_SSL` | `false` | Verify SSL certificates for OpenSearch |
| `OS_INDEXES` | `wazuh-alerts-*,wazuh-archives-*` | Comma-separated index patterns to query |

#### Email/SMTP Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SMTP_HOST` | `smtp.office365.com` | SMTP server hostname |
| `SMTP_PORT` | `587` | SMTP server port |
| `SMTP_USER` | `""` | SMTP authentication username |
| `SMTP_PASS` | `""` | SMTP authentication password |
| `EMAIL_FROM` | `{SMTP_USER}` | Email sender address |
| `EMAIL_TO` | `""` | Email recipient address (required) |
| `SMTP_STARTTLS` | `yes` | Use STARTTLS for SMTP connection |

**Note**: If `SMTP_USER` or `EMAIL_TO` are empty, email notifications are skipped with a warning log.

#### Wazuh API Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_API_URL` | `""` | Wazuh manager API base URL (e.g., `https://host:55000`) |
| `WAZUH_AUTH_USER` | `""` | Wazuh API authentication username |
| `WAZUH_AUTH_PASS` | `""` | Wazuh API authentication password |
| `WAZUH_VERIFY_SSL` | `false` | Verify SSL certificates for Wazuh API |
| `WAZUH_TIMEOUT_SEC` | `30` | API request timeout in seconds |

**Note**: Required for mitigation execution. Script initializes client but mitigations will fail if credentials are invalid.

#### DECIPHER Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DECIPHER_BASE_URL` | `""` | DECIPHER instance base URL |
| `DECIPHER_VERIFY_SSL` | `false` | Verify SSL certificates for DECIPHER API |
| `DECIPHER_TIMEOUT_SEC` | `30` | API request timeout in seconds |

**Note**: Required for CTI enrichment and FlowIntel case creation at tier ≥ 1. If `DECIPHER_BASE_URL` is empty or the health check fails, CTI score is set to 0 and no case is created.

#### Script Configuration Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AR_LOG_FILE` | `/var/ossec/logs/active-responses.log` | Path to structured log file |
| `AR_RISK_CONFIG` | `/var/ossec/active-response/ar.yaml` | Path to scenario configuration YAML |

### Environment File Parsing

The `EnvLoader` supports:
- **Inline comments**: `KEY=value # comment` (comments are stripped)
- **Quoted values**: `KEY="value with spaces"`
- **Empty lines and full-line comments**: Ignored
- **Fallback behavior**: If file doesn't exist, uses hardcoded defaults

---

## Configuration

### Configuration File: `ar.yaml`

The configuration file is located at `/var/ossec/active-response/ar.yaml` (or path specified by `AR_RISK_CONFIG` environment variable) and defines scenario mappings, risk parameters, and response actions.

### Configuration Structure

```yaml
scenarios:
  geoip_detection:
    # Scenario identification
    ad:
      rule_ids: []
    signature:
      rule_ids: [100900, 100901]

    # Risk calculation weights (must sum to 1.0)
    w_ad: 0.0
    w_sig: 0.6
    w_cti: 0.4

    # Signature risk parameters
    signature_likelihood: 0.8  # Can be scalar or list (see below)
    signature_impact: 0.6

    # Time windows for context collection
    delta_ad_minutes: 10
    delta_signature_minutes: 1

    # Tier boundaries
    tiers:
      tier1_min: 0.0
      tier1_max: 0.33
      tier2_max: 0.66

    # Mitigation configuration
    allow_mitigation: true
    mitigations_tier2:
      - firewall-drop
    mitigations_tier3:
      - firewall-drop

  suspicious_login:
    ad:
      rule_ids: [100021]
    signature:
      rule_ids: [210012, 210013, 210020, 210021]
    w_ad: 0.3
    w_sig: 0.4
    w_cti: 0.3
    signature_likelihood:
      - rule_id: [210012, 210013]
        weight: 0.5
      - rule_id: [210020, 210021]
        weight: 0.5
    signature_impact: 0.7
    tiers:
      tier1_min: 0.0
      tier1_max: 0.33
      tier2_max: 0.66
    allow_mitigation: true
    mitigations_tier2:
      - firewall-drop
    mitigations_tier3:
      - firewall-drop
      - lock_user_linux.sh
```

### Configuration Parameters

#### Per-Scenario Parameters

**Identification:**
- `rules`: List of Wazuh rule IDs that trigger this scenario
- `detection`: `"signature"` or `"ad"` (affects time window and AD score extraction)

**Risk Weights** (must sum to 1.0):
- `w_ad`: Weight for anomaly detection component (0.0-1.0)
- `w_sig`: Weight for signature-based component (0.0-1.0)
- `w_cti`: Weight for CTI component (0.0-1.0)

**Signature Risk:**
- `signature_likelihood`: Scalar (float) or list of rule-specific weights
- `signature_impact`: Impact value (0.0-1.0)

**Time Windows:**
- `delta_ad_minutes`: Lookback window for AD-based detection (default: 10)
- `delta_signature_minutes`: Lookback window for signature-based detection (default: 1)

**Mitigation:**
- `allow_mitigation`: Boolean flag (default: `false`) - **MUST be explicitly enabled**
- `mitigations`: List of mitigation commands to execute (Tier 2+)
- `risk_threshold`: Optional minimum risk score for response

### Signature Likelihood Modes

**Scalar mode** (single value for all rules):
```yaml
signature_likelihood: 0.8
```

**List mode** (rule-specific weights):
```yaml
signature_likelihood:
  - rule_id: [210012, 210013]
    weight: 0.5
  - rule_id: [210020]
    weight: 0.9
```

In list mode, if a rule ID doesn't match any entry, likelihood defaults to 0.0.

### Supported Mitigation Commands

| Command | Required IOC | Argument | Description |
|---------|--------------|----------|-------------|
| `firewall-drop` | `ip` | First IP address | Block IP at firewall level |
| `lock_user_linux.sh` | `user` | First username | Lock user account on Linux systems |
| `terminate_service.sh` | `service` | First service name | Stop specified service |

**Note**: Custom active response scripts must be registered in Wazuh configuration (`/var/ossec/etc/ossec.conf`) and deployed to agents.

### Deployment Checklist

When deploying to production:

1. **Test in staging**: Validate configuration with `allow_mitigation: false`
2. **Configure environment variables**: Complete `active_responses.env` with all required credentials
3. **Verify external services**: Test connectivity to OpenSearch, Wazuh API, SMTP, DECIPHER
4. **Review tier boundaries**: Adjust `tier1_min`, `tier1_max`, and `tier2_max` per scenario to match organizational risk tolerance
5. **Tune risk weights**: Calibrate `w_ad`, `w_sig`, `w_cti` based on detection source reliability
6. **Enable mitigations gradually**: Start with Tier 1 (notify + case only), then enable Tier 2/3 mitigations selectively
7. **Monitor logs**: Review `/var/ossec/logs/active-responses.log` for errors and false positives
8. **Configure DECIPHER**: Ensure `DECIPHER_BASE_URL` and connectivity are validated before enabling Tier ≥ 1 response