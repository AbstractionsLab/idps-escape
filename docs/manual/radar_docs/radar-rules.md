# RADAR Rules Overview

## Purpose

RADAR rules are custom Wazuh detection rules designed to identify anomalous behavior and security threats in real-time. These rules are deployed to `/var/ossec/etc/rules/` during the Ansible automation process and work in conjunction with custom decoders to extract and analyze event data.

## Repository Structure

```
radar/scenarios/rules/
└── {{ scenario_name }}/
    └── *.xml
```

Each scenario has its own subdirectory containing XML rule files that are automatically deployed based on the selected scenario.

---

## Rule Scenarios

### 1. Log Volume Growth Detection

**Purpose**: Detect anomalous increases in log volume that may indicate attacks, system issues, or data exfiltration attempts.

**How it works**: 
- Integrates with OpenSearch Anomaly Detection (AD) module
- Monitors log ingestion rates and patterns
- Triggers when OpenSearch AD identifies anomalies
- The anomaly is sent to Webhook
- The rule is triggered from Webhook logs

**Rules**:

| Rule ID | Level | Description | Trigger Condition |
|---------|-------|-------------|-------------------|
| `100300` | 5 | OpenSearch AD alert received | Any alert from OpenSearch AD module with `opensearch_ad` decoder |
| `100309` | 12 | Log Volume Growth Detected | Specific AD alert matching "LogVolume-Growth-Detected" |

**Alert Flow**:
```
1. OpenSearch AD detects anomaly 
2. Wazuh receives AD alert 
3. Rule 100300 catches all AD alerts (level 5) 
4. Rule 100309 escalates if "LogVolume-Growth-Detected" (level 12)
```

---

### 2. Non-GeoIP Connection Detection

**Purpose**: Detect and block authentication attempts from non-whitelisted geographic locations.

**How it works**:
- Extracts country information from successful authentication events enriched by `radar-helper`
- Compares against whitelist (`/var/ossec/etc/lists/whitelist_countries`)
- Triggers alerts for connections from unauthorized countries

**Rules**:

| Rule ID | Level | Description | Trigger Condition |
|---------|-------|-------------|-------------------|
| `100900` | 10 | Connection from non-whitelist country | Authentication success + `radar_country` field not in whitelist |
| `100901` | 10 | Connection from non-whitelist country | Authentication success + source GeoIP not in EU Greater Region |

**Alert Flow**:
```
1. Authentication success event
2. Custom decoder extracts `radar_country` field
3. Rule 100900 checks against whitelist_countries list
4. Rule 100901 checks against hardcoded countries
5. Alert if country not whitelisted
```

**Whitelist mechanism**:
- **List-based** (Rule 100900): Dynamic whitelist in `etc/lists/whitelist_countries`
- **Hardcoded** (Rule 100901): Fallback to countries using `srcgeoip` field

**Note**: The country list is subject for change according to needs.

---

### 3. Suspicious Login Detection

**Purpose**: Detect credential-based attacks including brute force attempts and impossible travel scenarios.

**How it works**:
- Monitors authentication failures and successes
- Tracks temporal patterns (frequency within timeframes)
- Analyzes geographic movement patterns (velocity, country changes) enriched by `radar-helper`

**Rules**:

| Rule ID | Level | Description | Trigger Condition | Timeframe |
|---------|-------|-------------|-------------------|-----------|
| `210012` | 8 | Failed-burst brute force | ≥5 failed SSH logins from same source user | 60 seconds |
| `210013` | 8 | Failed-burst brute force | ≥5 failed SSH logins from same destination user | 60 seconds |
| `210020` | 10 | Impossible travel (with success) | Auth success + country change + velocity ≥900 km/h | N/A |
| `210021` | 10 | Impossible travel (with failure) | Auth failure + country change + velocity ≥900 km/h | N/A |

**Alert Flow - Brute Force**:
```
1. SSH authentication failure
2. If ≥5 failures in 60 seconds from same user
3. Alert: Failed-burst brute force attack
```

**Alert Flow - Impossible Travel**:
```
1. Authentication event (success or failure)
2. RADAR helper identifies: `radar_country_change_i` (1 if country changed, 0 otherwise) and `radar_geo_velocity_kmh` (km/h between previous and current login)
3. Rule 210020/210021 checks:
    - Country changed? (radar_country_change_i == 1)
    - Velocity >= 900 km/h? (physically impossible travel)
```

---

# Rule matching and precedence in Wazuh used by RADAR

## Rule loading order

Wazuh loads rule files from the configured rule directory in alphabetical order by filename. This is why we use deterministic prefixes such as `a1_*`, `a2_*`, `a3_*`. 

Wazuh evaluates rules in a tree/layer model:

- Independent rules (no if_sid / if_matched_sid) are evaluated in the order they are read/loaded.

- Child rules (if_sid) are evaluated after their parent matches, and in the order they are defined. The first child rule that matches triggers; subsequent child rules are not evaluated (“first-match” logic). 
Groups Google

- When multiple rules can match within the same layer/parent context, Wazuh uses a deterministic precedence:
    1. Higher rule level takes priority.
    2. If the level is the same, the rule read first takes priority. 

> Important clarification for our documentation: Wazuh does not inherently sort by rule ID. In RADAR, “lower ID matches first” is true because we intentionally place rules in ascending ID order within files, and we control file loading order via filename prefixes. So the effective priority becomes “lower ID first” only as a consequence of our ordering strategy (read order). 

## Scenario rules order

- a1 — Log volume

Placed first to normalize OpenSearch AD alerts into Wazuh events early, and because it is self-contained (parent + specific child rule in the same pack). 

- a2 — GeoIP detection 

Placed second because it represents a baseline policy violation (“successful auth from non-whitelist country”) and is designed to be the primary classification when multiple geolocation-related conditions could apply.

- a3 — Suspicious login

Placed third because it contains more advanced behavioral logic (frequency correlation and enriched geo-velocity conditions). It is intentionally evaluated after baseline policy checks to avoid duplicate or competing alerts for the same authentication event.

# Summary

RADAR rules provide scenario-specific threat detection capabilities:

- **log_volume**: Anomaly detection via OpenSearch AD integration
- **geoip_detection**: Geographic access control and policy enforcement
- **suspicious_login**: Credential attack detection (brute force, impossible travel)

Rules are automatically deployed via Ansible, and generate alerts indexed in OpenSearch for analysis and response.