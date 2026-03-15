# Suspicious login extensibility guide

**Purpose**: This guide explains how to extend the suspicious login detection framework to support new authentication protocols beyond SSH.

**Last updated**: 2026-02-15

---

## Overview

The suspicious login detection system (SRS-051) is designed with protocol-agnostic patterns that allow easy extension to new authentication types (RDP, web, database, etc.) without modifying core logic.

### Current implementation

- **Protocol**: SSH authentication
- **Rule IDs**: 210012-210022 (failed-burst, impossible-travel, correlation)
- **Base rules**: 5760 (failed), 5715 (success)
- **Scenario name**: `suspicious_login`

---

## Extension process

To add a new authentication protocol (e.g., RDP), follow these steps:

### 1. Define scenario configuration

Add a new scenario to `radar/config.yaml`:

```yaml
suspicious_login_rdp:
  container_name: agent.rdp
  index_prefix: wazuh-ad-suspicious-login-rdp
  result_index: opensearch-ad-plugin-result-suspicious-login-rdp
  log_index_pattern: wazuh-ad-suspicious-login-rdp-*
  dataset_dir: suspicious_login_rdp/dataset
  time_field: "@timestamp"
  shingle_size: 8
  categorical_field: "User ID.keyword"
  detector_interval: 10
  delay_minutes: 1
  monitor_name: "SuspiciousLogin-RDP-Monitor"
  trigger_name: "Suspicious-RDP-Login-Detected"
  anomaly_grade_threshold: 0.8
  confidence_threshold: 0.85
  
  # Protocol-specific rule mappings
  protocol: rdp
  base_failed_rule: 60122  # Windows RDP authentication failed
  base_success_rule: 60204  # Windows RDP authentication success
  
  # Risk scoring weights
  w_ad: 0.4
  w_sig: 0.4
  w_cti: 0.2
  risk_threshold: 0.5
  signature_likelihood: 0.7
  signature_impact: 0.8
  
  # Tier boundaries
  tiers:
    tier1_max: 0.33
    tier2_max: 0.66
  
  # Time windows
  delta_ad_minutes: 10
  delta_signature_minutes: 1
  
  features:
    - feature_name: login_count
      feature_enabled: true
      aggregation_query:
        login_count:
          value_count:
            field: User ID.keyword
    
    - feature_name: distinct_geo_country
      feature_enabled: true
      aggregation_query:
        distinct_geo_country:
          cardinality:
            field: Country.keyword
```

### 2. Create custom Wazuh decoder

Create `radar/scenarios/decoders/suspicious_login_rdp/0320-rdp.xml`:

```xml
<decoder name="windows-rdp">
  <parent>ossec</parent>
  <prematch>^EventID: (4624|4625)</prematch>
  <regex offset="after_parent">^EventID: (\d+)\|</regex>
  <regex>LogonType: (\d+)\|</regex>
  <regex>User: ([^\|]+)\|</regex>
  <regex>SourceIP: ([^\|]+)</regex>
  <order>id,logon_type,user,srcip</order>
</decoder>

<decoder name="windows-rdp-fields">
  <parent>windows-rdp</parent>
  <use_own_name>true</use_own_name>
  
  <!-- Extract GeoIP fields if available -->
  <plugin_decoder>geoip</plugin_decoder>
  
  <!-- Custom fields for impossible travel detection -->
  <program_name>rdp_auth</program_name>
</decoder>
```

### 3. Create detection rules

Create `radar/scenarios/rules/suspicious_login_rdp/a3-suspicious-login-rdp.xml`:

```xml
<group name="suspicious_login_rdp,">

  <!-- 1) Failed burst for RDP -->
  <rule id="210023" level="8" timeframe="60" frequency="5">
    <if_matched_sid>60122</if_matched_sid>
    <same_srcuser />
    <description>RADAR SuspiciousLogin-RDP: failed-burst (≥5 in 60s)</description>
    <group>authentication_failures,brute_force,windows,rdp</group>
  </rule>

  <rule id="210024" level="8" timeframe="60" frequency="5">
    <if_matched_sid>60122</if_matched_sid>
    <same_user />
    <description>RADAR SuspiciousLogin-RDP: failed-burst (≥5 in 60s)</description>
    <group>authentication_failures,brute_force,windows,rdp</group>
  </rule>

  <!-- 2) Impossible travel for RDP -->
  <rule id="210025" level="10">
    <if_matched_sid>60122</if_matched_sid>
    <field name="radar_country_change_i">^1$</field>
    <field name="radar_geo_velocity_kmh" type="pcre2">^(?:9(?:0[1-9]|[1-9]\d)|[1-9]\d{3,})(?:\.\d+)?$</field>
    <description>RADAR SuspiciousLogin-RDP: impossible travel with failure (≥900 km/h)</description>
    <group>authentication_failed,impossible_travel,geo,windows,rdp</group>
  </rule>

  <rule id="210026" level="10">
    <if_matched_sid>60204</if_matched_sid>
    <field name="radar_country_change_i">^1$</field>
    <field name="radar_geo_velocity_kmh" type="pcre2">^(?:9(?:0[1-9]|[1-9]\d)|[1-9]\d{3,})(?:\.\d+)?$</field>
    <description>RADAR SuspiciousLogin-RDP: impossible travel (≥900 km/h)</description>
    <group>authentication_success,impossible_travel,geo,windows,rdp</group>
  </rule>

  <!-- 3) Composite correlation -->
  <rule id="210027" level="12" timeframe="300">
    <if_matched_sid>210026</if_matched_sid>
    <if_matched_sid>210023</if_matched_sid>
    <same_user />
    <description>RADAR SuspiciousLogin-RDP: credential compromise (burst+travel)</description>
    <group>authentication_success,impossible_travel,brute_force,credential_compromise,windows,rdp</group>
  </rule>

</group>
```

### 4. Configure active response

Create `radar/scenarios/ossec/radar-suspicious-login-rdp-ossec-snippet.xml`:

```xml
  <command>
    <name>radar_ar_suspicious_login_rdp</name>
    <executable>radar_ar.py</executable>
  </command>
  <active-response>
    <disabled>no</disabled>
    <command>radar_ar_suspicious_login_rdp</command>
    <location>server</location>
    <rules_id>210023,210024,210025,210026,210027</rules_id>
  </active-response>
```

### 5. Update active response config

Add scenario to `radar/scenarios/active_responses/ar.yaml`:

```yaml
scenarios:
  suspicious_login_rdp:
    ad:
      rule_ids: []  # If you create an OpenSearch AD detector
    signature:
      rule_ids: [210023, 210024, 210025, 210026, 210027]
      likelihood:
        - rule_id: [210023, 210024]
          weight: 0.6
        - rule_id: [210025, 210026]
          weight: 0.8
        - rule_id: [210027]
          weight: 0.95
      impact: 0.8
    w_ad: 0.4
    w_sig: 0.4
    w_cti: 0.2
    risk_threshold: 0.5
    delta_ad_minutes: 10
    delta_signature_minutes: 1
    tiers:
      tier1_max: 0.33
      tier2_max: 0.66
```

### 6. Create scenario directory structure

```bash
cd radar/scenarios
mkdir -p suspicious_login_rdp/{dataset,decoders,rules,agent_configs}

# Move/copy files to appropriate locations
mv decoders/suspicious_login_rdp/0320-rdp.xml decoders/
mv rules/suspicious_login_rdp/a3-suspicious-login-rdp.xml rules/
```

### 7. Update scenario registry

The existing `SuspiciousLogin` base class in `radar/scenarios/active_responses/radar_ar.py` should work without modification. If protocol-specific logic is needed, create a subclass:

```python
class SuspiciousLoginRDP(SuspiciousLogin):
    def resolve_effective_agent_name(self, scenario: dict, context_events: list):
        # RDP-specific logic if needed
        # For example, extract from Windows event logs
        return super().resolve_effective_agent_name(scenario, context_events)
```

Then register it:

```python
class Registry:
    def __init__(self, logger: Logger, os_client: OpenSearchClient):
        self._default = BaseScenario(logger, os_client)
        self._map = {
            "suspicious_login": SuspiciousLogin(logger, os_client),
            "suspicious_login_rdp": SuspiciousLoginRDP(logger, os_client),
            # ... other scenarios
        }
```

---

## Field mapping guide

For protocol-agnostic detection, map protocol-specific fields to canonical names:

| Canonical field | SSH | RDP | Web | Database |
|----------------|-----|-----|-----|----------|
| `authentication.outcome` | `is_success` | EventID 4624/4625 | HTTP 200/401 | pg_stat_activity |
| `source.user` | `srcuser` | `TargetUserName` | `username` | `usename` |
| `source.ip` | `srcip` | `IpAddress` | `X-Forwarded-For` | `client_addr` |
| `geo.country` | `radar_country` | `radar_country` | `radar_country` | `radar_country` |
| `geo.velocity_kmh` | `radar_geo_velocity_kmh` | `radar_geo_velocity_kmh` | `radar_geo_velocity_kmh` | `radar_geo_velocity_kmh` |

Use Wazuh decoders to normalize these fields during log ingestion.

---

## Testing the new scenario

1. **Deploy the scenario**:
   ```bash
   cd radar
   ./build-radar.sh suspicious_login_rdp --agent local --manager local --manager_exists true
   ```

2. **Verify rule files deployed**:
   ```bash
   docker exec -it wazuh.manager bash
   ls -l /var/ossec/ruleset/rules/a3-suspicious-login-rdp.xml
   ls -l /var/ossec/ruleset/decoders/0320-rdp.xml
   ```

3. **Test with synthetic data**:
   ```bash
   # Generate RDP failed login burst
   for i in {1..6}; do
     echo "<Event><EventID>4625</EventID><LogonType>10</LogonType><User>testuser</User><SourceIP>192.168.1.100</SourceIP></Event>"
   done | nc wazuh-manager 1514
   
   # Check if rule 210023 fired
   docker exec -it wazuh.manager tail -f /var/ossec/logs/alerts/alerts.log | grep 210023
   ```

4. **Validate active response**:
   ```bash
   # Check active response log
   docker exec -it wazuh.manager cat /var/ossec/logs/active-responses.log
   
   # Check RADAR AR log
   docker exec -it wazuh.manager cat /var/log/radar_ar.log | jq '.scenario'
   ```

---

## Common pitfalls

1. **Forgetting GeoIP enrichment**: Impossible travel rules require `radar_country_change_i` and `radar_geo_velocity_kmh` fields. Ensure the GeoIP helper script is deployed and logs are processed.

2. **Rule ID conflicts**: Use a new range for each protocol (SSH: 210012-210022, RDP: 210023-210027, Web: 210028-210032, etc.).

3. **Decoder parent mismatches**: Ensure decoder `<parent>` references match the actual log format parent decoder.

4. **Active response location**: Use `<location>server</location>` for centralized analysis, or `<location>local</location>` for agent-side response.

5. **Time window mismatches**: Ensure `delta_signature_minutes` in config matches the context window your rules correlate over.

---

## Example: Web authentication

For web application logins (e.g., Nginx/Apache with custom JSON logs):

**Decoder** (`0320-web-auth.xml`):
```xml
<decoder name="web-auth-json">
  <parent>json</parent>
  <use_own_name>true</use_own_name>
  <plugin_decoder>json</plugin_decoder>
</decoder>
```

**Rule** (210028):
```xml
<rule id="210028" level="8" timeframe="60" frequency="5">
  <if_matched_group>web-auth</if_matched_group>
  <field name="event.outcome">failure</field>
  <same_field>user.name</same_field>
  <description>RADAR SuspiciousLogin-Web: failed-burst</description>
  <group>authentication_failures,brute_force,web</group>
</rule>
```

**Log format** (application sends to syslog):
```json
{"timestamp":"2026-02-15T10:30:00Z","event":{"outcome":"failure"},"user":{"name":"admin"},"source":{"ip":"203.0.113.42"},"geo":{"country":"RU"}}
```

---

## Support and troubleshooting

**Documentation references**:
- [SRS-051](/docs/specs/srs/SRS-051.md): Requirement specification
- [Wazuh ruleset](https://documentation.wazuh.com/current/user-manual/ruleset/index.html): Rule syntax

**Common issues**:
- Rules not firing: Check `/var/ossec/logs/ossec.log` for syntax errors
- Active response not executing: Verify `<rules_id>` matches actual fired rule IDs
- Missing fields: Use `wazuh-logtest` to debug decoder output

**Questions**: Contact the RADAR development team or see [RADAR README](/radar/README.md).
