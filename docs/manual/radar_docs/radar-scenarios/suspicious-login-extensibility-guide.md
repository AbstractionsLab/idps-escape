# Suspicious login extensibility guide

**Purpose**: This guide explains how to extend the suspicious login detection framework to support new authentication protocols beyond SSH.

---

## Overview

The suspicious login detection system (SRS-051) is designed with protocol-agnostic patterns that allow easy extension to new authentication types (RDP, web, database, etc.) without modifying core logic.

### Current implementation

- **Protocol**: SSH authentication, plus Office 365 login failures
- **Rule IDs**: 210013, 210020–210022 (SSH failed-burst, impossible-travel, correlation); 210030–210031 (O365 login failure, O365 brute force); 210039–210041 for off-hours alerts (AD catch-all, model mode, rule mode)
- **Base rules**: 5760 (failed), 5715 (success)
- **Scenario name**: `suspicious_login`

---

## Extension process

To add a new authentication protocol (e.g., RDP), follow these steps:

### 1. Define scenario configuration

Add a new scenario to `radar/config.yaml`:

```yaml
suspicious_login_rdp:
  index_prefix: wazuh-ad-suspicious-login-rdp
  result_index: opensearch-ad-plugin-result-suspicious-login-rdp
  log_index_pattern: wazuh-ad-suspicious-login-rdp-*
  time_field: "@timestamp"
  shingle_size: 8
  categorical_field: "User ID.keyword"
  detector_interval: 10
  delay_minutes: 1
  monitor_name: "SuspiciousLogin-RDP-Monitor"
  trigger_name: "Suspicious-RDP-Login-Detected"
  anomaly_grade_threshold: 0.8
  confidence_threshold: 0.85
  
  # The Wazuh base rules (60122 failed, 60204 success) are referenced in the rules (step 3), not here.
  # Risk weights, tiers and time windows are not set here: they go in ar.yaml (step 5).
  
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
    active: false
    ad:
      rule_ids: []  # the rule ID of your anomaly-detector alerts, if you create a detector
    signature:
      rule_ids: ["210023", "210024", "210025", "210026", "210027"]
    w_ad: 0.3
    w_sig: 0.4
    w_cti: 0.3
    delta_ad_minutes: 10
    delta_signature_minutes: 1
    signature_impact: 0.8
    signature_likelihood:
      - rule_id: [210023, 210024]
        weight: 0.6
      - rule_id: [210025, 210026]
        weight: 0.8
      - rule_id: [210027]
        weight: 0.95
    # Optional, once ad.rule_ids is set: combine each alert with the other
    # detection type's strongest alert for the same user.
    # fusion:
    #   enabled: true
    #   window_minutes: 30
    #   ad_lead_minutes: 10   # (shingle_size - 1) x detector_interval
    #   key:
    #     ad: data.entity_keyword
    #     signature: [data.dstuser, data.srcuser, data.user, data.username]
    tiers:
      tier1_min: 0.15
      tier1_max: 0.33
      tier2_max: 0.55
    mitigations_tier2:
      - firewall-drop
    mitigations_tier3:
      - firewall-drop
      - lock_user_linux.sh
    allow_mitigation: false
```

Check that every tier you configure can be reached with your weights; see [Reachable tiers](../radar-tuning.md#reachable-tiers). DECIPHER is only asked for a CTI score for scenarios listed in `DecipherClient.ANALYZE_ENDPOINTS` in `radar_ar.py` (today `suspicious_login` and `scanning_detection`); for any other scenario name the CTI score is 0. With these values, a 210027 alert alone therefore scores at most 0.4 × 0.95 × 0.8 = 0.304 (tier 1). Once a DECIPHER endpoint is mapped for the scenario (step 7), it can reach 0.304 + 0.3 × 1.0 = 0.604, tier 3 on a strong CTI match, without any anomaly evidence. In the shipped `suspicious_login`, a signature alert alone scores at most 0.468 and needs fused anomaly evidence for tier 3. [Combining signature and anomaly alerts](../radar-tuning.md#combining-signature-and-anomaly-alerts-fusion) explains the `fusion` block.

### 6. Check the scenario file layout

Deployment reads each scenario's files from per-type folders named after the scenario, so keep the files where steps 2 to 4 put them:

```
radar/scenarios/decoders/suspicious_login_rdp/0320-rdp.xml
radar/scenarios/rules/suspicious_login_rdp/a3-suspicious-login-rdp.xml
radar/scenarios/ossec/radar-suspicious-login-rdp-ossec-snippet.xml
radar/scenarios/agent_configs/suspicious_login_rdp/   # optional: the agent group's agent.conf snippet
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

Then register it, and map a DECIPHER analyze endpoint if the scenario should get a CTI score (otherwise its CTI score is 0):

```python
class Registry:
    def __init__(self, logger: Logger, os_client: OpenSearchClient):
        self._default = BaseScenario(logger, os_client)
        self._map = {
            "suspicious_login": SuspiciousLogin(logger, os_client),
            "suspicious_login_rdp": SuspiciousLoginRDP(logger, os_client),
            # ... other scenarios
        }

class DecipherClient:
    ANALYZE_ENDPOINTS = {
        "suspicious_login": "/api/v1/analyze/suspicious_login",
        "suspicious_login_rdp": "/api/v1/analyze/suspicious_login",  # an endpoint DECIPHER serves
        "scanning_detection": "/api/v1/analyze/suspicious_nt_scanning",
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
   sudo ./radar.sh build suspicious_login_rdp
   ```

2. **Verify rule files deployed**:
   ```bash
   docker exec -it wazuh.manager bash
   ls -l /var/ossec/etc/rules/a3-suspicious-login-rdp.xml
   ls -l /var/ossec/etc/decoders/0320-rdp.xml
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
   
   # radar_ar.py writes its own entries to the same file (AR_LOG_FILE); find the scenario it identified
   docker exec -it wazuh.manager grep 'Scenario identified' /var/ossec/logs/active-responses.log
   ```

---

## Common pitfalls

1. **Forgetting GeoIP enrichment**: Impossible travel rules require `radar_country_change_i` and `radar_geo_velocity_kmh` fields. Ensure the manager-side enrichment integration (`custom-radar-enrich`, see the [suspicious login manual setup](./suspicious_login_explained.md#manager-side-setup)) is deployed and enriches the protocol's log lines; it parses only SSH lines today.

2. **Rule ID conflicts**: Use a new range for each protocol. SSH uses 210013, 210020–210022, 210030–210031 and 210039–210041; the examples here use 210023–210027 for RDP and 210028 for web. Check `a3-suspicious-login.xml` before picking a range.

3. **Decoder parent mismatches**: Ensure decoder `<parent>` references match the actual log format parent decoder.

4. **Active response location**: Use `<location>server</location>` for centralized analysis, or `<location>local</location>` for agent-side response.

5. **Time window mismatches**: Ensure `delta_signature_minutes` in config matches the context window your rules correlate over.

---

## Example: web authentication

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
