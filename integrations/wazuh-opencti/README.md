## 1\. Overview

The Wazuh-OpenCTI connector enhances Wazuh&#39;s detection and alerting capabilities by integrating it with the OpenCTI platform. It enriches security alerts with threat intelligence context from OpenCTI, enabling better threat correlation and enabling proactive response actions such as alert prioritization or automatic blocking via Wazuh&#39;s Active Response framework.

This documentation outlines the integration setup, configuration, testing, and an assessment of its usefulness in improving detection and response.

## 2\. Integration Architecture

*   **Wazuh Manager** receives alerts from agents.
    
*   **Custom Integration Script** (`custom-opencti.py`) is triggered based on specified rules or alert groups.
    
*   The script queries **OpenCTI GraphQL API** with relevant IoC data (e.g., IPs, hashes).
    
*   If a match is found, the script enriches the alert and sends it back into Wazuh’s alert pipeline via UNIX socket.
    

## 3\. Setup &amp; Configuration

### 3.1 Copying Integration Script

Copy `custom-opencti` and `custom-opencti.py` (files can be found in https://github.com/juaromu/wazuh-opencti) into Wazuh Manager:

```text
/var/ossec/integrations/
```

Ensure the files are executable (`chmod +x`).

### 3.2 Update /var/ossec/etc/ossec.conf

```xml
<integration>
   <name>custom-opencti</name>
   <group>syscheck_file,sysmon_eid3_detections,sysmon_eid22_detections,ids</group>
   <alert_format>json</alert_format>
   <api_key>YOUR_OPENCTI_API_KEY</api_key>
   <hook_url>http://opencti:8080/graphql</hook_url>
</integration>
```

> ⚠️ Replace api\_key and hook\_url with your actual values.

### 3.3 Add Custom Rules

Edit `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="threat_intel,">
   <rule id="100210" level="10">
      <field name="integration">opencti</field>
      <description>OpenCTI</description>
      <group>opencti,</group>
   </rule>
   <rule id="100211" level="5">
      <if_sid>100210</if_sid>
      <field name="opencti.error">\.+</field>
      <description>OpenCTI: Failed to connect to API</description>
      <options>no_full_log</options>
      <group>opencti,opencti_error,</group>
   </rule>
   <rule id="100212" level="12">
      <if_sid>100210</if_sid>
      <field name="opencti.event_type">indicator_pattern_match</field>
      <description>OpenCTI: IoC found in threat intel: $(opencti.indicator.name)</description>
      <options>no_full_log</options>
      <group>opencti,opencti_alert,</group>
   </rule>
   <rule id="100213" level="12">
      <if_sid>100210</if_sid>
      <field name="opencti.event_type">observable_with_indicator</field>
      <description>OpenCTI: IoC found in threat intel: $(opencti.observable_value)</description>
      <options>no_full_log</options>
      <group>opencti,opencti_alert,</group>
   </rule>
   <rule id="100214" level="10">
      <if_sid>100210</if_sid>
      <field name="opencti.event_type">observable_with_related_indicator</field>
      <description>OpenCTI: Possibly related IoC: $(opencti.related.indicator.name)</description>
      <options>no_full_log</options>
      <group>opencti,opencti_alert,</group>
   </rule>
   <rule id="100215" level="10">
      <if_sid>100210</if_sid>
      <field name="opencti.event_type">indicator_partial_pattern_match</field>
      <description>OpenCTI: Partial IoC match: $(opencti.indicator.name)</description>
      <options>no_full_log</options>
      <group>opencti,opencti_alert,</group>
   </rule>
</group>
```

### 3.5 Restart Wazuh Manager Control in docker container

```bash
/var/ossec/bin/wazuh-control restart
```

## 4\. Testing the Integration

### Use Case: File Hash Detection

1.  In OpenCTI, create an **Indicator**:
    
    *   Observable type: `File`
        
    *   Pattern: `[file:hashes.'SHA-256' = '3a7bd3e2360a3d80b04824c9aefed829254d12a2583eaa4f38d8e3f60e27c077']`
        
    *   Pattern type: `stix`
        
2.  On a monitored Wazuh agent:
    

```bash
echo 'malware' > /tmp/malicious_file.txt
sha256sum /tmp/malicious_file.txt
```

1.  Ensure `/tmp` is monitored by `syscheck` and wait for an alert.
    
2.  Observe new alert in:
    

```bash
docker exec -it <manager> tail -f /var/ossec/logs/alerts/alerts.json
```

## 5\. Assessment of usefulness

### 5.1 Threat Enrichment

The connector enriches Wazuh alerts with threat intelligence from OpenCTI, adding context such as indicator names, confidence levels, detection flags, threat types, and kill chain phases. This enables security analysts to better understand and prioritize incidents.

**Scenario:**

A security analyst receives a Wazuh alert indicating unusual file execution on a host. The alert contains a SHA-256 hash of the suspicious file. The connector automatically queries OpenCTI using that hash. OpenCTI returns additional intelligence showing that the file is linked to a known ransomware family, providing details such as the indicator name, confidence level, and the specific stage of the kill chain it targets (e.g., &quot;execution&quot;). With this enriched context, the analyst can quickly understand that the alert is linked to a ransomware campaign and can prioritize incident containment.

### 5.2 Correlation with Known Threats

By matching SHA-256 file hashes, IP addresses, domain names, or URLs with OpenCTI indicators, the connector allows Wazuh to identify known malicious entities in real-time. This reduces response times and supports incident correlation across endpoints and networks.

**Scenario:**

Wazuh detects network activity from an external IP address that exhibits suspicious behavior. The connector takes this IP address and consults OpenCTI. OpenCTI identifies it as an indicator previously associated with a known Advanced Persistent Threat (APT) group. The connector then correlates this information with other alerts that have shown similar patterns, thereby helping analysts link seemingly isolated events.

### 5.3 Proactive Detection

The integration is especially powerful in pre-execution detection. For example, Wazuh&#39;s `syscheck` can detect a file written to disk and trigger a lookup in OpenCTI before the file is ever executed. This proactive stance is essential in stopping malware early.

**Scenario:**

The Wazuh agent&#39;s syscheck module notices the creation of a new executable file in a sensitive directory on a critical server. Before the file is ever executed, the connector intercepts the event and extracts the file&#39;s hash. It then immediately queries OpenCTI to check if this hash has any associated threat intelligence. OpenCTI indicates that this file hash was recently seen in malware samples used in a pre-execution attack scenario. As a result, the connector flags the alert as high-risk even before any malicious activity occurs, allowing the security team to block execution proactively and prevent a potential compromise.

### 5.4 Active Response Enablement

When alerts are enriched with high-confidence threat indicators, they can be escalated to trigger automated Wazuh Active Responses.

**Scenario:**

During routine monitoring, Wazuh triggers an alert for a process communicating with an external server. The connector enriches this alert, and the intelligence from OpenCTI reveals that the process is part of a botnet command-and-control (C2) infrastructure. Recognizing the threat through high-confidence indicators, the connector then triggers an active response. For instance, the connector instructs Wazuh&#39;s Active Response module to automatically block the suspicious IP address and isolate the affected host from the network.

### 5.5 Real-Time Intelligence Application

Rather than relying on static signatures or rules, the connector allows Wazuh to act on fresh intelligence from OpenCTI. This is particularly useful for dealing with fast-evolving threats such as ransomware or APT campaigns.

**Scenario:**

A new ransomware campaign has emerged, and threat intelligence feeds through OpenCTI are continuously updated with fresh indicators. When Wazuh detects behavior consistent with malware, the connector immediately pulls the latest intelligence from OpenCTI and compares it against the alert data.

### 5.6 Alert Prioritization

With added context (e.g., OpenCTI score, detection confidence), alerts can be triaged more effectively. Events associated with high-confidence indicators can be assigned higher severity and routed to analysts faster.

**Scenario:**

Wazuh generates dozens of alerts from various endpoints. The connector processes each alert and enriches them with data from OpenCTI. During enrichment, some alerts are found to have indicators with high confidence scores and are linked to well-known threat actors targeting financial institutions. These alerts are then automatically flagged and assigned a higher priority in the incident management system.

### 5.7 Low False Positives

Matching against validated indicators with detection tags and revocation status from OpenCTI helps reduce noise. The filtering mechanisms implemented in the connector logic help ensure only relevant alerts are triggered.

**Scenario:**

A Wazuh alert is generated due to an unusual connection attempt to a domain that was once marked as suspicious. However, upon enrichment the connector contacts OpenCTI and discovers that the indicator for that domain has recently been revoked. Based on this updated context—including detection tags and revocation status—the connector suppresses the alert

## 6\. Conclusion

This integration transforms Wazuh into a more intelligence-driven detection and response platform.