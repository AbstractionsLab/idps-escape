# Web scanning detection

## Objectives

**Example Scenario:** A threat actor performs reconnaissance against a web application by sending high-frequency HTTP requests to discover web endpoints, or uses automated scanning tools like `nikto`, `sqlmap`, or `gobuster` to identify vulnerabilities. These activities generate high-volume request patterns and characteristic User-Agent signatures that can be detected and automatically blocked before exploitation attempts occur.

The objective is to detect web-layer scanning activity by identifying three complementary attack indicators, and confirming a scan only when at least two of them are observed from the same source IP within a short window:
1. **Volume-based detection** - high-frequency failed-request floods from a single source IP.
2. **Fingerprint-based detection** - HTTP requests carrying User-Agent strings from known web scanning and exploitation tools.
3. **Method-abuse detection** - requests using `TRACE`/`TRACK`/`CONNECT`, or WebDAV methods against a virtual host not on the WebDAV allowlist.

Requiring two corroborating indicators, rather than any single one, keeps the false-positive rate low: an isolated scanner User-Agent or an isolated burst of 404s is recorded but does not by itself raise an alert.

**Detection scope:** This scenario operates on Suricata's HTTP event stream (`eve.json`, Wazuh rule group `ids`), correlated with HTTP access logs from monitored web servers, enabling both rapid threat suppression and detailed attack attribution.

**Hybrid detection (rules + active response):** This scenario implements a signature-based detection pipeline augmented with automated response mechanisms. Rules detect scanning patterns with high confidence; upon detection, automated active responses block the source IP in the firewall and send SOC notifications. This approach provides both immediate threat suppression and situational awareness.

## Signature-based approach

This scenario implements a signature-based detection pipeline for web scanning. It combines HTTP access log analysis with Wazuh rules and active response automation.

### Log source

The primary log source is **Suricata's `eve.json`** event log on the monitored host, typically at `/var/log/suricata/eve.json`, which the detection rules match via the Wazuh `ids` rule group and Suricata's `http.*` fields (`http_user_agent`, `status`, `http_method`, `hostname`). The scenario's agent configuration also ships the web server's own access logs, useful for correlation and manual investigation:
- **Apache:** `/var/log/apache2/access.log` or `/var/log/apache2/other_vhosts_access.log`
- **Nginx:** `/var/log/nginx/access.log`

### End-to-end flow

1. **Raw HTTP events** are captured by Suricata and written to `/var/log/suricata/eve.json`; access logs are captured by Apache/Nginx in parallel.
2. **Wazuh agent** monitors both and forwards entries to the Wazuh manager.
3. **Rules** in `/radar/scenarios/rules/scanning_detection/a4-scanning-detection.xml` evaluate each Suricata HTTP event against the three indicators:
   - Rule 100810: Scanner User-Agent match (`sqlmap`, `nikto`, `nmap`, `gobuster`, and others in the shipped signature list)
   - Rule 100815 → 100825: Failed-request rate — 20 responses of 401/403/404 from the same source IP within 70 seconds
   - Rule 100820 / 100821: HTTP method abuse (`TRACE`/`TRACK`/`CONNECT`) or WebDAV methods on a virtual host not in the `radar_webdav_apps` allowlist
   - Rules 100826–100832: Correlate any two of the above indicators from the same source IP within 300 seconds
   - Rule 100830: The confirmed-scan alert — the only rule in this ruleset bound to active response
   - Rule 100835: An operational alert, raised if the scanning allowlist file cannot be read
4. **When rule 100830 fires:** Wazuh triggers the configured active response.
5. **RADAR risk engine** computes a risk score based on rule severity and historical context.
6. **Tier-based mitigation:** If the risk score exceeds the configured thresholds, RADAR automatically sends a notification and applies `firewall-drop`. In the shipped `ar.yaml`, `scanning_detection` ships with `allow_mitigation: false`, so mitigations are planned and logged but not executed until explicitly enabled.

This completes the scanning detection path for the `scanning_detection` scenario.

### Manual setup

This section describes how to manually deploy the **scanning detection scenario** on Wazuh.

#### Prerequisites

- A functioning Wazuh deployment (manager and agents). For deployment instructions, refer to the [RADAR README](/radar/README.md).
- **Suricata** installed on the monitored host and writing `/var/log/suricata/eve.json` with HTTP logging enabled — this is the primary detection source (see [Log source](#log-source) above).
- Apache or Nginx web server configured with HTTP access logging enabled, for correlation.
- Network connectivity from Wazuh agent to Wazuh manager.
- Firewall access on the Wazuh manager to execute `iptables` commands (for active response block operations).

#### Manager-side setup

1. Copy the scanning detection rules to the Wazuh manager configuration:
```bash
cp /radar/scenarios/rules/scanning_detection/a4-scanning-detection.xml \
   /var/ossec/etc/rules/a4-scanning-detection-rules.xml
```

2. Copy the scenario's CDB lists — the scanning allowlist and the WebDAV virtual-host allowlist — and register them in `ossec.conf`:
```bash
cp /radar/scenarios/lists/scanning_detection/radar_scanning_allowlist /var/ossec/etc/lists/
cp /radar/scenarios/lists/scanning_detection/radar_webdav_apps        /var/ossec/etc/lists/
chown root:wazuh /var/ossec/etc/lists/radar_scanning_allowlist /var/ossec/etc/lists/radar_webdav_apps
chmod 640       /var/ossec/etc/lists/radar_scanning_allowlist /var/ossec/etc/lists/radar_webdav_apps
```
Add both inside the `<ruleset>` tag:
```xml
<list>etc/lists/radar_scanning_allowlist</list>
<list>etc/lists/radar_webdav_apps</list>
```

3. Copy the scanning detection active-response snippet to the Wazuh configuration, and the `radar_ar.py` dispatcher script the snippet's `radar_ar_scanning` command invokes:
```bash
cat /radar/scenarios/ossec/radar-scanning-detection-ossec-snippet.xml \
   >> /var/ossec/etc/ossec.conf

cp /radar/scenarios/active_responses/radar_ar.py /var/ossec/active-response/bin/radar_ar.py
chmod 750 /var/ossec/active-response/bin/radar_ar.py
chown root:wazuh /var/ossec/active-response/bin/radar_ar.py
```

4. Copy the agent configuration to the manager's scenario-specific group, rather than the fleet-wide `default` group, so only endpoints assigned to `scanning_detection` receive it:
```bash
mkdir -p /var/ossec/etc/shared/scanning_detection
cp /radar/scenarios/agent_configs/scanning_detection/radar-scanning-detection-agent-snippet.xml \
   /var/ossec/etc/shared/scanning_detection/agent.conf
```

5. Reload Wazuh configuration:
```bash
/var/ossec/bin/wazuh-control restart
```