# GeoIP detection

## Objectives

**Example Scenario:** A user attempts to log in from a country that is not included in the approved whitelist of safe locations. Any login originating from a non-whitelisted country is considered unauthorized. This scenario aims to prevent access from risky or unexpected geographic locations, mitigating potential account compromise or unauthorized access.

Goal: Trigger alerts for unusual logins from non-whitelisted countries and enable automated responses (e.g., email notifications) for such suspicious events.

---

## Signature-based approach

### Detection

Detection relies on **custom rules, decoders, and whitelists**:

- **Rules (`/radar/scenarios/rules/geoip_detection/a2-geoip-detection.xml`)**
    - Match log events with unusual geographic origin.
    - **SSH login monitoring** (rules 100900, 100901): Detects successful SSH authentication from non-whitelisted countries.
    - **Web access log monitoring** (rule 100902, correlated by rule 100903): Detects HTTP/HTTPS requests from non-whitelisted countries (Apache, Nginx), with 100903 raising a higher-severity alert when 100902 recurs 300 times within 300 seconds. Active response is bound to 100900, 100901 and 100903 — a single rule 100902 match is recorded but does not by itself trigger a response.
- **Decoders**
    - Standard SSH decoder for authentication logs.
    - Apache/Nginx web accesslog decoder: Parses web server access logs and enriches them with GeoIP country information.
- **Whitelists (`/radar/scenarios/lists/whitelist_countries`)**
    - Lists countries considered safe for login and web access.
    - Events from these countries are ignored by the rules.

### Active Response Analysis

Active responses handle detected suspicious events:

- **`/radar/scenarios/active_responses/radar_ar.py`**
    - Computes a risk score for the alert via the RADAR risk engine and dispatches the response tier configured in `ar.yaml` — starting with an email notification at the lowest tier, and escalating to automated mitigations (`firewall-drop`) at higher tiers.
    - In the shipped `ar.yaml`, `geoip_detection` has `allow_mitigation: true`, so automated mitigations execute by default once this scenario is deployed. See [radar-active-response.md](../radar-active-response.md) for the full tiering model.

### Manual setup

We distinguish between:

- **Agent side** (the SSH host that produces `/var/log/auth.log`)
- **Manager side** (Wazuh manager where decoders, rules, and active responses live)

#### Prerequisites

- A functioning Wazuh deployment (manager and agents). For deployment instructions, refer to the [SOAR RADAR README](/radar/README.md).

#### Agent-side setup

> **Enrichment is manager-side, not agent-side.** Earlier revisions of RADAR ran a `radar-helper.py` process on each agent to perform GeoIP enrichment locally. That process no longer exists — enrichment now happens once, centrally, on the manager (see step 4 in Manager-side Setup below). The agent only needs the Wazuh agent itself, shipping its raw logs unmodified.

1. Install and enroll the Wazuh agent (e.g. via `bootstrap-agent.sh`, or your own Wazuh agent installation/enrollment process).
2. Configure the agent to monitor `/var/log/apache2/access.log` and `/var/log/apache2/other_vhosts_access.log`:
```
nano /var/ossec/etc/ossec.conf
```
And paste the content of `/radar/scenarios/agent_configs/geoip_detection/radar-geoip-detection-agent-snippet.xml` into the end of file before the tag `</ossec_config>`

3. For SSH-based detection (rules 100900/100901), also paste the content of `/radar/scenarios/agent_configs/_shared/radar-shared-auth-log-agent-snippet.xml`, which ships `/var/log/auth.log`.

4. Save the file and restart the agent:
```
systemctl restart wazuh-agent
```

#### Manager-side Setup

1. Copy the Apache/Nginx accesslog decoder to the manager:
```
cp /radar/scenarios/decoders/geoip_detection/0375-web-accesslog.xml /var/ossec/etc/decoders/0375-web-accesslog.xml
chmod 640 /var/ossec/etc/decoders/0375-web-accesslog.xml
chown root:wazuh /var/ossec/etc/decoders/0375-web-accesslog.xml
```

2. Copy the SSH decoder to the manager and ensure that it has the needed permissions `root:wazuh`:
```
cp /radar/scenarios/decoders/geoip_detection/0310-ssh.xml /var/ossec/etc/decoders/0310-ssh.xml
chmod 640 /var/ossec/etc/decoders/0310-ssh.xml
chown root:wazuh /var/ossec/etc/decoders/0310-ssh.xml
```
3. Ensure that the default `0310` SSH decoders are excluded from the configurations of manager:
```
nano /var/ossec/etc/ossec.conf
```
Add this line into the `ruleset` tag:
```
<decoder_exclude>0310-ssh_decoders.xml</decoder_exclude>
```
And add the whitelist inside of `ruleset` tag:
```
<list>etc/lists/whitelist_countries</list>
```
3. Ensure the whitelist exists in Wazuh Manager configurations by adding the country two-letter codes per each line, see an example in `/radar/scenarios/lists/whitelist_countries`:
```
nano /var/ossec/etc/lists/whitelist_countries
chmod 640 /var/ossec/etc/lists/whitelist_countries
chown root:wazuh /var/ossec/etc/lists/whitelist_countries
```
4. Copy the files in `/radar/scenarios/rules/geoip_detection` into the `/var/ossec/etc/rules/`
5. Copy the `/radar/scenarios/active_responses/radar_ar.py` script into `/var/ossec/active-response/bin/` and ensure that it has proper permissions: 
```
cp /radar/scenarios/active_responses/radar_ar.py /var/ossec/active-response/bin/radar_ar.py
chmod 750 /var/ossec/active-response/bin/*.py
chown root:wazuh /var/ossec/active-response/bin/*.py
```
6. Download the `GeoLite2-City`/`GeoLite2-ASN` databases into `/var/ossec/etc/radar/` using your `MAXMIND_LICENSE_KEY`, and copy the manager-side enrichment integration scripts: `/radar/manager-enrichment/custom-radar-enrich` and `/radar/manager-enrichment/custom-radar-web-enrich` into `/var/ossec/integrations/`, and `/radar/manager-enrichment/geoip.py`, `/radar/manager-enrichment/state_store.py`, `/radar/manager-enrichment/enrichment.py`, `/radar/manager-enrichment/web_enrichment.py` into `/var/ossec/integrations/radar_enrichment/`.
7. Add the content of `/radar/scenarios/ossec/radar-geoip-detection-ossec-snippet.xml` inside `<ossec_config>` in `/var/ossec/etc/ossec.conf`. If SSH-based detection is also in use, add `/radar/scenarios/ossec/radar-shared-auth-log-ossec-snippet.xml` as well, which registers `custom-radar-enrich`.
8. Restart Wazuh manager:
```
/var/ossec/bin/wazuh-control restart
```
