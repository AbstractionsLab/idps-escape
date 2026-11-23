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
    - **SSH login monitoring** (rules 100900, 100901): Detects successful SSH authentication from non-whitelisted countries. Rule 100900 checks the enriched `radar_country` against the whitelist; rule 100901 uses Wazuh's own `srcgeoip` against a country list written in the rule itself (`Luxembourg|France|Germany|Belgium`), not the whitelist file, so edit the rule to change it.
    - **Web access log monitoring** (rule 100902, correlated by rule 100903): Detects HTTP/HTTPS requests from non-whitelisted countries (Apache, Nginx), with 100903 raising a higher-severity alert when 100902 recurs 300 times within 300 seconds.
- **Decoders**
    - Standard SSH decoder for authentication logs.
    - Apache/Nginx web accesslog decoder: Parses web server access logs, including the `RADAR country=...` tail that the manager-side enrichment appends (`radar_country`, `radar_region`, `radar_city`).
- **Whitelists (`/radar/scenarios/lists/geoip_detection/whitelist_countries`)**
    - Lists countries considered safe for login and web access.
    - Events from these countries are ignored by rules 100900 and 100902.

### Active response analysis

Active responses handle detected suspicious events:

- **`/radar/scenarios/active_responses/radar_ar.py`**
    - Computes a risk score for the alert via the RADAR risk engine and dispatches the response tier configured in `ar.yaml` — starting with an email notification at the lowest tier, and escalating to automated mitigations (`firewall-drop`) at higher tiers.
    - In the shipped `ar.yaml`, `geoip_detection` has `allow_mitigation: true`, so `firewall-drop` runs by default once this scenario is deployed: an alert from rule 100900, 100901 or 100903 scores 0.54 (T2) and blocks its source IP. Rule 100902 is not bound to the active response (the snippet's `rules_id` is `100900,100901,100903`), so a single web request triggers no response; it only feeds the 100903 frequency rule. This scenario has no CTI source, so all of its weight is on the signature (`w_sig: 1.0`). Add gateways and admin subnets to `global.never_block` before deploying. See [Reachable tiers](../radar-tuning.md#reachable-tiers) and [Tiers](../radar-tuning.md#tiers) for the full tiering model.

### Manual setup

We distinguish between:

- **Agent side** (the SSH host that produces `/var/log/auth.log`)
- **Manager side** (Wazuh manager where decoders, rules, and active responses live)

#### Prerequisites

- A functioning Wazuh deployment (manager and agents). For deployment instructions, refer to the [SOAR RADAR README](/radar/README.md).

#### Agent-side setup

> **Enrichment is manager-side, not agent-side.** Earlier revisions of RADAR ran a `radar-helper.py` process on each agent to perform GeoIP enrichment locally. That process no longer exists — enrichment now happens once, centrally, on the manager (see step 7 in Manager-side setup below). The agent only needs the Wazuh agent itself, shipping its raw logs unmodified.

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

#### Manager-side setup

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
3. Ensure that the default `0310` SSH and `0375` web access-log decoders are excluded from the configurations of manager:
```
nano /var/ossec/etc/ossec.conf
```
Add these lines into the `ruleset` tag, since the copied decoders replace Wazuh's default SSH and web access-log decoders:
```
<decoder_exclude>0310-ssh_decoders.xml</decoder_exclude>
<decoder_exclude>0375-web-accesslog_decoders.xml</decoder_exclude>
```
And add the whitelist inside of `ruleset` tag:
```
<list>etc/lists/whitelist_countries</list>
```
4. Ensure the whitelist exists in Wazuh Manager configurations by adding the country two-letter codes per each line, see an example in `/radar/scenarios/lists/geoip_detection/whitelist_countries`:
```
nano /var/ossec/etc/lists/whitelist_countries
chmod 640 /var/ossec/etc/lists/whitelist_countries
chown root:wazuh /var/ossec/etc/lists/whitelist_countries
```
5. Copy the files in `/radar/scenarios/rules/geoip_detection` into the `/var/ossec/etc/rules/`
6. Copy the `/radar/scenarios/active_responses/radar_ar.py` script, its scenario configuration `ar.yaml` and its settings file (`active_responses.env`, only the keys the active response needs, filtered from `/radar/.env`) into `/var/ossec/active-response/bin/`, and ensure that they have proper permissions. Without `ar.yaml`, `radar_ar.py` matches no scenario and does nothing. `--os-url` is the indexer address as the manager reaches it, and `--manager-address` the manager's own address(es), which are never blocked. Keep `AR_RISK_CONFIG=/var/ossec/active-response/bin/ar.yaml` in `.env`, as in `env.example`.
```
cd /radar
PYTHONPATH=/radar python3 -m wazuh_api.ar_env write /var/ossec/active-response/bin/active_responses.env \
  --env-file /radar/.env --os-url https://<indexer-host>:9200 --manager-address <manager-ip>
cp /radar/scenarios/active_responses/radar_ar.py /var/ossec/active-response/bin/radar_ar.py
cp /radar/scenarios/active_responses/ar.yaml /var/ossec/active-response/bin/ar.yaml
chown root:wazuh /var/ossec/active-response/bin/active_responses.env /var/ossec/active-response/bin/radar_ar.py /var/ossec/active-response/bin/ar.yaml
chmod 0440 /var/ossec/active-response/bin/active_responses.env
chmod 0750 /var/ossec/active-response/bin/radar_ar.py
chmod 0640 /var/ossec/active-response/bin/ar.yaml
```
7. Download the `GeoLite2-City`/`GeoLite2-ASN` databases into `/var/ossec/etc/radar/` using your `MAXMIND_LICENSE_KEY`, and copy the manager-side enrichment integration scripts: `/radar/manager-enrichment/custom-radar-enrich` and `/radar/manager-enrichment/custom-radar-web-enrich` into `/var/ossec/integrations/`, and `/radar/manager-enrichment/geoip.py`, `/radar/manager-enrichment/state_store.py`, `/radar/manager-enrichment/enrichment.py`, `/radar/manager-enrichment/web_enrichment.py` into `/var/ossec/integrations/radar_enrichment/`.
8. Add the content of `/radar/scenarios/ossec/radar-geoip-detection-ossec-snippet.xml` inside `<ossec_config>` in `/var/ossec/etc/ossec.conf`. If SSH-based detection is also in use, add `/radar/scenarios/ossec/radar-shared-auth-log-ossec-snippet.xml` as well, which registers `custom-radar-enrich`.
9. Restart Wazuh manager:
```
/var/ossec/bin/wazuh-control restart
```
