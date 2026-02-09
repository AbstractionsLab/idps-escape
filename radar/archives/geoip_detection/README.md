# GeoIP detection

## Objectives

**Example Scenario:** A user attempts to log in from a country that is not included in the approved whitelist of safe locations. Any login originating from a non-whitelisted country is considered unauthorized. This scenario aims to prevent access from risky or unexpected geographic locations, mitigating potential account compromise or unauthorized access.

Goal: Trigger alerts for unusual logins from non-whitelisted countries and enable automated responses (e.g., email notifications) for such suspicious events.

---

## Signature-based approach

### Detection

Detection relies on **custom rules, decoders, and whitelists**:

- **Rules (`local_rules.xml`)**
    - Match log events with unusual geographic origin.
- **Whitelists (`whitelist_countries`)**
    - Lists countries considered safe for login.
    - Events from these countries are ignored by the rules.

### Active Response Analysis

Active responses handle detected suspicious events:

- **Email Notification (`email_ar.py`)**
    - Sends alert emails when a scenario rule is triggered.

### Manual setup

We distinguish between:

- **Agent side** (the SSH host that produces `/var/log/auth.log`)
- **Manager side** (Wazuh manager where decoders, rules, and active responses live)

#### Prerequisites

- A functioning Wazuh deployment (manager and agents). For deployment instructions, refer to the [SOAR RADAR README](/soar-radar/README.md).

#### Agent-side setup

1. Copy `soar-radar/radar-helper.py` to the target host into `/opt/radar/radar-helper.py`:
```bash
mkdir -p /opt/radar
mkdir -p /opt/radar/venv
chown user:user /opt/radar -R
chmod 755 /opt/radar
```
2. Ensure required Python packages are installed (paths must match what radar-helper.py expects):
```bash
apt-get update
apt-get install -y \
  python3 \
  python3-venv \
  python3-pip
python3 -m venv /opt/radar/venv
/opt/radar/venv/bin/pip install --upgrade pip
/opt/radar/venv/bin/pip install maxminddb
```
3. Ensure required GeoIP databases installed in the required paths:
```
mkdir -p /usr/share/GeoIP
chown user:user /usr/share/GeoIP
chmod 755 /usr/share/GeoIP
cp ../geoip/GeoLite2-City.mmdb /usr/share/GeoIP/GeoLite2-City.mmdb
cp GeoLite2-ASN.mmdb  /usr/share/GeoIP/GeoLite2-ASN.mmdb
```
4. Copy `radar-helper` service configurations and run it as a service so it continuously:
```
cp ../radar-helper.service /etc/systemd/system/radar-helper.service
systemctl daemon-reload
systemctl enable radar-helper.service
systemctl start radar-helper.service
```
5. Configure Wazuh agent to monitor /var/log/suspicious_login.log:
```
nano /var/ossec/etc/ossec.conf
```
And paste the content of `radar-agent-ossec-snippet.xml` into the end of file before the tag `</ossec_config>`

6. Save the file and restart the agent:
```
systemctl restart wazuh-agent
```

#### Manager-side Setup

1. Copy `0310-ssh.xml` to the manager and ensure that it has the needed permissions `root:wazuh`:
```
cp 0310-ssh.xml /var/ossec/etc/decoders/0310-ssh.xml
chmod 640 /var/ossec/etc/decoders/0310-ssh.xml
chown root:wazuh /var/ossec/etc/decoders/0310-ssh.xml
```
2. Ensure that the default `0310` SSH decoders are excluded from the configurations of manager:
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
3. Ensure the whitelist exists in Wazuh Manager configurations by adding the country two-letter codes per each line, see an example in `whitelist_countries`:
```
nano /var/ossec/etc/lists/whitelist_countries
chmod 640 /var/ossec/etc/lists/whitelist_countries
chown root:wazuh /var/ossec/etc/lists/whitelist_countries
```
4. Copy the content of `local_rules.xml` into the `/var/ossec/etc/rules/local_rules.xml`
5. Copy the `active_responses/email_ar.py` script into `/var/ossec/active-response/bin/` and ensure that it has proper permissions: 
```
cp active_responses/email_ar.py /var/ossec/active-response/bin/email_ar.py
chmod 750 /var/ossec/active-response/bin/*.py
chown root:wazuh /var/ossec/active-response/bin/*.py
```
6. Add the content of `radar-ossec-snippet.xml` inside `<ossec_config>` in `/var/ossec/etc/ossec.conf`.
7. Restart Wazuh manager:
```
/var/ossec/bin/wazuh-control restart
```
