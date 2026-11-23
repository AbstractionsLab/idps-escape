# Suspicious login

## Signature-based approach

This scenario implements a hybrid detection pipeline for suspicious logins. Its signature side combines local log enrichment with Wazuh decoders, rules, and active responses. Its anomaly side is off-hours activity against declared working hours, reported by a rule monitor or by a per-user anomaly detector (OpenSearch Alerting and anomaly detection). RADAR combines the two over time for the same user; see [Off-hour anomalies and fusion](#off-hour-anomalies-and-fusion).


### Log source

The primary log source for this scenario is the Linux authentication log: `/var/log/auth.log`, on the monitored agent. This file contains raw SSH authentication events produced by `sshd` (both successful and failed login attempts). The agent ships it to the manager via the shared `auth_log_enrichment` configuration (`scenarios/agent_configs/_shared/radar-shared-auth-log-agent-snippet.xml`).

### Log enrichment

Enrichment happens entirely on the **manager side**, via a Wazuh integration — no agent-side helper process is involved. The pipeline works in two passes:

1. Wazuh's own stock `sshd` decoder and rules first classify the raw `auth.log` line as an `authentication_success` or `authentication_failed` event. This triggers the `custom-radar-enrich` integration (registered in `scenarios/ossec/radar-shared-auth-log-ossec-snippet.xml`, implemented in `manager-enrichment/`).
2. The integration script re-parses the alert's original log line independently of Wazuh's own decoding, looks up GeoIP/ASN context for the source IP via MaxMind databases (`manager-enrichment/geoip.py`), and tracks each user's recent login history to compute geo-velocity and ASN novelty (`manager-enrichment/state_store.py`). It then appends a `RADAR outcome='...' asn='...' country='...' geo_velocity_kmh='...' ...` tail to the original log line, and writes the result to `/var/ossec/logs/radar/enriched_auth.log`.

Wazuh also monitors `enriched_auth.log` directly (via a second `<localfile>` block in the same shared snippet), so this enriched line gets decoded a second time — this second pass is what the `-with-radar` decoders below are for.

### Wazuh decoders

The enriched entries in `/var/ossec/logs/radar/enriched_auth.log` are parsed by Wazuh using decoders defined in `scenarios/decoders/suspicious_login/0310-ssh.xml`. At the end of this file, specific decoders are defined to handle enriched SSH events:
- `sshd-success-with-radar`
- `ssh-failed-with-radar`
- `ssh-invfailed-with-radar`

**Role of these decoders:** Parse the enriched log format produced by the manager-side enrichment integration. These extract both standard SSH fields (e.g., user, IP, port, result) and enrichment fields (ASN, country, geo-velocity, etc.).

### Detection logic

The parsed events are then evaluated by rules defined in `scenarios/rules/suspicious_login/`, namely rules starting with `210XXX`. These rules implement the **signature-based detection logic**, including:

- **Failed-login bursts**  
  Rules that detect repeated failed SSH authentication attempts within a defined time window (e.g., multiple failures for the same user in a short period).

- **Impossible travel / abnormal geo-velocity**  
  Rules that use the geo-velocity information produced by the manager-side enrichment integration to detect login patterns that are not physically plausible (e.g., logins from distant countries within an unrealistically short time frame).

- **Office 365 login failures**  
  Rule 210030 marks an O365 `UserLoginFailed` event and rule 210031 raises a brute-force alert for 3 failures of the same `office365.UserId` within 300 seconds. They need Wazuh's Office 365 integration (base rule 91545).

When rule conditions are satisfied, Wazuh generates an alert for the corresponding suspicious login behavior.

### Active response

Once a rule from `scenarios/rules/suspicious_login/` fires, Wazuh triggers the configured active response defined in `scenarios/ossec/radar-suspicious-login-ossec-snippet.xml`. This snippet binds the rule IDs starting with `210XXX` to the `radar_ar_suspicious_login` command, which dispatches to `scenarios/active_responses/radar_ar.py`.

`radar_ar.py` computes a risk score for the alert via the RADAR risk engine and dispatches the response tier configured in `ar.yaml`:
  - At the lowest tier, it formats contextual information about the suspicious login event and delivers an email notification to the configured recipients — SMTP configuration is set in the `/radar/.env` file. Without a CTI score, an impossible-travel alert (210020/210021, likelihood 0.4) scores 0.4 × 0.4 × 0.7 = 0.112, below `tier1_min` (0.15), so it sends no email unless DECIPHER or fusion raises it; the 0.6-likelihood rules score 0.168 (T1).
  - At higher tiers it escalates to automated mitigations, `firewall-drop` and `lock_user_linux.sh`. In the shipped `ar.yaml`, `suspicious_login` has `allow_mitigation: true`, so these mitigations execute by default once the scenario is deployed. With the shipped weights, `firewall-drop` (T2) runs on a signature alert only when DECIPHER returns a high CTI score. `lock_user_linux.sh` (T3, from 0.55) needs both: the user's signature alert combined with an off-hour anomaly reaches at most 0.168 + 0.3 = 0.468 without CTI, so DECIPHER must also return a CTI score of at least about 0.27 (0.46 for 210020/210021), and more when the anomaly is weaker than 1.0 or the two alerts are far apart in time; see [Reachable tiers](../radar-tuning.md#reachable-tiers). `lock_user_linux.sh` only ever targets the user named in the alert itself, never other users found in the agent's logs. See [Tiers](../radar-tuning.md#tiers) for the full tiering model.

### End-to-end flow

1. **Raw logs** are generated by `sshd` and written to `/var/log/auth.log` on the agent, shipped to the manager.
2. **Wazuh's stock decoders/rules** classify the event as `authentication_success`/`authentication_failed`, triggering the `custom-radar-enrich` integration on the manager.
3. **The enrichment integration** (manager-side) looks up GeoIP/ASN context, computes geo-velocity and ASN novelty against the user's recent history, appends a `RADAR outcome=...` tail to the line, and writes it to `/var/ossec/logs/radar/enriched_auth.log`.
4. **Wazuh** also monitors `enriched_auth.log`.
5. **Decoders** in `0310-ssh.xml` (`sshd-success-with-radar`, `ssh-failed-with-radar`, `ssh-invfailed-with-radar`) parse this second pass of enriched SSH events into structured fields.
6. **Rules** in `scenarios/rules/suspicious_login/` apply signature-based logic to detect failed-login bursts and impossible travel patterns.
7. **Active responses** configured in `scenarios/ossec/radar-suspicious-login-ossec-snippet.xml` are executed when rules fire, dispatching to `radar_ar.py`, which scores the alert and triggers the response tier configured in `ar.yaml` — an email notification at the lowest tier, escalating to `firewall-drop` and `lock_user_linux.sh` at higher tiers.

This completes the signature-based suspicious login detection path for the `suspicious_login` scenario.

### Off-hour anomalies and fusion

Off-hours activity is judged against declared working hours, set per schedule group in `scenarios.suspicious_login.off_hours` of `radar/config.yaml`. An ingest pipeline marks each archived event of a listed user with `radar.off_hours`. Each group picks one of two consumers:

- **Rule mode** (rule 210041): reports the start of every off-hours burst, for staff who never work off hours.
- **Model mode** (rule 210040): a per-user detector learns each user's usual number of off-hours events and reports an unusual one, for administrators and on-call staff.

See [Off-hours activity](./off-hours-activity.md) for the configuration, the commands and the checks.

Both reach Wazuh the same way:

1. The monitor posts the alert to the RADAR webhook, which writes it to `/var/log/ad_alerts.log`. The entity is the username; rule-mode lines also carry `off_hours_count` and `schedule_group`.
2. Wazuh decodes it with `0001-ad-common.xml` and raises rule 210041 or 210040 (level 10).
3. `radar_ar.py` scores both as the scenario's anomaly side (`ad.rule_ids` in `ar.yaml`). Their context is that user's events on every agent, not the webhook agent's logs, and DECIPHER is asked about that user.

Fusion (`fusion:` in `ar.yaml`, enabled for this scenario) then combines each alert with the strongest alert of the other kind for the same user within 30 minutes:

- A failed-burst or impossible-travel alert for a user who had an off-hours alert gets that alert's score as well, discounted by the time between them. This is the only way to reach T3 (`lock_user_linux.sh`), and it also needs a DECIPHER CTI score (see above); the lock targets the user named in the signature alert.
- An off-hours alert for a user who just had signature alerts gets their strongest signature score. Such a decision notifies, and opens a case when DECIPHER is configured, but blocks or locks nothing: an anomaly alert names no source IP and no Linux user.

See [Combining signature and anomaly alerts](../radar-tuning.md#combining-signature-and-anomaly-alerts-fusion) for the parameters. Rule mode works from the first event; model mode needs a baseline first (the synthetic history, or a few weeks of real data marked by the backfill). To test fusion without either, inject an anomaly with `radar-test-framework/simulate/scenarios/inject_ad_alert.py` (see the [simulation README](../../../../radar/radar-test-framework/simulate/README.md)).

### Manual setup

This section describes how to manually deploy the **signature-based suspicious login scenario** on Wazuh.

We distinguish between:

- **Agent side** (the SSH host that produces `/var/log/auth.log`)
- **Manager side** (Wazuh manager where decoders, rules, and active responses live)

---

#### Prerequisites

- A functioning Wazuh deployment (manager and agent). For deployment instructions, refer to the [SOAR RADAR README](/radar/README.md).
- A MaxMind GeoLite2 license key (`MAXMIND_LICENSE_KEY` in `/radar/.env`). The automated deployment (`build-radar.sh`) downloads the `GeoLite2-City`/`GeoLite2-ASN` databases to the manager itself; in a manual setup you download them (step 5 below). Nothing needs to be installed on the agent.

---

#### Agent-side setup

The agent side only needs the Wazuh agent itself installed and enrolled, with SSH log collection configured — no additional helper process runs on the agent; GeoIP enrichment happens entirely on the manager side (see below).

1. Install and enroll the Wazuh agent (e.g. via `bootstrap-agent.sh`, or your own Wazuh agent installation/enrollment process).
2. Configure the agent to monitor `/var/log/auth.log`:
```
nano /var/ossec/etc/ossec.conf
```
And paste the content of `/radar/scenarios/agent_configs/_shared/radar-shared-auth-log-agent-snippet.xml` into the end of file before the tag `</ossec_config>`

3. Save the file and restart the agent:
```
systemctl restart wazuh-agent
```

#### Manager-side setup

1. Copy `/radar/scenarios/decoders/suspicious_login/0310-ssh.xml` to the manager and ensure that it has the needed permissions `root:wazuh`:
```
cp /radar/scenarios/decoders/suspicious_login/0310-ssh.xml /var/ossec/etc/decoders/0310-ssh.xml
chmod 640 /var/ossec/etc/decoders/0310-ssh.xml
chown root:wazuh /var/ossec/etc/decoders/0310-ssh.xml
```
   For the off-hours side, also copy `/radar/scenarios/decoders/suspicious_login/0001-ad-common.xml` the same way (the same file ships with the other anomaly scenarios; any copy will do). The Filebeat step that calls the off-hours ingest pipeline is added to the manager's mounted archives pipeline by `sudo ./radar.sh build suspicious_login`; the pipeline itself, the monitors and the detector are set up by `run-radar.sh` from the RADAR host; see [Off-hours activity](./off-hours-activity.md#commands).
2. Ensure that the default `0310` SSH decoders are excluded from the configurations of manager:
```
nano /var/ossec/etc/ossec.conf
```
And add this line into the `ruleset` tag:
```
<decoder_exclude>0310-ssh_decoders.xml</decoder_exclude>
```
3. Copy the content of `/radar/scenarios/rules/suspicious_login` into the `/var/ossec/etc/rules/`
4. Copy the `/radar/scenarios/active_responses/radar_ar.py` dispatcher, its scenario configuration `ar.yaml` and its settings file (`active_responses.env`, only the keys the active response needs, filtered from `/radar/.env`) into `/var/ossec/active-response/bin/`. Without `ar.yaml`, `radar_ar.py` matches no scenario and does nothing. `--os-url` is the indexer address as the manager reaches it, and `--manager-address` the manager's own address(es), which are never blocked. Keep `AR_RISK_CONFIG=/var/ossec/active-response/bin/ar.yaml` in `.env`, as in `env.example`.
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
The `lock_user_linux.sh` mitigation (highest tier) runs on the endpoint, not on the manager: `radar_ar.py` sends it to the agent where the login happened. The snippet in step 6 only declares the command. On each endpoint, copy the script into the agent's active response folder:
```
cp /radar/radar-agent/active_responses/lock_user_linux_v1.sh /var/ossec/active-response/bin/lock_user_linux.sh
chmod 750 /var/ossec/active-response/bin/lock_user_linux.sh
chown root:wazuh /var/ossec/active-response/bin/lock_user_linux.sh
```
`lock_user_linux.sh` needs `jq`, and refuses to act without it. It never locks or unlocks `root`, accounts with UID < 1000, `nobody`, or accounts listed one per line in the optional `/var/ossec/etc/radar-protected-users`. To keep shared admin accounts from being locked, also list them under `protected_users` for `suspicious_login` in `ar.yaml`. Endpoints onboarded with `bootstrap-agent.sh` get the script and `jq` installed automatically, whatever their group. See [Mitigations](../radar-tuning.md#mitigations).
5. Download the `GeoLite2-City`/`GeoLite2-ASN` databases into `/var/ossec/etc/radar/` using your `MAXMIND_LICENSE_KEY`, and copy the manager-side enrichment integration script: `/radar/manager-enrichment/custom-radar-enrich` into `/var/ossec/integrations/`, and `/radar/manager-enrichment/geoip.py`, `/radar/manager-enrichment/state_store.py`, `/radar/manager-enrichment/enrichment.py` into `/var/ossec/integrations/radar_enrichment/`.
6. Add the content of `/radar/scenarios/ossec/radar-suspicious-login-ossec-snippet.xml` and of `/radar/scenarios/ossec/radar-shared-auth-log-ossec-snippet.xml` inside `<ossec_config>` in `/var/ossec/etc/ossec.conf`. The shared snippet registers the `custom-radar-enrich` integration and the `enriched_auth.log` localfile; without it no login is enriched and the impossible-travel rules never fire.
7. Restart Wazuh manager:
```
/var/ossec/bin/wazuh-control restart
```