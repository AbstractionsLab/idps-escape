---
active: true
derived: false
level: 2.9
links:
- SRS-068: -z4KtFVs6E8dQfxlWTv0m-w72QVcvMmgc6jTvbLt-zQ=
normative: true
ref: ''
release: Alpha
reviewed: fgrNDgr3tSiG80BrYrhOM5ZSAN_gdGrKHobBd3ZXYEA=
version: '0.1'
---

# RADAR manager-side enrichment pipeline

This item describes the log enrichment pipeline that runs on the Wazuh manager for the `suspicious_login` and `geoip_detection` scenarios (HARC-014). It replaced the per-endpoint RADAR helper daemon, removed in v2.0.0.

## Pipeline overview

Endpoints forward their raw authentication and web-access logs. The manager classifies each line with Wazuh's stock decoders and rules; an alert in a relevant group triggers an enrichment integration, which appends geographic and behavioural context to the original line and writes it to a file the manager monitors. The enriched line is decoded a second time, and the scenario rules match on the added `radar_*` fields.

| Path | Trigger (rule groups) | Integration | Output file |
|---|---|---|---|
| Authentication | `authentication_success`, `authentication_failed` | `custom-radar-enrich` | `/var/ossec/logs/radar/enriched_auth.log` |
| Web access (`geoip_detection` only) | `accesslog` | `custom-radar-web-enrich` | `/var/ossec/logs/radar/enriched_web_access.log` |

Both integrations and their `<localfile>` entries are declared in the manager snippets `radar/scenarios/ossec/radar-shared-auth-log-ossec-snippet.xml` and `radar/scenarios/ossec/radar-geoip-detection-ossec-snippet.xml`, and installed by `radar/radar_deploy/manager-apply-scenario.sh`.

## Pipeline stages (authentication path)

### 1. Trigger and loop guard

`integratord` passes the alert to `custom-radar-enrich`. If the alert's `full_log` already carries a RADAR tail, the line is an enriched line on its second pass, and the integration exits without output.

### 2. Parsing

The integration parses the event timestamp, user, source IP and outcome (`success` or `failure`) from the original `sshd` log line itself, not from Wazuh's decoded fields, which the scenario decoders fill only once a tail exists. Accepted and failed logins, including invalid users, are recognised; any other line produces no output. The timestamp is the log line's own (syslog or ISO 8601), so velocity is computed on event time, not processing time.

### 3. Geographic lookup

`geoip.py` looks up the source address in the MaxMind GeoLite2 City and ASN databases (`/var/ossec/etc/radar/`): ISO country code, first subdivision, city, latitude, longitude and ASN. A missing ASN sets `asn_placeholder_flag` to `true`.

### 4. User state

`state_store.py` loads the user's state from the SQLite database `/var/ossec/etc/radar/user_state.sqlite3`, keyed by user name and shared by all endpoints: last event time, last position, last country, and the ASN history of the last 90 days.

### 5. Behavioural indicators

- **Geo-velocity**: great-circle (haversine) distance between the previous and current positions divided by the time between the two events: $v = d_{km} / \max(|\Delta t_h|, 10^{-9})$. It is 0 for the user's first located event. Velocity is not capped.
- **Country change**: 1 when the user's previous known country differs from the current one, else 0.
- **ASN novelty**: 1 when the ASN is not in the user's ASN history, else 0. History entries older than 90 days (relative to the event time) are dropped before the check.

The updated state is written back before the tail is emitted.

### 6. Enriched line

The original line is appended with a tail and written to `enriched_auth.log`, for example:

```
Nov 23 10:15:02 web01 sshd[4242]: Accepted password for alice from 203.0.113.42 port 52111 ssh2 RADAR outcome='success' asn='64500' asn_placeholder_flag='false' country='US' region='California' city='San Francisco' geo_velocity_kmh='450.230' country_change_i='1' asn_novelty_i='0'
```

### 7. Second pass

The manager reads the file as syslog. The `-with-radar` decoders in `radar/scenarios/decoders/suspicious_login/0310-ssh.xml` (shipped identically for `geoip_detection`) extract the `radar_*` fields, and the rules evaluate them: for example impossible travel (velocity of at least 900 km/h with a country change) in `suspicious_login`, and a country outside the `whitelist_countries` CDB list in `geoip_detection`.

## Web-access path

`custom-radar-web-enrich` handles access-log lines (Apache or Nginx, plain or relayed through rsyslog). It extracts the client address, skips loopback and RFC 1918 addresses, and appends `RADAR country="…" region="…" city="…" lat="…" lon="…"`. It keeps no state and computes no velocity or novelty. The `geoip_detection` web decoders in `0375-web-accesslog.xml` read the tail.

## Failure handling

Any failure to read the alert, open a GeoIP database, update the state or write the output is appended to `/var/ossec/logs/radar/enrichment_errors.log`; the integration then exits without output. The first-pass alert is unaffected, so a broken enrichment never hides the original event. `radar/radar_deploy/manager-health.sh` reports missing integration files, databases, an unwritable state database and recent error-log entries (SRS-068).

## Implementation reference

`radar/manager-enrichment/` (`custom-radar-enrich`, `custom-radar-web-enrich`, `enrichment.py`, `web_enrichment.py`, `geoip.py`, `state_store.py`); design in SWD-030.

## See also

- `docs/manual/radar_docs/radar-scenarios/suspicious_login_explained.md`
- `docs/manual/radar_docs/radar-scenarios/geoip_detection_explained.md`

Related: HARC-014.