---
active: true
derived: false
level: 2.12
links:
- SRS-055: Hm7JBBZfnHwAw8aqU35M6JZid7yQicBJjWCT0oqUEFI=
- SRS-068: -z4KtFVs6E8dQfxlWTv0m-w72QVcvMmgc6jTvbLt-zQ=
normative: true
ref: ''
release: Alpha
reviewed: ogTXYskn3CWX4j41bOqhnpK_k9h8N_DXp1TA5PWKd9s=
version: '0.1'
---

# RADAR GeoIP detection scenario flow

This item describes the end-to-end flow of the `geoip_detection` scenario, which uses signature rules to detect and block access from non-whitelisted countries (SRS-055).

## Scenario overview

GeoIP detection is a **signature-based** scenario with no anomaly detector. It relies on:

- manager-side GeoIP enrichment by Wazuh integrations (SRS-068; replaces the former endpoint-side RADAR helper),
- RADAR-aware decoders that read the enrichment,
- rules that look the country up in a CDB whitelist,
- the RADAR active response for notification and blocking.

## Flow stages

### 1. Source events on the endpoint
- SSH authentication lines in `/var/log/auth.log`, collected through the `radar_shared` agent group.
- Apache access logs (`/var/log/apache2/access.log`, `other_vhosts_access.log`), collected through the `geoip_detection` agent group.

### 2. First pass on the manager
- The stock decoders and rules classify the events (`authentication_success` / `authentication_failed`, `accesslog`). Only an event that produces an alert reaches the integrations; a plain 2xx/3xx web request stays at level 0.

### 3. Enrichment (SRS-068)
- `custom-radar-enrich` (groups `authentication_success`, `authentication_failed`) looks the source IP up in GeoLite2 City and ASN, updates the user's travel state, and appends a `RADAR ...` tail (country, region, city, ASN, geo-velocity, country change, ASN novelty) to the original line in `/var/ossec/logs/radar/enriched_auth.log`.
- `custom-radar-web-enrich` (group `accesslog`) skips private addresses and appends `RADAR country="…" region="…" city="…" lat="…" lon="…"` to `/var/ossec/logs/radar/enriched_web_access.log`.
- The manager reads both files back as `localfile` inputs.

### 4. Decoding of the enriched lines
- `0310-ssh.xml` (`sshd-success-with-radar`, `ssh-failed-with-radar`, `ssh-invfailed-with-radar`) and `0375-web-accesslog.xml` (`web-accesslog-*-radar`) extract `radar_country` and the other `radar_*` fields. They replace the stock `0310-ssh_decoders.xml` and `0375-web-accesslog_decoders.xml`, which are excluded in `ossec.conf`.

### 5. Rule evaluation
- **100900**: `authentication_success` and `radar_country` not in `etc/lists/whitelist_countries`.
- **100901**: `authentication_success` and `srcgeoip` not Luxembourg, France, Germany or Belgium (fallback; needs Wazuh's legacy GeoIP support).
- **100902**: `accesslog` and `radar_country` not in the whitelist.
- **100903** (level 12): 300 matches of 100902 within 300 seconds.

### 6. Active response trigger
- Rules 100900, 100901 and 100903 invoke the `radar_ar_geoip` command (`radar_ar.py`) on the manager.

### 7. Active response processing (LARC-026)
- Scenario `geoip_detection`, detection `signature`; context: the alert agent's events in the last `delta_signature_minutes`.
- No DECIPHER analysis endpoint: $T = 0$.
- Risk: $R = 1.0 \cdot (0.9 \times 0.6) = 0.54$ for the bound rules, Tier 2 with the default boundaries.
- Tier 1 and above: email and, if DECIPHER is reachable, a Flowintel case. Tier 2 and 3: `firewall-drop` of the alert's source IP when `allow_mitigation` is true (shipped value), unless the IP is protected by `global.never_block`.

### 8. Logging
- The decision is recorded in `/var/ossec/logs/active-responses.log` (SRS-061).

## Configuration

- **Whitelist** (`radar/scenarios/lists/geoip_detection/whitelist_countries`, deployed as `etc/lists/whitelist_countries`): one ISO 3166-1 alpha-2 code per line followed by a colon; shipped `LU`, `DE`, `FR`, `BE`.
- **ar.yaml** (`geoip_detection`): see the abbreviated block in LARC-026.

## Key characteristics

- **Real time**: no training phase.
- **Deterministic**: rule matching against a list; only the response tier is scored.
- **Operational flexibility**: the whitelist is a list file, changed without retraining or code changes.

See also:

- docs/manual/radar_docs/radar-scenarios/geoip_detection_explained.md
- `radar/manager-enrichment/` for the integrations
- `radar/scenarios/decoders/geoip_detection/` and `radar/scenarios/rules/geoip_detection/`

Related: HARC-004, HARC-014, LARC-025, LARC-026.