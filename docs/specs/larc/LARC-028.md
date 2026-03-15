---
active: true
derived: false
level: 2.12
links:
- HARC-004: B-4i2SClF5iGbeV-cWw9l0nDiMns0PHC2fNuaqSQAmo=
- HARC-014: RXkcsJfH9zSPUQ5b1GZ_tcRQ7PRGe6A6TxCOFXi3UJk=
- LARC-025: RzzNYmMKi9eyZkK5_qa7Iq20a6YsJGXh8cjkEU6xy6k=
- LARC-026: Ga9LLhP4KMUK4ofaZY7Eh15_ZEQ_FIbOsCd8rgrwEyA=
- SRS-053: jfqrMY0E7WgN_fwk_1FLF43v0VDRJ2CvbAzt_me8VAM=
- SRS-055: ysWB5SJEBNrXmKQYG-xHmAiWmgdyjAcTkOqrg1qRW4g=
normative: true
ref: ''
release: Alpha
reviewed: BZLu__gBU6QIG_HlS0mE5hMS27w5Q5OlWoSYKAnbHFs=
version: '0.1'
---

# RADAR GeoIP detection scenario flow

The diagram below depicts the end-to-end flow for the GeoIP detection scenario, which uses signature-based detection to identify and block authentication attempts from non-whitelisted geographic locations.

## Scenario overview

GeoIP detection is a **signature-based** scenario that does not use anomaly detection. It relies on:

- Real-time log enrichment via RADAR Helper
- Custom decoders for field extraction
- Rules with country whitelist matching
- Active response for automated notification and optional mitigation

## Flow stages

### 1. Authentication event
- SSH authentication attempt recorded in `/var/log/auth.log` on monitored endpoint
- Event includes: timestamp, outcome (success/failure), username, source IP

### 2. RADAR Helper enrichment (see LARC-025)
- AuthLogWatcher detects new authentication event
- GeoLookup queries MaxMind databases for source IP
- Enrichment adds: country, region, city, ASN, geo_velocity_kmh, country_change_i, asn_novelty_i
- Writes enriched log to `/var/log/suspicious_login.log`

### 3. Wazuh agent ingestion
- Wazuh agent monitors `/var/log/suspicious_login.log`
- Reads enriched log line
- Forwards to Wazuh Manager

### 4. Decoder extraction
- Custom decoder (`0310-ssh.xml`) parses enriched log
- Extracts structured fields: `radar_outcome`, `radar_country`, `radar_src_ip`, `radar_user`, etc.
- Populates alert data structure

### 5. Rule evaluation
**Rule 100900**: Connection from non-whitelist country (list-based)

- Condition: `radar_outcome="success"` AND `radar_country NOT IN /var/ossec/etc/lists/whitelist_countries`
- Level: 10
- Groups: `authentication_success`, `geoip_detection`

**Rule 100901**: Connection from non-whitelist country (hardcoded fallback)

- Condition: `authentication_success` AND `srcgeoip NOT IN {predefined EU countries}`
- Level: 10
- Fallback if list-based check unavailable

### 6. Active response trigger
- Rule match triggers active response command: `radar-ar`
- Wazuh executes: `/var/ossec/active-response/bin/radar_ar.py`
- Alert JSON passed via stdin

### 7. Active response processing (see LARC-026)
- Scenario identification: Maps rule ID 100900/100901 → `geoip_detection` scenario
- Context collection: Query recent authentication events for user
- CTI enrichment: Check source IP against threat intelligence
- Risk calculation: Primarily signature-based (w_sig = 0.7, w_cti = 0.3)
- Tier determination: Based on risk score and configuration
- Action execution:

    - **Low/Medium tier**: Email notification with alert details
    - **High tier** (if mitigation enabled): Email + Flowintel case + firewall block

### 8. Audit logging
- Decision recorded in `/var/ossec/logs/active-responses.log`
- Includes: scenario, rule ID, risk score, tier, actions executed, IOCs, CTI hits

## Configuration

**Whitelist** (`/var/ossec/etc/lists/whitelist_countries`):
```
US
CA
GB
DE
FR
...
```

**ar.yaml configuration**:
```yaml
geoip_detection:
  rules:
    signature: ["100900", "100901"]
  detection_params:
    delta_signature_minutes: 1
  risk_params:
    likelihood: 0.4
    impact: 0.9
    weights: {w_ad: 0.0, w_sig: 0.7, w_cti: 0.3}
  tier_thresholds: {low: 0.33, high: 0.66}
  actions:
    email_enabled: true
    case_creation_enabled: true
    mitigation_enabled: false
```

## Key characteristics

- **Real-time**: No training phase required
- **Deterministic**: Rule-based matching, no probabilistic scoring
- **Low false positives**: Whitelist approach ensures legitimate geographic regions allowed
- **Operational flexibility**: Whitelist easily updated without retraining
- **Fast response**: No detector delays, immediate rule evaluation

See also:

- `/docs/manual/radar_docs/radar-scenarios/geoip_detection_explained.md` for detailed documentation
- `/radar/scenarios/decoders/geoip_detection/` for decoder implementations
- `/radar/scenarios/rules/geoip_detection/` for rule definitions