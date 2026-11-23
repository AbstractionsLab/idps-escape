---
active: true
derived: false
level: 2.8
links:
- MRS-007: T_irYXTjWbTLRStypNV_lJ0NrCpz_1UXPGaQK7pMs2k=
normative: true
ref: ''
reviewed: FwT500JotVw0F5ZHjI1Bj8d-lRS_7tVIEK1HE79sxIc=
---

# RADAR manager-side enrichment architecture

The diagram below depicts the high-level architecture of RADAR's log enrichment, which runs on the Wazuh manager as two `integratord` integrations. It replaced the earlier RADAR helper, a per-endpoint enrichment daemon with its own virtual environment, service and GeoIP databases, which was removed in v2.0.0 (CHANGELOG, "Manager Enrichment & Architecture").

Enrichment adds geographic and behavioural context to authentication and web-access events so that the `suspicious_login` and `geoip_detection` rules can match on it (impossible travel, country change, country whitelist). Because the manager receives the events of every endpoint, it keeps one history per user, so geo-velocity and ASN novelty are computed across all endpoints a user reaches (SRS-068). Endpoints run only the Wazuh agent and forward their raw logs.

Key architectural components (`radar/manager-enrichment/`):

- **`custom-radar-enrich`**: integration entry point for authentication events. Wazuh calls it for alerts in the `authentication_success` and `authentication_failed` groups. It parses the user, source IP, outcome and timestamp from the original log line, enriches them and appends the line with a `RADAR …` tail to `/var/ossec/logs/radar/enriched_auth.log`.
- **`custom-radar-web-enrich`**: integration entry point for web-access events (`accesslog` group), writing `/var/ossec/logs/radar/enriched_web_access.log`.
- **`enrichment.py`**: authentication log parsing, `RadarEnricher` (geo-velocity, country change, ASN novelty) and the tail format.
- **`web_enrichment.py`**: source-IP extraction from access-log lines, private-address filtering and the web tail format.
- **`geoip.py`**: stateless lookup of country, region, city, coordinates and ASN in the MaxMind GeoLite2 City and ASN databases.
- **`state_store.py`**: `UserState` and `UserStateStore`, the per-user history (last time, position and country, 90-day ASN history) in one SQLite database on the manager.

The manager reads both enriched files through `<localfile>` entries, so each enriched line is decoded a second time by the scenario's `-with-radar` decoders, and the scenario rules evaluate the `radar_*` fields. Failures are written to `/var/ossec/logs/radar/enrichment_errors.log` and never suppress the original alert. The design is specified in LARC-025 and SWD-030.

## Architecture diagram

```plantuml
@startuml
!define ENTRY #e1f5ff
!define LOGIC #fff3cd
!define STATE #d4edda
!define GEO #f8d7da
!define OUTPUT #d1ecf1
!define EXTERNAL #f5f5f5

package "Monitored endpoints" <<Rectangle>> {
  component [Wazuh agent\nforwards raw /var/log/auth.log\nand web access logs] as agent EXTERNAL
}

package "Wazuh manager" <<Rectangle>> {
  component [analysisd, first pass\nstock sshd / web decoders and rules] as pass1 EXTERNAL
  component [integratord] as integratord EXTERNAL

  package "Enrichment integrations (/var/ossec/integrations)" {
    component [custom-radar-enrich\ngroups authentication_success,\nauthentication_failed] as auth_entry ENTRY
    component [custom-radar-web-enrich\ngroup accesslog] as web_entry ENTRY
  }

  package "radar_enrichment modules" {
    component [enrichment.py\nparse_auth_line, RadarEnricher,\ntail format] as enrich LOGIC
    component [web_enrichment.py\nsource IP, private-range skip,\ntail format] as web LOGIC
    component [geoip.py\ngeo_lookup] as geo GEO
    component [state_store.py\nUserStateStore] as store STATE
  }

  database "/var/ossec/etc/radar\nGeoLite2-City.mmdb\nGeoLite2-ASN.mmdb" as mmdb GEO
  database "/var/ossec/etc/radar\nuser_state.sqlite3" as sqlite STATE

  database "/var/ossec/logs/radar\nenriched_auth.log\nenriched_web_access.log" as enriched OUTPUT
  database "/var/ossec/logs/radar\nenrichment_errors.log" as errors OUTPUT

  component [logcollector\nlocalfile, syslog format] as logcollector EXTERNAL
  component [analysisd, second pass\n-with-radar decoders,\nsuspicious_login / geoip_detection rules] as pass2 EXTERNAL
}

agent --> pass1 : raw log line
pass1 --> integratord : alert (JSON)
integratord --> auth_entry
integratord --> web_entry

auth_entry --> enrich
web_entry --> web
enrich --> geo
web --> geo
geo --> mmdb
enrich --> store
store --> sqlite

auth_entry --> enriched : original line + RADAR tail
web_entry --> enriched : original line + RADAR tail
auth_entry ..> errors : on failure
web_entry ..> errors : on failure

enriched --> logcollector
logcollector --> pass2
pass2 ..> integratord : lines with a RADAR tail\nare not enriched again

note right of enrich
  **Authentication tail fields**
  outcome, asn, asn_placeholder_flag,
  country, region, city, geo_velocity_kmh,
  country_change_i, asn_novelty_i
end note

note right of web
  **Web tail fields**
  country, region, city, lat, lon
end note

@enduml
```