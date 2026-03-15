---
active: true
derived: false
level: 2.8
links:
- MRS-007: hXM-PkC-g29wtz-Qe3MbM2viHIYzarGh2jFtSD-7N18=
normative: true
ref: ''
reviewed: 9Ca2FOQcLAHezM9LcErlaJk0Xow_XlE0ap7MMSz6V6c=
---

# RADAR helper architecture

The diagram below depicts the high-level architecture of the RADAR Helper component, a multi-threaded log enrichment service deployed on Wazuh agents.

The RADAR Helper monitors authentication logs in real-time and enriches them with geographic and behavioral context before Wazuh ingests them for analysis. This enrichment enables geographic-based detection scenarios (GeoIP detection, impossible travel) and behavioral anomaly detection (ASN novelty, velocity calculations).

Key architectural components:

- **RadarLogger**: Module-level singleton encapsulating all logger setup; provides a shared debug logger and a factory (`build_out_logger`) for per-watcher output loggers
- **BaseLogWatcher**: Abstract base class implementing tail-like log following with rotation handling
- **AuthLogWatcher**: Processes `/var/log/auth.log`, enriches SSH authentication events
- **UserState**: Per-user state tracking (last location, ASN history, timestamps for velocity calculation)
- **GeoLookup Service**: Interfaces with MaxMind GeoLite2 databases (City and ASN)
- **Enrichment Pipeline**: Adds 9 fields including country, region, city, ASN, geo_velocity_kmh, country_change_i, asn_novelty_i

Enriched logs are written to `/var/log/suspicious_login.log` where Wazuh monitors and applies detection rules.

## Architecture Diagram

```plantuml
@startuml
!define CONFIG #e1f5ff
!define WATCHER #fff3cd
!define STATE #d4edda
!define GEO #f8d7da
!define PIPELINE #cfe2ff
!define OUTPUT #d1ecf1
!define EXTERNAL #f5f5f5

package "RADAR Helper Service" <<Rectangle>> {
  package "Configuration Layer" {
    component [CLI Entry Point\nradar-helper] as cli CONFIG
    component [config.yaml\nPaths, thresholds,\nGeoIP DB locations] as cfg CONFIG
  }

  package "Log Watcher Layer" {
    component [RadarLogger\nModule-level singleton\nDebug + output logger factory] as radar_logger WATCHER
    component [BaseLogWatcher\nAbstract base class] as base WATCHER
    component [AuthLogWatcher\nTail /var/log/auth.log] as auth WATCHER
    component [Watcher Thread\ninotify-based monitoring] as watcher_thread WATCHER
  }

  package "State Management" {
    component [UserState\nPer-user tracking] as user_state STATE
    component [StateManager\nPersistent state] as state_mgr STATE

    package "Tracked State" {
      component [Last Location\ncountry, city, lat/lon] as last_loc STATE
      component [ASN History\nSet of seen ASNs] as asn_hist STATE
      component [Timestamps\nLast login times] as timestamps STATE
    }
  }

  package "Geo Intelligence Layer" {
    component [GeoLookup Service] as geo_lookup GEO

    package "GeoIP Databases" {
      database [MaxMind GeoLite2-City\n.mmdb] as city_db GEO
      database [MaxMind GeoLite2-ASN\n.mmdb] as asn_db GEO
    }
  }

  package "Enrichment Pipeline" {
    component [Log Parser\nExtract IP, user, timestamp] as parser PIPELINE
    component [Enricher\nAdd geo fields] as enricher PIPELINE
    component [Calculator\nVelocity, novelty, changes] as calculator PIPELINE
    component [JSON Formatter\nStructure enriched event] as formatter PIPELINE
  }

  package "Output Layer" {
    component [Enriched Log Writer] as writer OUTPUT
    database [/var/log/suspicious_login.log\nWazuh monitored] as suspicious OUTPUT
  }
}

package "External Systems" <<Rectangle>> {
  database [/var/log/auth.log\nSSH authentication events] as auth_log EXTERNAL
  component [Wazuh Agent\nMonitors suspicious_login.log] as wazuh EXTERNAL
  component [Wazuh Manager\nRADAR rules 610000-699999] as rules EXTERNAL
}

cli --> cfg
cfg --> auth
cfg --> geo_lookup

radar_logger --> base : injected into constructor
base <|-- auth : Inheritance
auth --> watcher_thread
auth_log --> watcher_thread : Tail -F behavior

auth --> user_state
user_state --> state_mgr
state_mgr --> last_loc
state_mgr --> asn_hist
state_mgr --> timestamps

geo_lookup --> city_db
geo_lookup --> asn_db

watcher_thread --> parser
parser --> enricher
enricher --> geo_lookup
enricher --> user_state
enricher --> calculator
calculator --> formatter

formatter --> writer
writer --> suspicious
suspicious --> wazuh
wazuh --> rules

calculator ..> user_state : Update state

note right of formatter
  **9 Enriched Fields**
  outcome, country, region, city,
  asn, geo_velocity_kmh, country_change_i, asn_novelty_i
end note

note right of radar_logger
  Instantiated once at module level
  as RADAR_LOG singleton.
  Passed explicitly to each watcher
  via constructor injection.
end note

@enduml
```