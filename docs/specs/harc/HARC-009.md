---
active: true
derived: false
level: 9.0
links:
- MRS-032: T6hCz4404Ang3Ig9Z1a4aSLoszOGnnuq3HdS2NZZ2LQ=
- MRS-039: -K_FLcCc63SwoERy1DmALXIhaL5t_KOpDmEBzdT0mZY=
normative: true
ref: ''
reviewed: OalreGuZZ2_VV8CzisZ5HcrVeydWq9-XggbkrU5tZpU=
---

# SONAR subsystem context

The diagram below depicts the system context of the SONAR (SIEM-Oriented Neural Anomaly Recognition) subsystem within the IDPS-ESCAPE architecture.

SONAR is a multivariate anomaly detection engine that analyzes Wazuh security alerts to identify unusual patterns that may indicate security threats. It integrates with the Wazuh Indexer (OpenSearch) for data ingestion and result storage.

## System boundary

```plantuml
@startuml
!define SONAR_COLOR #e1f5ff

component "Wazuh Indexer\nOpenSearch" as WazuhIndexer
component "SONAR Subsystem" as SONAR SONAR_COLOR
component "RADAR Subsystem" as RADAR
actor "Security Analyst" as Admin

WazuhIndexer -down-> SONAR : Security Alerts
SONAR -up-> WazuhIndexer : Anomaly Scores
SONAR -right-> RADAR : Anomaly Events
Admin -down-> SONAR : Configure Scenarios
Admin -down-> WazuhIndexer : Review Anomalies

@enduml
```

## Key interfaces

| Interface | Direction | Protocol | Purpose |
|-----------|-----------|----------|---------|
| Wazuh Indexer API | Inbound | HTTPS/REST | Alert retrieval, query execution |
| Wazuh Data Streams | Outbound | HTTPS/REST | Anomaly document indexing |
| RADAR Webhook | Outbound | HTTPS/REST | Real-time anomaly notifications |

## Related documentation

- Technical architecture: `docs/manual/sonar_docs/architecture.md`
- UML diagrams: `docs/manual/sonar_docs/uml-diagrams.md`