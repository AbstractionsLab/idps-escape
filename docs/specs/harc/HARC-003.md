---
active: true
derived: false
level: 4.1
links:
- MRS-002: rw7LHgWV1s22rWsoCRJX4MOW5eGWoyU8xScfv-_9KOM=
- MRS-003: 8krPjCwmUwFserZGnXQT3zoF2VR7A3S1IE-chqQMrJw=
- MRS-004: gVqspc4sDwTg4t4dbQQCmYQicvh8utXO2dXEC-PmBAs=
- MRS-005: VhDxOFytavm5M0q8xaLGTt3hvSPdPyJqPd-4LPA71t4=
- MRS-006: 62hLSb4w_PEhRbLxvMTOz-_QaElRVqUBZBs0HMs5FII=
- MRS-007: T_irYXTjWbTLRStypNV_lJ0NrCpz_1UXPGaQK7pMs2k=
- MRS-008: gVngmnks42UZBAyG_IB31AFm_z7x97_SiTW-E19-afc=
- MRS-011: wZWfvyzspyJ-nmoGS45sdrFpzPFVx_McLB5FdOp8sk0=
- MRS-012: DiXLptltrfh07-ndUNM7b6BPSGudu8wMrZW-tr_Wt2A=
- MRS-013: 2gfJxtukUG2fX-Y21vmVLBz4_yLJXQL206xKxdkt_po=
- MRS-017: O03AY1ejn7HGiRYPESAqoYnuDe4R-oKarS3-_AWN8Bo=
- MRS-018: s23mBfztr9qnXlvnDE0TeEN0IaOl8k7uW_zEWTGg4iM=
- MRS-019: XwUNC5T2_yICrRsWY8ZyWYFBtvAbrxSEja1ZwL0TB3Q=
- MRS-020: tdHZ8nH44kifclPmaYdh-opzFgj3X1MW4279EVCC71I=
- MRS-022: rIrRK0xxkOu53QUnXFNoQ9Dvp5swoAUgvEA787r3Cxo=
- MRS-024: F5zql4yq0eMIzrjrbif-XN_lAXfJIRoxxIyeNzDcK9k=
- MRS-032: T6hCz4404Ang3Ig9Z1a4aSLoszOGnnuq3HdS2NZZ2LQ=
- MRS-033: U470hMVIXAfpaW14r-E4OSp8hO2VfCVVWdXg7KQ9lVE=
- MRS-035: 0oS5sLYfa-_5VaojtFk2kNU5dHLsJaI-VATHMyyr38o=
- MRS-037: fiSWApf8Zdd1mXT0zijBxOBF6Dh3VT5S-LwAv5y6HAQ=
- MRS-039: -K_FLcCc63SwoERy1DmALXIhaL5t_KOpDmEBzdT0mZY=
- MRS-040: YKYUlyHt1toZCQkRa9eyonv2N3LKydDS8abHtWKlkf4=
- MRS-041: ig3VUk73khs5Lx0Y-Ydr-0gDbCqg5rLE2v_WzcuNP2Y=
normative: true
ref: ''
reviewed: xPSJQ3_RAqWDkSq47aiBA1Vuyi621XY6gqj0T8DTpJw=
---

# IDPS-ESCAPE context

The diagram below illustrates the overall context of the IDPS-ESCAPE system.

```mermaid
flowchart TB
  USERS["Incident responder, SOC analyst,<br/>security admin and engineer, CSIRT"]

  subgraph cti["External CTI tools and TIPs"]
    MISP["MISP"]
    FLOW["Flowintel"]
  end

  subgraph satrap["SATRAP-DL"]
    SAT["SATRAP"]
    DEC["DECIPHER"]
    DECAPI["DECIPHER API"]
  end

  subgraph center["IDPS-ESCAPE Center"]
    subgraph siem["SIEM and XDR: Wazuh with RADAR extensions"]
      DASH["Wazuh dashboard"]
      subgraph mgr["Wazuh manager"]
        RULES["Decoders, rules, CDB lists"]
        ENR["Manager enrichment"]
        RAR["radar_ar.py<br/>(risk score, response)"]
      end
      subgraph idx["Wazuh indexer (OpenSearch)"]
        STORE[("Indices<br/>(data storage)")]
        MON["AD detectors and<br/>alerting monitors"]
      end
    end
    WH["ad-webhook container<br/>(own Wazuh agent)"]
    ORCH["RADAR orchestrator<br/>(GUI, radar.sh, build-radar.sh, radar_deploy)"]
    SONAR["SONAR (MVAD)"]
    ADBOX["ADBox (legacy)"]
  end

  subgraph nids["Central NIDS"]
    NIDS["Suricata NIDS"]
    NSTORE[("Data storage")]
  end

  subgraph capep["Capture end-points"]
    RTR1["Router<br/>(traffic mirroring)"]
  end

  subgraph genep["Generic end-points"]
    RTR2["Router<br/>(traffic mirroring)"]
    GAG["Wazuh agent + radar-agent"]
  end

  subgraph idsep["IDS end-points"]
    IDS["Suricata IDS"]
    ISTORE[("Data storage")]
    IAG["Wazuh agent + radar-agent"]
  end

  subgraph hidsep["HIDS end-points"]
    HAG["Wazuh agent + radar-agent"]
  end

  USERS -.->|use| DASH
  DASH --- STORE
  SAT <--> MISP
  SAT <--> FLOW
  DECAPI --- DEC
  DEC -->|case creation| FLOW
  RAR <-->|"CTI score, incident"| DECAPI
  RULES --> ENR
  RULES --> RAR
  RULES -->|"alerts, archives"| STORE
  STORE --> MON
  MON -->|notification| WH
  WH -->|ad_alert lines| RULES
  SONAR -->|reads alerts| STORE
  SONAR -->|anomaly events| RULES
  ADBOX -.-> STORE
  ORCH -->|"deploy (Wazuh API)"| RULES
  ORCH -->|"indexer API"| MON
  RTR1 -->|mirror| NIDS
  RTR2 -->|mirror| NIDS
  NIDS <--> NSTORE
  NIDS -->|"alerts (Wazuh agent)"| RULES
  IDS <--> ISTORE
  IDS -->|eve.json| IAG
  IAG <-->|"events, active responses"| RULES
  HAG <-->|"events, active responses"| RULES
  GAG <-->|"events, active responses"| RULES
```
{width="80%"}