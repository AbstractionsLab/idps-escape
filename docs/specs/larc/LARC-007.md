---
active: true
derived: false
level: 4.4
links:
- SRS-007: s_qKmitDpbSoa2OiIUl8MG6Zxa0pVN8ZGoozcgdbfzA=
- SRS-033: Z9AkMsMgFcqHp-K2cHLgaYARe0ULlVDjevw7NVo-EZo=
normative: true
ref: ''
release: Alpha
reviewed: KMFmy_xJO69AlwDss_1g7MznvvjIX3Nl1kzuJ0FQJ4E=
version: '0.1'
---

# IDPS-ESCAPE end-point capture-only arch.

## IDPS-ESCAPE end-point capture-only model architecture diagram

The diagram illustrates the architecture of IDPS-ESCAPE end-point capture only model.

```mermaid
flowchart LR
  subgraph cc["C&C server"]
    subgraph ccd["CyFORT-Suricata and CyFORT-Wazuh (Docker containers)"]
      CSUR["Suricata service"]
      IDX["Wazuh indexer"]
      DASH["Wazuh dashboard"]
      MGR["Wazuh manager"]
    end
    CLOGS[("Suricata logs")]
    CAG["Wazuh agent"]
    CNIC["nic"]
  end

  subgraph host["Host (end-point, no Wazuh agent)"]
    TUN["tun (GRE)"]
    HNIC["nic"]
    TRAFFIC["Network traffic"]
  end

  TRAFFIC <--> HNIC
  HNIC -.->|mirrors| TUN
  TUN -.->|"GRE tunnel (unencrypted)"| CNIC
  CSUR -.->|inspects| CNIC
  CSUR -->|stores| CLOGS
  CAG -.->|reads| CLOGS
  CAG -->|"1514 events, 1515 enrollment"| MGR
  MGR --> IDX
  DASH --> IDX
```