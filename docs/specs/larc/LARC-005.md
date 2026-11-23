---
active: true
derived: false
level: 4.2
links:
- SRS-005: MFA6jIvRlMPYtqho0ZPke0PjmRoykevXCSzk9u6PlQM=
- SRS-007: s_qKmitDpbSoa2OiIUl8MG6Zxa0pVN8ZGoozcgdbfzA=
- SRS-033: Z9AkMsMgFcqHp-K2cHLgaYARe0ULlVDjevw7NVo-EZo=
normative: true
ref: ''
release: Alpha
reviewed: KcIQGnqr8BG3BCosdVQ6E9rNklNg4RP2BzFM9kNv-Ms=
version: '0.1'
---

# IDPS-ESCAPE end-point hybrid arch.

## IDPS-ESCAPE end-point hybrid model architecture diagram

The diagram illustrates the architecture of IDPS-ESCAPE end-point hybrid model.

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

  subgraph host["Host (end-point)"]
    HAG["Wazuh agent"]
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
  HAG -->|"1514 events, 1515 enrollment"| MGR
```