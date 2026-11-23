---
active: true
derived: false
level: 4.1
links:
- SRS-005: MFA6jIvRlMPYtqho0ZPke0PjmRoykevXCSzk9u6PlQM=
- SRS-008: oeodWzW_QBgNq8-wrRKnH_AsmLMnhr8y7Djvd4XAlOs=
- SRS-010: QvAvUwUoD-Q0mkFyJr5bAuQrQi4lyzTt1Y4UwWs6xrA=
- SRS-033: Z9AkMsMgFcqHp-K2cHLgaYARe0ULlVDjevw7NVo-EZo=
normative: true
ref: ''
release: Alpha
reviewed: Ji9jrzky3MGUqSd9dd-qtm9E5hM_DYdrMCee-ME0spU=
version: '0.1'
---

# IDPS-ESCAPE end-point integrated arch.

## IDPS-ESCAPE end-point integrated architecture diagram

The diagram illustrates the architecture of IDPS-ESCAPE end-point integrated model.

```mermaid
flowchart LR
  subgraph cc["C&C server"]
    subgraph ccd["C-CyFORT-Suricata and CyFORT-Wazuh (Docker containers)"]
      CSUR["Suricata service"]
      IDX["Wazuh indexer"]
      DASH["Wazuh dashboard"]
      MGR["Wazuh manager"]
    end
    CLOGS[("Suricata logs")]
    CAG["Wazuh agent"]
  end

  subgraph host["Host (end-point)"]
    subgraph hd["CyFORT-Suricata (Docker container)"]
      HSUR["Suricata service"]
    end
    HLOGS[("Suricata logs")]
    HAG["Wazuh agent"]
    TRAFFIC["Network traffic"]
  end

  CSUR -->|stores| CLOGS
  CAG -.->|reads| CLOGS
  CAG -->|"1514 events, 1515 enrollment"| MGR
  MGR --> IDX
  DASH --> IDX
  TRAFFIC --> HSUR
  HSUR -->|stores| HLOGS
  HAG -.->|reads| HLOGS
  HAG -->|"1514 events, 1515 enrollment"| MGR
```