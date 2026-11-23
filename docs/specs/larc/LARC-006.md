---
active: true
derived: false
level: 4.3
links:
- SRS-003: UE_j6E5YSNLE7QwpauqBy-iQh6oYSXmwbJVoChYV5u4=
- SRS-009: u-y-I-pk9Lmel0SyuG5mNjgZRCiqXTG5FlpAV-uWTtI=
- SRS-033: Z9AkMsMgFcqHp-K2cHLgaYARe0ULlVDjevw7NVo-EZo=
normative: true
ref: ''
release: Alpha
reviewed: EpfONd4W9zJLtcRiN9mLar5xiGgCaai2VSxH8gLhbM4=
version: '0.1'
---

# IDPS-ESCAPE end-point host-only IDS arch.

## IDPS-ESCAPE end-point host-only IDS model architecture diagram

The diagram illustrates the architecture of IDPS-ESCAPE end-point HIDS only model.

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
  end

  subgraph host["Host (end-point)"]
    HLOGS[("Host logs")]
    HAG["Wazuh agent"]
  end

  CSUR -->|stores| CLOGS
  CAG -.->|reads| CLOGS
  CAG -->|"1514 events, 1515 enrollment"| MGR
  MGR --> IDX
  DASH --> IDX
  HAG -.->|reads| HLOGS
  HAG -->|"1514 events, 1515 enrollment"| MGR
```