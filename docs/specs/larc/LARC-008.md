---
active: true
derived: false
level: 8.0
links:
- SRS-027: 4dCtXOdWfUfx6pg8aEDeW6lRp-YfPPfKrOM5hMIuluQ=
normative: true
ref: ''
release: Alpha
reviewed: j4_wd_nEktHFDzh4bXZjznXD21UvMWNheJO0vULUoes=
version: '0.2'
---

# ADBox batch and real-time prediction flow

## Batch and real-time ADBox run modes prediction flow diagrams

The diagram summarizes the flow of the prediction pipeline for online run modes orchestrated by the ADBox Engine.

Specifically,

- batch mode runs the loop every batch interval,

- real-time mode runs the loop every granularity interval.

![ADBox predict pipeline flow - online diagram](assets/1B3A4D_DIA_IDPS_ESCAPE_ADBoxDiagrams-engine-predict-pipeline-flow-online_v1.2.png "ADBox predict pipeline flow - online")