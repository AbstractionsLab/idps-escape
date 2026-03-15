---
active: true
derived: false
level: 2.7
links:
- MRS-007: hXM-PkC-g29wtz-Qe3MbM2viHIYzarGh2jFtSD-7N18=
- MRS-012: JTNuTLP6JJZdPo_d_XYH5pxtJBAYucascA5JbOTcAVg=
normative: true
ref: ''
reviewed: gkvYNTzHk892xQxfE_tvWxj1KV_lOUba51N2F5Ntsd8=
---

# RADAR Ansible automation architecture

The diagram below depicts the high-level architecture of RADAR's Ansible-based deployment automation system. The architecture enables flexible deployment across three modes: local Docker, remote Docker, and remote host installations.

Key architectural components:

- **RADAR Controller**: Orchestrates deployment via build-radar.sh and run-radar.sh scripts
- **Ansible Playbooks**: Define scenario-specific configuration and deployment workflows
- **Role Modules**: Modular roles for wazuh_manager, wazuh_agent, and scenario configurations
- **Volume-Based Strategy**: Direct host-side manipulation of bind-mounted Wazuh configuration directories, eliminating docker cp overhead

The volume-first approach maps Wazuh configuration directories (etc, active-response/bin, filebeat/etc) from host to container, enabling idempotent configuration updates without container rebuilds. Configuration injection uses marker-based appending for scenario isolation.

## Architecture Diagram

```plantuml
@startuml
!define CONTROLLER #e1f5ff
!define PLAYBOOK #fff3cd
!define ROLE #d4edda
!define SERVICE #f8d7da
!define VOLUME #cfe2ff

package "RADAR Controller" <<Rectangle>> {
  component [build-radar.sh] as build CONTROLLER
  component [run-radar.sh] as run CONTROLLER
  component [stop-radar.sh] as stop CONTROLLER
  component [inventory.yaml\nDefines targets] as inv CONTROLLER
  component [config.yaml\nScenario configs] as config CONTROLLER
}

package "Ansible Playbook Layer" <<Rectangle>> {
  component [site.yaml\nMain orchestration] as site PLAYBOOK

  package "Deployment Modes" {
    component [Local Docker Mode\nlocalhost + docker.sock] as local PLAYBOOK
    component [Remote Docker Mode\nSSH + docker.sock] as rdocker PLAYBOOK
    component [Remote Host Mode\nSSH + native install] as rhost PLAYBOOK
  }
}

package "Ansible Roles" <<Rectangle>> {
  package "Core Roles" {
    component [wazuh_manager\nConfigure manager] as wm ROLE
    component [wazuh_agent\nDeploy helpers] as wa ROLE
    component [scenario_config\nScenario setup] as sc ROLE
  }

  package "Role Tasks" {
    component [Volume Mapping\nBind mount config] as vol ROLE
    component [Marker-Based Injection\nIdempotent appends] as marker ROLE
    component [Service Restart\nApply configurations] as restart ROLE
  }
}

package "Wazuh Services (Target)" <<Rectangle>> {
  package "Volume Mounts" {
    database "/var/ossec/etc/\nrules, decoders" as etc VOLUME
    database "/var/ossec/active-response/bin/\nAR scripts" as ar VOLUME
    database "/var/ossec/integrations/filebeat/etc/\nFilebeat config" as fb VOLUME
  }

  component [Wazuh Manager\nContainer/Service] as wazuh_mgr SERVICE
  component [Wazuh Agent\nContainer/Service] as wazuh_agt SERVICE
  component [RADAR Helper\nLog enrichment] as helper SERVICE
}

build --> site
run --> site
inv --> site
config --> site

site --> local
site --> rdocker
site --> rhost

local --> wm
rdocker --> wm
rhost --> wm

local --> wa
rdocker --> wa
rhost --> wa

wm --> sc
wa --> sc

sc --> vol
vol --> marker
marker --> restart

vol ..> etc : Host side\nmanipulation
vol ..> ar : Host side\nmanipulation
vol ..> fb : Host side\nmanipulation

etc --> wazuh_mgr
ar --> wazuh_mgr
fb --> wazuh_mgr

wa --> helper
helper --> wazuh_agt

note right of vol
  **Volume-First Strategy**
  Direct host-side manipulation
  No docker cp overhead
  Idempotent marker-based injection
end note

note right of local
  **Supported Modes**
  1. Local: Docker Compose + localhost
  2. Remote Docker: SSH + Docker API
  3. Remote Host: SSH + native install
end note

@enduml
```