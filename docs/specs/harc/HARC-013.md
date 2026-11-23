---
active: true
derived: false
level: 2.7
links:
- MRS-007: T_irYXTjWbTLRStypNV_lJ0NrCpz_1UXPGaQK7pMs2k=
- MRS-021: JNEBtHLFz9j_TWTSczFmgK2yyaMqYbHvZlh6v2bgmGg=
normative: true
ref: ''
reviewed: VTz4xqc_m4ApVLslDYbg9nMJHFFkBYIMnTtywz9MG_c=
---

# RADAR deployment automation architecture

RADAR's deployment automation (the deployment control plane) is made of shell entry points, a manager-side shell backbone and a Python Wazuh API layer, driven either from the command line or from the RADAR GUI. It replaced the Ansible-based automation, which was removed in v2.0.0. SWD-042 specifies its design.

Key architectural decisions:

- **One privileged host, no remote execution.** The control plane runs on the Docker host that runs the Wazuh manager containers. Nothing is pushed to endpoints over SSH, and there is no inventory or vault. `sudo` is needed only to bring up the containers, to write under the bind-mounted manager directories and to manage the `iptables` rule guarding the enrollment port.
- **API first, files second.** Whatever the Wazuh REST API can do (agent groups and their `agent.conf`, decoders, rules, CDB lists, `ossec.conf` blocks, agent assignment and deregistration, health) goes through `radar/wazuh_api/`. Files the API cannot place (`radar_ar.py`, `ar.yaml`, the manager's copy of `.env`, enrichment integrations, GeoLite2 databases, Filebeat pipeline patches) are written by `radar/radar_deploy/` on the host side of the bind mounts listed in `radar/volumes.yml`.
- **Marker-delimited, idempotent changes.** `ossec.conf` is changed only inside `<!-- RADAR: <name> BEGIN/END -->` blocks. Re-applying a scenario converges to the same state, and undoing a scenario keeps everything another deployed scenario still needs.
- **Self-onboarding endpoints.** An endpoint runs `radar/radar-agent/bootstrap-agent.sh` with a short-lived enrollment token. Enrollment is hardened (`use_password=yes`, `purge=no`, port 1515 closed outside a timed window).
- **Runtime address resolution.** `radar/infra.yaml` registers the manager node(s), indexer, dashboard and webhook. `wazuh_api/infra.py` tries a component's declared host first and falls back to its container name, so the same scripts serve a stack RADAR deployed itself and a pre-existing containerised Wazuh installation.

## Architecture diagram

```plantuml
@startuml
!define ENTRY #e1f5ff
!define BACKBONE #fff3cd
!define API #d4edda
!define SERVICE #f8d7da
!define VOLUME #cfe2ff

actor Operator
actor "Endpoint admin" as EpAdmin

package "Operator interfaces" <<Rectangle>> {
  component [RADAR GUI\ngui/app.py + gui/orchestrator] as gui ENTRY
  component [radar.sh] as radar ENTRY
}

package "Entry-point scripts" <<Rectangle>> {
  component [build-radar.sh] as build ENTRY
  component [run-radar.sh] as run ENTRY
  component [health-radar.sh] as health ENTRY
  component [stop-radar.sh] as stop ENTRY
}

package "Configuration" <<Rectangle>> {
  component [config.yaml] as cfg ENTRY
  component [.env] as env ENTRY
  component [volumes.yml] as vols ENTRY
  component [infra.yaml] as infra ENTRY
  component [scenarios/] as scen ENTRY
}

package "Manager-side shell backbone\nradar_deploy/" <<Rectangle>> {
  component [manager-apply-scenario(-all).sh\nmanager-undo-scenario.sh] as apply BACKBONE
  component [manager-harden-enrollment.sh\nmanager-mint-token.sh\nmanager-revoke-token.sh\nmanager-enrollment-window.sh] as enroll BACKBONE
  component [manager-health.sh] as mhealth BACKBONE
}

package "Wazuh API layer\nwazuh_api/" <<Rectangle>> {
  component [cli.py / scenario_ops.py\nruleset.py / manager_config.py\ngroups.py / health.py] as wapi API
  component [infra.py\ncredentials.py] as winfra API
}

component [radar-cli container\ndetector.py / monitor.py / off_hours.py] as cli API

package "RADAR host (Docker)" <<Rectangle>> {
  package "Bind mounts" {
    database "/var/ossec/etc\n/var/ossec/active-response/bin\n/var/ossec/integrations\n/etc/filebeat" as mounts VOLUME
  }
  component [Wazuh manager\nnode(s)] as mgr SERVICE
  component [Wazuh indexer\n(OpenSearch + AD plugin)] as idx SERVICE
  component [Wazuh dashboard] as dash SERVICE
  component [ad-webhook\n(Wazuh agent)] as hook SERVICE
  component [iptables DOCKER-USER\nport 1515 rule] as fw SERVICE
}

package "Monitored endpoint" <<Rectangle>> {
  component [radar-agent/bootstrap-agent.sh] as boot ENTRY
  component [Wazuh agent\n+ AR dispatchers\n+ collectors] as agent SERVICE
}

Operator --> gui
Operator --> radar
gui --> build
gui --> run
gui --> wapi
gui --> enroll
radar --> build
radar --> run
radar --> health
radar --> stop
radar --> enroll

build --> apply
build --> enroll
build --> wapi
build --> winfra
health --> mhealth
health --> wapi
run --> cli

cfg --> build
env --> build
vols --> apply
infra --> winfra
scen --> apply
scen --> wapi

apply ..> mounts : host-side writes
mounts --> mgr
enroll --> fw
enroll --> mgr : authd.pass\n(docker exec)
wapi --> mgr : REST :55000
cli --> idx : REST :9200
idx --> hook : monitor POST /notify
hook --> mgr : ad_alert log line

EpAdmin --> boot
boot --> agent
agent --> mgr : enroll :1515\nevents :1514
@enduml
```

See: `docs/manual/radar_docs/radar-operations.md`.