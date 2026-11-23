---
active: false
derived: false
level: 2.3
links: []
normative: true
ref: ''
reviewed: PzlJ9aV4tapnUCiKyrzDxCUP9KHQlnw9JL5AHohRrxc=
---

# RADAR deployment: Remote Agent and Remote Manager mode

> **Status: obsolete.** RADAR no longer deploys to or configures a manager on a remote host: the SSH/Ansible remote-manager mode was removed in v2.0.0 together with the Ansible playbooks, and every manager-side step now runs on the Docker host that runs the manager containers (see HARC-007, HARC-013).

This mode covered a deployment in which both the Wazuh Manager and the Wazuh agents are hosted on remote endpoints. The diagram was removed with the deployment mode.