---
active: true
derived: false
level: 2.8
links:
- HARC-006: 6rkS6X050Xmdq2IKckYulMoM0OAMumiJ1HXrxtCxnZo=
- HARC-007: DzyMReBOsBksJ4GhX2_mwUhZyXJX5VLyJHnpbha9y8M=
- HARC-008: BVyt44yJgtgUv8ntSQR8ZdoEzOopkJAfLo3PMkyaiZ0=
- HARC-013: 6bGjiy1XvE-7UMsZ7dhn9HkuxmUmQCeZN0IRROAunf4=
normative: true
ref: ''
release: Alpha
reviewed: vshVlwYUr3LAfQRsuE_3ZxcXfeXHnwlq4s-nAMGY0lQ=
version: '0.1'
---

# RADAR Ansible deployment pipeline flow

The diagram below depicts the end-to-end deployment flow orchestrated by `build-radar.sh` and Ansible playbooks. The pipeline automates infrastructure setup, scenario configuration, and service initialization across multiple deployment modes.

## Pipeline stages

### 1. Mode selection and validation
- Parse command-line arguments: `./build-radar.sh <scenario> --manager <local|remote> --agent <local|remote>`
- Validate deployment mode combination
- Set Ansible variables: `manager_mode`, `agent_mode`, `scenario_name`
- Load inventory configuration from `inventory.yaml`

### 2. Volume resolution
The volume-first architecture maps Wazuh configuration directories to host paths:

- Parse `volumes.yml` Docker Compose configuration
- Extract bind mount mappings (container path → host path)
- Key volumes:

    - `/var/ossec/etc` → `/radar-srv/wazuh/manager/etc`
    - `/var/ossec/active-response/bin` → `/radar-srv/wazuh/manager/active-response/bin`
    - `/etc/filebeat` → `/radar-srv/wazuh/manager/filebeat/etc`

- Derive host-side file paths for direct manipulation

### 3. Infrastructure deployment

- Deploy Wazuh core stack (if manager_mode != existing):

    - Wazuh Manager container
    - Wazuh Indexer (OpenSearch)
    - Wazuh Dashboard

- Deploy Wazuh agents (if agent_mode == local):
    - Agent Docker containers
    - Register with manager

- Install OpenSearch AD plugin in indexer

### 4. Scenario configuration injection
For the specified scenario, inject configurations via Ansible roles:

**Decoders** (`/var/ossec/etc/decoders/`):

- Copy scenario-specific XML decoders
- Marker-based appending to avoid duplicates
- Set ownership: `root:wazuh`, permissions: `640`

**Rules** (`/var/ossec/etc/rules/`):

- Copy scenario-specific XML rules
- Use unique markers: `<!-- BEGIN RADAR {scenario} -->` / `<!-- END RADAR {scenario} -->`
- Idempotent insertion (skip if marker exists)

**Active Response** (`/var/ossec/active-response/bin/`):

- Copy `radar_ar.py` and dependencies
- Set executable permissions: `750`
- Copy `ar.yaml` configuration

**OSSEC Configuration** (`/var/ossec/etc/ossec.conf`):

- Inject localfile, command, and active_response blocks
- Use marker-based insertion for idempotency
- Configure log monitoring and response commands

**Filebeat Pipelines** (if applicable):

- Configure ingest pipelines for data enrichment
- Set up index templates

### 5. RADAR Helper deployment (if scenario requires)
For geographic-enrichment scenarios (geoip_detection, suspicious_login):

- Copy `radar-helper.py` to `/opt/radar/` on agent hosts
- Install Python dependencies (maxminddb)
- Copy MaxMind GeoLite2 databases to `/usr/share/GeoIP/`
- Deploy systemd service: `radar-helper.service`
- Start and enable service

### 6. Service management
- Restart Wazuh Manager: `/var/ossec/bin/wazuh-control restart`
- Reload Filebeat configuration
- Verify service health

### 7. Build radar-cli container
- Build Docker image with detector.py, monitor.py, webhook.py
- Load environment variables from `.env`
- Image used by `run-radar.sh` for detector/monitor setup

## Idempotency mechanisms

- **File checksums**: Compare content before copying to avoid unnecessary operations
- **Marker-based injection**: Scenario-specific markers prevent duplicate configuration
- **Conditional logic**: Check for existing resources before creation
- **State tracking**: Ansible facts maintain deployment state

**Diagram**: Ansible deployment pipeline showing mode selection, infrastructure setup, scenario injection, and service management. See [assets/RADAR-ansible-deployment-flow.md](assets/RADAR-ansible-deployment-flow.mermaid.md) for detailed documentation.

## Deployment modes

| manager_mode | agent_mode | Execution context |
|--------------|------------|-------------------|
| docker_local | N/A | Docker on controller host |
| docker_remote | N/A | Docker on remote host via SSH |
| host_remote | N/A | Bare metal installation via SSH |

All modes accept local or remote agents independently.

**Note**: Diagram placeholder - to be created in Phase 7 showing flowchart: mode selection → volume resolution → infrastructure → config injection → helper deploy → service restart.

See also:

- `/radar/roles/wazuh_manager/tasks/main.yml` for playbook implementation
- `/radar/build-radar.sh` for orchestration script
- `/docs/manual/radar_docs/radar-manager-ansible-playbook.md` for detailed documentation