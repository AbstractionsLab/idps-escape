# Wazuh manager Ansible playbook logic documentation

## Overview

The [Wazuh manager deployment playbook](/radar/roles/wazuh_manager/tasks/main.yml) (at `radar/roles/wazuh_manager/tasks/main.yml`) automates the deployment and configuration of Wazuh Manager instances with RADAR scenario-specific customizations. It supports three deployment modes (local Docker, remote Docker, and remote host) and ensures idempotent, scenario-aware configuration management.

## Table of contents

- [High-level architecture](#high-level-architecture)
- [Execution flow diagram](#execution-flow-diagram)
- [Key design principles](#key-design-principles)
- [Architecture: volume-based approach](#architecture-volume-based-approach)
- [Pseudocode: automation algorithm](#pseudocode-automation-algorithm)
- [Blocks breakdown](#blocks-breakdown)
  - [Block 1: Variable resolution & initialization](#block-1-variable-resolution--initialization)
  - [Block 2: DOCKER_LOCAL](#block-2-docker_local)
  - [Block 3: DOCKER_REMOTE](#block-3-docker_remote)
  - [Block 4: HOST_REMOTE](#block-4-host_remote)
- [Idempotency mechanisms](#idempotency-mechanisms)
- [Error handling strategy](#error-handling-strategy)
- [Scenario-specific customization](#scenario-specific-customization)
- [Deployment mode selection logic](#deployment-mode-selection-logic)
- [File modification tracking](#file-modification-tracking)
- [Extending the playbook](#extending-the-playbook)

---

## High-level architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Playbook entry point: initialize variables & resolve paths │
└─────────────────────────────────────────────────────────────┘
                            ↓
        ┌───────────────────┬───────────────────┐
        ↓                   ↓                   ↓                   
   DOCKER_LOCAL     DOCKER_REMOTE         HOST_REMOTE       
   (Local Dev)      (Remote Container)    (Bare Metal)
```

The playbook consists of four logical parts: one handles initial configuration and flow choices, and the rest branches into **three mutually exclusive blocks** based on the `manager_mode` variable set in the inventory, which are as follows:
- `docker_local`: Manager runs in Docker on controller machine
- `docker_remote`: Manager runs in Docker on remote host
- `host_remote`: Manager runs directly on remote host (no containers)

---

## Execution flow diagram

```
START
  ↓
┌─────────────────────────────┐
│ Load Variables & Resolve    │
│ Scenario Path               │
└────────────┬────────────────┘
             ↓
    ┌────────────────────┐
    │ Determine Manager  │
    │ Mode               │
    └─┬──────┬───────┬───┤
      │      │       │   └─→ host_remote
      │      │       └─────→ docker_remote
      │      └──────────────→ docker_local
      │
      ├─ (If docker_local)
      │  ├─ Check container running
      │  ├─ Upload templates to OpenSearch
      │  ├─ Copy config files
      │  ├─ Append decoders (idempotent)
      │  ├─ Append rules (idempotent)
      │  ├─ Handle SSH override (conditional)
      │  ├─ Modify ossec.conf
      │  ├─ Restart Wazuh (if changed)
      │  ├─ Configure filebeat
      │  └─ Setup filebeat pipelines
      │
      ├─ (If docker_remote)
      │  ├─ Create staging dir on remote
      │  ├─ Bootstrap manager (if needed)
      │  ├─ Check container running
      │  ├─ [Same as docker_local, executed on remote]
      │
      └─ (If host_remote)
         ├─ Verify target directories
         ├─ Read snippets on controller
         ├─ Insert configs via Ansible modules
         ├─ Copy active response files
         ├─ Validate XML (optional)
         └─ Restart Wazuh (if changed)
           ↓
        END
```

---

## Key design principles

### 1. **Idempotency first**
- Every operation can be re-run safely
- Markers prevent duplicates
- Checksum comparison prevents unnecessary copies
- Conditional logic prevents re-execution

### 2. **Scenario isolation**
- Each scenario tagged with unique marker
- Multiple scenarios coexist in same configuration files
- No data loss when deploying new scenario

### 3. **Multi-mode support**
- Single playbook supports 3 deployment topologies
- Logic adapted per mode, same end-state
- Bootstrap capability for greenfield deployments

### 4. **Graceful error handling**
- Retries for transient failures (network, startup)
- Non-critical operations marked as `failed_when: false`
- Clear logging via `debug` tasks

### 5. **Minimal restarts**
- Restart only if configuration actually changed
- Service restart via `wazuh-control` (not full container)
- Avoids downtime for unchanged deployments

---

## Architecture: volume-based approach

### Volume mapping strategy

The playbook uses a **volume-first architecture** where all Wazuh configuration directories are bind-mounted from the host into the container. This eliminates the need for `docker cp` operations and allows direct host-side manipulation.

**Key volume mappings** (defined in `volumes.yml`):
```yaml
volumes:
  - /radar-srv/wazuh/manager/etc:/var/ossec/etc
  - /radar-srv/wazuh/manager/active-response/bin:/var/ossec/active-response/bin
  - /radar-srv/wazuh/manager/filebeat/etc:/etc/filebeat
```

### Volume resolution process

1. **Load volumes.yml**: Parse the Docker Compose volumes configuration
2. **Extract bind mounts**: Identify host paths mapped to container paths
3. **Derive host paths**: Calculate exact host file locations
4. **Validate mappings**: Ensure required volumes exist

### Benefits of volume-based approach

- **Performance**: No file transfer overhead
- **Atomicity**: Changes visible immediately to container
- **Simplicity**: Standard file operations instead of Docker API calls
- **Debuggability**: Easy to inspect/modify files on host
- **Consistency**: Same approach for local and remote deployments

---

## Refactor: task decomposition & shared interface

The manager playbook was decomposed into small task files, each responsible for a single configuration domain. The key refactor idea is: tasks are mode-agnostic; only the source path changes between `docker_local` and `docker_remote`. 

The orchestration is centralized in `main.yml`, which acts as a control plane, not an execution script.

Common task modules (`roles/wazuh_manager/tasks/`):

| Task file          | Responsibility                         | Modified resources                         |
| ------------------ | -------------------------------------- | ------------------------------------------ |
| `responses.yml`    | Active response scripts & env          | `/var/ossec/active-response/bin`           |
| `lists.yml`        | Whitelists / lists                     | `/var/ossec/etc/lists`, `ossec.conf`       |
| `decoders.yml`     | Custom decoders                        | `local_decoder.xml`, SSH overrides         |
| `rules.yml`        | Custom rules                           | `local_rules.xml`                          |
| `ossec.yml`        | Core manager configuration             | `ossec.conf`                               |
| `filebeat.yml`     | Ingest & indexing logic                | Filebeat config, pipelines                 |
| `bootstrap.yml`    | Manager / webhook bootstrap            | Docker Compose stack                       |
| `agent_config.yml` | Centralized agent configuration        | `/var/ossec/etc/shared/<group>/agent.conf` |

Each task file:

- Has one clear responsibility
- Is idempotent by design
- Is reusable across deployment modes

This keeps business logic identical across modes and prevents divergence.

---

## Pseudocode: automation algorithm

Here we provide a summarized description of the entire automation pipeline in the form of pseudocode.

```
FUNCTION DeployRadarScenario(scenario_name, manager_mode, bootstrap_flag):
  
  // ============================================
  // PHASE 1: INITIALIZATION
  // ============================================
  scenario_root ← RESOLVE_SCENARIO_ROOT_DIR()                       // "scenarios/"
  scenario_path ← RESOLVE_scenario_path(scenario_root, scenario_name)
  manager_vars ← LOAD_INVENTORY_VARS(manager_mode)
  
  // Load and parse volumes.yml
  volumes_yml ← LOAD_YAML_FILE("volumes.yml")
  volume_mappings ← EXTRACT_BIND_MOUNTS(volumes_yml)
  
  // Resolve host paths from volume mappings
  host_ossec_etc ← EXTRACT_HOST_PATH(volume_mappings, "/var/ossec/etc")
  host_active_response_bin ← EXTRACT_HOST_PATH(volume_mappings, "/var/ossec/active-response/bin")
  host_filebeat_etc ← EXTRACT_HOST_PATH(volume_mappings, "/etc/filebeat")
  
  IF scenario_root DOES NOT EXIST:
    FAIL "scenarios/ root not found"
  END IF
  
  // ============================================
  // PHASE 2: BRANCH ON DEPLOYMENT MODE
  // ============================================
  
  SWITCH manager_mode:
    
    CASE "docker_local":
      RETURN DeployLocal(scenario_path, manager_vars)
    
    CASE "docker_remote":
      RETURN DeployRemoteContainer(scenario_path, manager_vars, bootstrap_flag)
    
    CASE "host_remote":
      RETURN DeployRemoteHost(scenario_path, manager_vars)
  
  END SWITCH


// ============================================
// DOCKER_LOCAL DEPLOYMENT
// ============================================
FUNCTION DeployLocal(scenario_path, manager_vars):
  
  container ← manager_vars.container_name
  
  // Step 1: Verify container running
  REPEAT 3 TIMES with 30sec delay:
    IF docker.ps(container) == RUNNING:
      BREAK
  END REPEAT
  
  // Step 2: Upload templates to OpenSearch
  template_json ← READ_FILE(scenario_path + "/wazuh-alerts-template.json")
  HTTP_PUT("https://indexer:9200/_index_template/wazuh-alerts-*", 
           auth=(admin_user, admin_pass),
           body=template_json,
           retries=3)
  
  // Step 3: Copy configuration files
  CopyConfigFiles(container, scenario_path)
  
  // Step 4: Ensure host bind-mount directories exist
  ENSURE_DIRS_EXIST_LOCAL([
    host_ossec_etc + "/decoders",
    host_ossec_etc + "/rules",
    host_ossec_etc + "/lists",
    host_active_response_bin,
    host_filebeat_etc
  ])
  
  // Step 5: Copy decoders into volume mapped to /var/ossec/etc/decoders/
  COPY_FILES(scenario_path.decoders_dir + "/*.xml",
             host_ossec_etc + "/decoders/")
  
  // Step 6: Copy rules into volume mapped to /var/ossec/etc/rules/
  COPY_FILES(scenario_path.rules_dir + "/*.xml",
             host_ossec_etc + "/rules/")
  
  // Step 7: Modify ossec.conf in volume mapped to /var/ossec/etc/ossec.conf (idempotent)
  ossec_conf ← host_ossec_etc + "/ossec.conf"
  
  IF MarkerNotExists(ossec_conf, "RADAR: " + scenario_name):
    snippet ← READ_FILE(scenario_path.ossec_snippet)
    InsertBefore(ossec_conf, "</ossec_config>", 
                 markers="RADAR: " + scenario_name,
                 content=snippet)
  END IF
  
  IF scenario_name IN ["suspicious_login", "geoip_detection"]:
    AddIfMissing(ossec_conf, "<decoder_exclude>0310-ssh_decoders.xml</decoder_exclude>")
  END IF
  
  AddIfMissing(ossec_conf, "<logall>yes</logall>")
  AddIfMissing(ossec_conf, "<logall_json>yes</logall_json>")
  
  // Step 8: Restart if config changed
  IF any_file_changed:
    DOCKER_EXEC(container, "/var/ossec/bin/wazuh-control restart")
  END IF
  
  // Step 9: Configure filebeat using volume-mapped paths
  ConfigureFilebeat(container, scenario_path)
  
  // Step 10: Setup filebeat pipelines
  DOCKER_EXEC(container, 
    "filebeat setup --pipelines --modules wazuh --strict.ssl=false",
    ignore_errors=TRUE)  // Non-critical

  // Step 11: Update centralized agent configuration (agent.conf) on manager
  ENSURE_DIR_EXISTS_LOCAL(host_ossec_etc + "/shared/default")
  ENSURE_FILE_EXISTS_LOCAL(agent_conf)

  IF MarkerNotExists(agent_conf, "RADAR: " + scenario_name + " agent_config"):
    agent_snippet ← READ_FILE(scenario_path.agent_snippet)
    AppendBlock(agent_conf,
                markers="RADAR: " + scenario_name + " agent_config",
                content=agent_snippet)
  END IF

  DOCKER_EXEC(container, "/var/ossec/bin/verify-agent-conf -f /var/ossec/etc/shared/default/agent.conf")
  
  RETURN SUCCESS


// ============================================
// DOCKER_REMOTE DEPLOYMENT
// ============================================
FUNCTION DeployRemoteContainer(scenario_path, manager_vars, bootstrap_flag):
  
  remote_host ← manager_vars.ansible_host
  remote_user ← manager_vars.ansible_user
  container ← manager_vars.container_name
  
  // Step 1: Bootstrap if needed
  IF bootstrap_flag:
    stage_dir ← CREATE_TEMP_DIR_ON_REMOTE(remote_host)
    COPY_DOCKER_COMPOSE(stage_dir, remote_host)
    SSH_EXEC(remote_host, "docker compose up -d")
    WAIT_FOR_CONTAINER(remote_host, container, retries=20)
  END IF
  
  // Step 2: Verify container running
  REPEAT 3 TIMES with 30sec delay:
    IF docker.ps(container, remote_host) == RUNNING:
      BREAK
  END REPEAT
  
  // Step 3-11: Same as docker_local, but:
  //    - Operations run on remote_host via SSH
  //    - Use "become: true" for privilege escalation
  
  RETURN SUCCESS


// ============================================
// HOST_REMOTE DEPLOYMENT  
// ============================================
FUNCTION DeployRemoteHost(scenario_path, manager_vars):
  
  remote_host ← manager_vars.ansible_host
  remote_user ← manager_vars.ansible_user
  
  // Step 1: Verify target directories
  ENSURE_DIRS_EXIST(remote_host, [
    "/var/ossec",
    "/var/ossec/etc",
    "/var/ossec/etc/lists",
    "/var/ossec/active-response/bin"
  ])
  
  // Step 2: Read scenario snippets on controller
  ossec_snippet ← READ_FILE(scenario_path + "/radar-ossec-snippet.xml")
  decoder_snippet ← READ_FILE(scenario_path + "/local_decoder.xml")
  rules_snippet ← READ_FILE(scenario_path + "/local_rules.xml")
  
  // Step 3: Insert into host files via Ansible modules (idempotent)
  INSERT_INTO_FILE(remote_host, "/var/ossec/etc/ossec.conf",
                   marker="RADAR: " + scenario_name,
                   content=ossec_snippet)
  
  APPEND_TO_FILE(remote_host, "/var/ossec/etc/decoders/local_decoder.xml",
                 marker="RADAR_DECODERS: " + scenario_name,
                 content=decoder_snippet)
  
  APPEND_TO_FILE(remote_host, "/var/ossec/etc/rules/local_rules.xml",
                 marker="RADAR_RULES: " + scenario_name,
                 content=rules_snippet)
  
  // Step 4: Copy active response files
  IF file_exists(scenario_path + "/radar_ar.py"):
    SCP(scenario_path + "/radar_ar.py",
        remote_host + ":/var/ossec/active-response/bin/")
  END IF
  
  // Step 5: Handle SSH decoder (if applicable)
  IF scenario_name IN ["suspicious_login", "geoip_detection"]:
    CopySshDecoderOverride(remote_host, scenario_path)
  END IF
  
  // Step 6: Validate ossec.conf XML (if Python available)
  TRY:
    SSH_EXEC(remote_host, "python3 -m xml.etree.ElementTree " +
                          "/var/ossec/etc/ossec.conf")
  CATCH:
    WARN "Could not validate XML syntax"
  END TRY
  
  // Step 7: Restart Wazuh if config changed
  IF any_file_changed:
    SSH_EXEC(remote_host, "/var/ossec/bin/wazuh-control restart",
             become=true)
  END IF
  
  RETURN SUCCESS


// ============================================
// HELPER FUNCTIONS
// ============================================

FUNCTION CopyConfigFiles(container, scenario_path):
  
  // Active response env vars
  IF file_exists(".env"):
    COPY_TO_VOLUME(".env", host_active_response_bin + "/active_responses.env")
  END IF
  
  // Whitelist (geoip scenario)
  IF file_exists(scenario_path + "/whitelist_countries"):
    ENSURE_DIR(host_ossec_etc + "/lists")
    COPY_TO_VOLUME(scenario_path + "/whitelist_countries",
                   host_ossec_etc + "/lists/whitelist_countries")
    SET_PERMS(container, "/var/ossec/etc/lists/whitelist_countries",
              "root:wazuh", "0644")
    AddToOssecConf(container, "<list>etc/lists/whitelist_countries</list>")
  END IF
  
  // Unified active response script
  IF file_exists(scenario_path + "/active_responses/radar_ar.py"):
    COPY_TO_VOLUME(scenario_path + "/active_responses/radar_ar.py",
                   host_active_response_bin + "/radar_ar.py")
  END IF

  IF file_exists(scenario_path + "/active_responses/ar.yaml"):
    COPY_TO_VOLUME(scenario_path + "/active_responses/ar.yaml",
        host_active_response_bin + "ar.yaml")
  END IF

  IF dir_exists("pyflowintel"):
    SCP_RECURSIVE("/pyflowintel",
                  container + ":/var/ossec/active-response/bin/")
  END IF

  

END FUNCTION


FUNCTION ConfigureFilebeat(container):
  
  filebeat_yml ← host_filebeat_etc + "/filebeat.yml"
  
  // Enable archives
  REPLACE_IN_FILE(filebeat_yml, "enabled: false", "enabled: true",
                  within_section="archives")
  REPLACE_IN_FILE(filebeat_yml, "var.paths: []", 
                  "var.paths:\n  - /var/ossec/logs/archives/archives.json",
                  within_section="archives")
  
  IF file_changed:
    DOCKER_RESTART(container)
  END IF

END FUNCTION


FUNCTION MarkerExists(container, file_path, marker_text):
  result ← DOCKER_EXEC(container, "grep -F '" + marker_text + "' " + file_path)
  RETURN result.exit_code == 0
END FUNCTION


FUNCTION COPY_IF_DIFFERENT(src, dest_container_path):
  src_sum ← HASH_FILE(src)
  dest_sum ← DOCKER_EXEC(container, "sha256sum " + dest_container_path)
  
  IF src_sum != dest_sum:
    COPY_TO_VOLUME(src, dest_host_path)
    RETURN TRUE
  END IF
  
  RETURN FALSE
END FUNCTION

```

---

## Block 1: Variable resolution & initialization

### Purpose
Establish common variables used across all blocks.

### Key variables resolved
| Variable | Source | Purpose |
|----------|--------|---------|
| `_scenario_root` | Ansible fact | Root scenarios directory (e.g., `radar/scenarios`) |
| `_scenario_path` | Ansible fact (derived) | Resolved per-scenario artifact paths across the new structure (ossec/decoders/rules/lists/filebeat) |
| `_mgr_mode` | Inventory host var | Deployment mode: `docker_local`, `docker_remote`, or `host_remote` |
| `_mgr_container` | Inventory (default: `wazuh.manager`) | Docker container name |
| `_list_marker` | Hardcoded | Marker for geoip whitelist insertion |
| `_radar_ar_dest` | Hardcoded | Container path to the generalized active response script (`radar_ar.py`) |
| `_lists_dir` | Hardcoded | Container path to Wazuh lists directory |
| `_host_ossec_conf` | Derived from `volumes.yml` | Host bind-mount path for `ossec.conf` (e.g., `/radar-srv/wazuh/manager/etc/ossec.conf`) |
| `_host_decoders_dir` | Derived from `volumes.yml` | Host bind-mount dir for decoders (e.g., `/radar-srv/wazuh/manager/etc/decoders`)                                                   |
| `_host_rules_dir` | Derived from `volumes.yml` | Host bind-mount dir for rules (e.g., `/radar-srv/wazuh/manager/etc/rules`) |
| `_host_active_response_bin` | Derived from `volumes.yml` | Host bind-mount dir for active responses (e.g., `/radar-srv/wazuh/manager/active-response/bin`) |
| `_host_filebeat_yml` | Derived from `volumes.yml` | Host bind-mount path for `filebeat.yml` (e.g., `/radar-srv/wazuh/manager/filebeat/etc/filebeat.yml`) |


### Logic
```yaml
- Check .env file existence on controller (for active response env vars)
- Set scenario paths and destination paths
- Load volumes.yml from controller
- Parse volumes.yml to extract volume mappings
- Derive host paths from volume mappings
- Validate required volume mappings exist
- Debug output current manager mode
```

---

# Blocks breakdown

## Block 2: DOCKER_LOCAL

### Conditions
```yaml
when: _mgr_mode == 'docker_local'
```

### Purpose
Deploy scenario to a **local Docker container** on the controller machine.

### Sub-blocks and logic flow

#### 2.1 Container health check
**What**: Verify manager container is running  
**How**: `docker ps` with retries (3x, 30sec delay)  
**Why**: Ensure container is ready before modifications  
**Idempotency**: Register variable, use `changed_when: false` (check-only)

---

#### 2.2 Configuration files copy
Transfers scenario-specific files into container via volume-mapped directories:

| File | Source | Destination | Purpose |
|------|--------|-------------|---------|
| `.env` | Controller | `{host_active_response_bin}/active_responses.env` | Active response environment vars |
| `whitelist_countries` | Scenario dir | `{host_lists_dir}/whitelist_countries` | IP whitelist for geoip scenario |
| `radar_ar.py` | Scenario dir | `{host_active_response_bin}/radar_ar.py` | Unified active response script |
| `ar.yaml` | Scenario dir | `{host_active_response_bin}/ar.yaml` | Risk config for radar_ar |
| `pyflowintel` | Controller | `{host_active_response_bin}/pyflowintel/` | FlowIntel wrapper |

**What**: Copy scenario configuration files to volume-mapped host directories  
**How**: Ansible `copy` module to host paths, then fix permissions via container exec  
**Why**: Volume mapping makes files immediately visible to container without `docker cp`  
**When**: Files only copied if source exists

**Idempotency**: 
- Files only copied if source exists or checksum differs
- Ownership/perms set correctly (root:wazuh, 0640/0750)
- Whitelist insertion checks for duplicate marker before adding

**Key changes**: 
- Active response consolidated from `radar_ar.py` and `ad_context_*.py` to single `radar_ar.py` script
- `radar_ar.py` expects `ar.yaml` in the same directory for risk configuration
- `pyflowintel` is vendored under active-response/bin for FlowIntel case creation
- `PYFLOWINTEL_PATH` environment variable points to `/var/ossec/active-response/bin/pyflowintel`
- No pip install needed for pyflowintel itself (vendored); only runtime dependencies required in container/host Python: `yaml` (PyYAML) and `requests` (for OpenSearch and FlowIntel HTTP operations)

---

#### 2.3 Decoder insertion
**What**: Copy scenario decoders as files into `/var/ossec/etc/decoders/` via volume

**How**: Copy `*.xml` files from `scenarios/decoders/{{scenario_name}}/` to `{host_decoders_dir}/`, then normalize permissions via container exec

**Why**: Volume mapping eliminates need for `docker cp` operations

**When**: Always executed for each scenario

**Idempotency mechanism**: Copy only when source exists and content differs (or missing)

**Flow**:
1. Ensure host decoders directory exists
2. Copy files to volume-mapped directory on host
3. Normalize perms/ownership via `docker exec`

---

#### 2.4 Rules insertion
**What**: Copy scenario rules as files into `/var/ossec/etc/rules/` via volume

**How**: Identical to decoders, but for rules directory

**Why**: Same volume-mapping benefits as decoders

**When**: Always executed for each scenario

**Idempotency**: Same as decoders

---

#### 2.5 ossec.conf modification
**What**: Modify Wazuh core configuration  
**How**: Complex multi-step process using volume-mapped file  
**Why**: Enable scenario-specific settings (active responses, rule configs)  
**When**: Always executed for each scenario

**Complex multi-step process**:

1. **Verify snippet exists**: Check scenario ossec snippet file on controller
2. **Ensure file exists**: Validate `{host_ossec_conf}` exists on host
3. **Insert RADAR snippet**: Use `blockinfile` with scenario-specific markers (idempotent) 
4. **Check for custom SSH decoder**: Execute `docker exec` to test if `0310-ssh.xml` exists
5. **Add SSH decoder exclusion**: Insert `<decoder_exclude>` if custom override present
6. **Ensure logging**: Set `<logall>yes</logall>` and `<logall_json>yes</logall_json>`
7. **Fix perms**: Execute in container to set root:wazuh ownership, 0640 mode
8. **Track changes**: Register all modification tasks

**Idempotency**: 
- `blockinfile` with markers prevents duplicates
- Conditional execution checks for changes
- `replace` module is inherently idempotent

---

#### 2.6 Service restart
**What**: Restart Wazuh service if configuration changed  
**How**: `docker exec wazuh.manager /var/ossec/bin/wazuh-control restart`  
**Why**: Apply configuration changes without full container restart  
**When**: If any of these changed:
- ossec.conf modifications
- Decoders
- Rules
- Active response scripts
- Whitelist insertion

---

#### 2.7 Filebeat configuration
**What**: Enable archives in filebeat.yml for log collection

**Steps**:
1. Edit `/etc/filebeat/filebeat.yml` via volume-mapped file
2. Modify to enable archives and set paths
3. Restart container if needed

**Idempotency**: 
- Check if file exists before modification
- Conditional restart only on changes
- Markers in regex replacements

---

#### 2.8 OpenSearch template upload
**What**: Upload wazuh-ad-log-volume index template to OpenSearch  
**How**: HTTP PUT request to `/_index_template/wazuh-ad-log-volume-*`  
**When**:  Only for scenario_name == 'log_volume'
**Idempotency**: Check HTTP status (200/201 = success)  
**TLS**: `validate_certs: no` (handles self-signed certs)
**Why**: This creates a template for index to store log volume metric events

---

#### 2.9 RADAR log_volume index template & archives pipeline routing
**What**: Configures dedicated OpenSearch index and routes `log_volume_metric` events via Wazuh archives ingest pipeline

**How**: Pull pipeline.json from container, patch with routing logic, push back

**When**: Only for `scenario_name == 'log_volume'`

**Why**: This isolates the log volume metrics into a RADAR-controlled index with correct mappings (e.g., `data.log_bytes` as numeric), without changing the global `wazuh-archives-*` schema or impacting existing dashboards. Any future events from the `log_volume_metric` program are now indexed into the dedicated `wazuh-ad-log-volume-*` indices, while all other archives events remain under the standard Wazuh index pattern.

**Steps**:
1. Pull `/usr/share/filebeat/module/wazuh/archives/ingest/pipeline.json` via `docker cp`
2. Read routing snippet from `scenarios/pipelines/log_volume/radar-pipeline.txt`
3. Replace single `date_index_name` processor with two-branch conditional:
   - If `predecoder.program_name == "log_volume_metric"` → index prefix `wazuh-ad-log-volume-*`
   - Else → fallback to `{{fields.index_prefix}}` (standard `wazuh-archives-*`)
4. Push patched pipeline back via `docker cp`
5. Reload Filebeat pipelines

**Note**: Pipeline.json not volume-mapped, requires `docker cp` operations

---

#### 2.10 Centralized agent configuration via `agent.conf`

**What**: Deploys agent-side settings centrally from the manager using Wazuh Centralized Configuration (`agent.conf`)

**How**: Append a scenario-scoped `<agent_config ...>` block into `/var/ossec/etc/shared/default/agent.conf` (volume-mapped via `/var/ossec/etc`), validate with `verify-agent-conf`

**When**: For scenarios that require agent-side log collection

**Steps**:
1. Ensure directory and file exist: {{ host_ossec_etc }}/shared/default/agent.conf
2. Read scenario snippet from `scenarios/agent_configs/{{ scenario_name }}/radar-{{ scenario_slug }}-agent-snippet.xml` (must contain a complete `<agent_config ...>...</agent_config>` block)
3. Insert block in `agent.conf` using a stable marker `RADAR: {{ scenario_name }} agent_config`
4. Validate using `verify-agent-conf`

---

## Block 3: DOCKER_REMOTE

### Conditions
```yaml
when: _mgr_mode == 'docker_remote'
```

### Purpose
Deploy scenario to a **Docker container on a remote host** via SSH.

### Key differences from docker_local

#### 3.1 Staging directory
**What**: Create temporary directory on remote host  
**How**: Using `tempfile` module  
**Why**: Clean, isolated staging area for bootstrap files  
**When**: Always created at start of remote deployment

```bash
_stage.path = /tmp/radar_mgr_XXXXX/
```

#### 3.2 Bootstrap manager option
**What**: Deploy entire Wazuh stack from scratch  
**How**: Multi-step Docker Compose deployment  
**Why**: Enables greenfield deployments on remote hosts  
**When**: If `manager_bootstrap == true` (i.e., manager doesn't exist yet)

**Steps**:
1. Create directory tree on remote
2. Copy docker-compose files, configs, certs
3. Run `docker-compose up -d`
4. Wait for container readiness (20 retries, 3sec delay)

---

#### 3.3 Webhook bootstrap
**What**: Deploy webhook container alongside manager  
**How**: Separate Docker Compose stack  
**Why**: Enable Teams/Slack integrations  
**When**: If `manager_bootstrap == true` AND webhook container not running

**Purpose**: Deploy webhook container alongside manager  
**Scope**: Separate from manager configuration

---

#### 3.4 Decoders/rules
**What**: Deploy scenario decoders and rules  
**How**: Identical logic to docker_local  
**Why**: Same volume-mapping approach works on remote  
**When**: Always executed

**Execution context**: Remote host via `become: true`

---

#### 3.5 ossec.conf handling
**What**: Modify Wazuh configuration  
**How**: Enhanced vs docker_local with additional SSH decoder checks  
**Why**: Support scenarios requiring custom SSH decoders  
**When**: Always executed

**Enhanced features**:
- Additional checks for SSH decoder override
- Lineinfile module for whitelist insertion (alternative to sed)
- Better error handling with `become: true`

---

#### 3.6 Active response artifact transfer (pyflowintel)

- `docker_local`: copy directly to controller bind-mount path.
- `docker_remote`: stage to /tmp/pyflowintel/, then privileged copy into bind mount.
- Do not rsync directly into bind mount unless permissions are guaranteed.

---

## Block 4: HOST_REMOTE

### Conditions
```yaml
when: _mgr_mode == 'host_remote'
```

### Purpose
Deploy to **bare-metal Wazuh Manager** on remote host (no Docker).

### Key differences

#### 4.1 Directly modifying host files
No Docker intermediate → modify host files directly:
- `/var/ossec/etc/ossec.conf`
- `/var/ossec/etc/decoders/local_decoder.xml`
- `/var/ossec/etc/rules/local_rules.xml`

#### 4.2 Directory validation
Ensures target directories exist (parent creation):
```bash
/var/ossec
/var/ossec/etc
/var/ossec/etc/lists
/var/ossec/active-response/bin
```

#### 4.3 Read snippets to variables
Uses `lookup()` to read scenario snippets on controller  
**Why**: Single file transfer, then insert from variable (fewer SSH ops)

#### 4.4 blockinfile for config insertion
Uses Ansible `blockinfile` module (preferred for idempotency over shell scripts)

#### 4.5 XML validation (Optional)
Attempts to validate ossec.conf well-formedness using Python XML parser  
**Why**: Catch config errors early  
**Graceful**: Skips if Python not available

---


---

## Idempotency mechanisms

### 1. **Marker-based insertion** (Primary)
```yaml
blockinfile:
  marker: "<!-- RADAR: {{ scenario_name }} {mark} -->"
```
- Ansible `blockinfile` tracks content between markers
- Only inserts if marker not present
- Safe to re-run without duplication
- Used for: ossec.conf, decoders, rules

### 2. **Checksum comparison**
```bash
lsum="$(sha256sum "$f" | awk '{print $1}')"
rsum="$(docker exec ... sha256sum ...)"
if [ "$lsum" != "$rsum" ]; then copy; fi
```
- Used for: radar_ar.py
- Avoids unnecessary copies
- Detects content changes

### 3. **Existence checks**
```bash
if grep -Fq "$marker" "$file"; then
  echo "NOCHANGE"
else
  append content
fi
```
- Used for: decoders, rules
- Simple grep for marker presence

### 4. **Conditional execution**
```yaml
when:
  - file_stat.stat.exists
  - previous_task is changed
```
- Only execute if prerequisites met
- Saves unnecessary operations

---

## Error handling strategy

### Retry pattern
```yaml
retries: 3
delay: 30
until: result.rc == 0
```
Used for:
- Container health checks (initial startup)
- Network operations (template upload)

### Failed-when false
```yaml
failed_when: false
```
Used for:
- Filebeat setup (non-critical)
- Optional operations

### Status tracking
```yaml
register: _variable_name
changed_when: "'CHANGED' in stdout"
```
- Capture output for inspection
- Conditional downstream logic

---

## Scenario-specific customization

### Scenario selection
```yaml
--extra-vars "scenario_name=suspicious_login"
```

### Scenario path resolution
```
controller:/home/user/radar/scenarios/
├── active_responses/
|   ├── ar.yaml
│   └── radar_ar.py
├── lists/
│   └── whitelist_countries
├── ossec/
│   ├── radar-geoip-detection-ossec-snippet.xml
│   ├── radar-log-volume-ossec-snippet.xml
│   └── radar-suspicious-login-ossec-snippet.xml
├── decoders/
│   └── {{ scenario_name }}/
│       └── *.xml
├── rules/
│   └── {{ scenario_name }}/
│       └── *.xml
├── templates/
│   └── {{ scenario_name }}/
│       └── radar-template.json
├── pipelines/
│   └── {{ scenario_name }}/
│       └── radar-pipeline.txt
└── agent_configs/
    └── {{ scenario_name }}/
        └── radar-{{ scenario_slug }}-agent-snippet.xml
```

### Conditional blocks
| Scenario | Conditional Block |
|----------|------------------|
| `suspicious_login`, `geoip_detection` | 0310 SSH decoder override |
| `log_volume` | Index template upload + archives pipeline routing + filebeat setup |
| All | Decoders + Rules + ossec.conf modifications |

---

## Deployment mode selection logic

```yaml
# From build-radar.sh
--manager local   → _mgr_mode = docker_local     (block 2)
--manager remote  → _mgr_mode = docker_remote    (block 3)
--manager host    → _mgr_mode = host_remote      (block 4)
```

Each block:
- Receives same variable set
- Adapted for deployment environment
- Produces same end-state (Wazuh + scenario config)

---

## File modification tracking

### Files modified per block

#### docker_local/docker_remote:
- `/var/ossec/etc/ossec.conf` (via volume: `{host_ossec_conf}`)
- `/var/ossec/etc/decoders/*.xml` (via volume: `{host_decoders_dir}`)
- `/var/ossec/etc/rules/*.xml` (via volume: `{host_rules_dir}`)
- `/var/ossec/etc/lists/whitelist_countries` (via volume: `{host_lists_dir}`, conditional)
- `/var/ossec/active-response/bin/radar_ar.py` (via volume: `{host_active_response_bin}`)
- `/var/ossec/active-response/bin/ar.yaml` (via volume: `{host_active_response_bin}`)
- `/var/ossec/active-response/bin/active_responses.env` (via volume: `{host_active_response_bin}`)
- `/etc/filebeat/filebeat.yml` (via volume: `{host_filebeat_yml}`)
- `/var/ossec/etc/shared/<GROUP_NAME>/agent.conf` (via volume: `{_host_shared_group_dir}`)
- `/usr/share/filebeat/module/wazuh/archives/ingest/pipeline.json` (via docker cp, conditional for log_volume)
- OpenSearch: `/_index_template/wazuh-alerts-*` (HTTP PUT)
- OpenSearch: `/_index_template/radar-log-volume` (conditional, HTTP PUT)

#### host_remote:
- Same files, modified directly on host

---

## Extending the playbook

### Adding a new scenario
1. Create directory: `radar/scenarios/`
2. Populate with:
   - `ossec/radar-{{ scenario_name }}-ossec-snippet.xml` → ossec.conf insertions
   - `decoders/{{ scenario_name }}/*.xml` → custom decoders
   - `rules/{{ scenario_name }}/*.xml` → custom rules
   - `active_responses/radar_ar.py` → unified active response script (if needed)
   - `templates/{{ scenario_name }}/radar-template.json` (optional) → index template
   - `pipelines/{{ scenario_name }}/radar-pipeline.txt` (optional) → pipeline routing
   - `agent_configs/radar-{{ scenario_name }}-agent-snippet.xml` → agent.conf insertions
3. Conditionals in playbook automatically handle new scenario

### Adding a new deployment mode
1. Create new block with `when: _mgr_mode == 'new_mode'`
2. Adapt logic to target environment (e.g., Kubernetes, cloud)
3. Maintain same file modification pattern