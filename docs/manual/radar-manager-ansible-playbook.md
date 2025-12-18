# Wazuh manager Ansible playbook logic documentation

## Overview

The [Wazuh manager deployment playbook](/soar-radar/roles/wazuh_manager/tasks/main.yml) (at `soar-radar/roles/wazuh_manager/tasks/main.yml`) automates the deployment and configuration of Wazuh Manager instances with RADAR scenario-specific customizations. It supports three deployment modes (local Docker, remote Docker, and remote host) and ensures idempotent, scenario-aware configuration management.

## Table of contents

- [High-level architecture](#high-level-architecture)
- [Execution flow diagram](#execution-flow-diagram)
- [Key design principles](#key-design-principles)
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
      │  ├─ Stage RADAR snippets
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

## Refactor: task decomposition & shared interface

The manager playbook was decomposed into small task files, each responsible for a single configuration domain. The key refactor idea is: tasks are mode-agnostic; only the source path changes between `docker_local` and `docker_remote`. 

The orchestration is centralized in `main.yml`, which acts as a control plane, not an execution script.

Common task modules (`roles/wazuh_manager/tasks/`):

| Task file       | Responsibility                         | Modified resources                   |
| --------------- | -------------------------------------- | ------------------------------------ |
| `stage.yml`     | Stage scenario artifacts (remote only) | Remote temp directory                |
| `responses.yml` | Active response scripts & env          | `/var/ossec/active-response/bin`     |
| `lists.yml`     | Whitelists / lists                     | `/var/ossec/etc/lists`, `ossec.conf` |
| `decoders.yml`  | Custom decoders                        | `local_decoder.xml`, SSH overrides   |
| `rules.yml`     | Custom rules                           | `local_rules.xml`                    |
| `ossec.yml`     | Core manager configuration             | `ossec.conf`                         |
| `filebeat.yml`  | Ingest & indexing logic                | Filebeat config, pipelines           |
| `bootstrap.yml` | Manager / webhook bootstrap            | Docker Compose stack                 |

Each task file:

- Has one clear responsibility
- Is idempotent by design
- Is reusable across deployment modes

Shared interface (`src` argument):

- docker_local: `src = {{ _scenario_path }}`
- docker_remote: `src = {{ _stage.path }}`

This keeps business logic identical across modes and prevents divergence.

---

## Pseudocode: automation algorithm

Here we provide a summarized description of the entire automation pipeline in the form of pseudocode.

```
FUNCTION DeployRadarScenario(scenario_name, manager_mode, bootstrap_flag):
  
  // ============================================
  // PHASE 1: INITIALIZATION
  // ============================================
  scenario_path ← RESOLVE_SCENARIO_DIR(scenario_name)
  manager_vars ← LOAD_INVENTORY_VARS(manager_mode)
  
  IF scenario_path DOES NOT EXIST:
    FAIL "Scenario path not found"
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
  
  // Step 4: Stage scenario snippets
  DOCKER_EXEC(container, "mkdir -p /tmp/radar_snippets")
  COPY_TO_CONTAINER(container, [
    scenario_path + "/radar-ossec-snippet.xml",
    scenario_path + "/local_decoder.xml",
    scenario_path + "/local_rules.xml"
  ], "/tmp/radar_snippets/")
  
  // Step 5: Append decoders (idempotent)
  IF NOT MarkerExists(container, "/var/ossec/etc/decoders/local_decoder.xml",
                      "RADAR_DECODERS: " + scenario_name):
    decoder_content ← READ_FILE("/tmp/radar_snippets/local_decoder.xml")
    AppendToFile(container, "/var/ossec/etc/decoders/local_decoder.xml",
                 markers=SCENARIO_NAME, content=decoder_content)
  END IF
  
  // Step 6: Append rules (idempotent)
  SAME AS Step 5 but for rules file
  
  // Step 7: Handle SSH decoder override (if applicable)
  IF scenario_name IN ["suspicious_login", "geoip_detection"]:
    CopySshDecoderOverride(container, scenario_path)
  END IF
  
  // Step 8: Modify ossec.conf (idempotent)
  ossec_conf ← DOCKER_CP(container, "/var/ossec/etc/ossec.conf", "/tmp/")
  
  IF MarkerNotExists(ossec_conf, "RADAR: " + scenario_name):
    snippet ← READ_FILE(scenario_path + "/radar-ossec-snippet.xml")
    InsertBefore(ossec_conf, "</ossec_config>", 
                 markers="RADAR: " + scenario_name,
                 content=snippet)
  END IF
  
  AddIfMissing(ossec_conf, "<logall>yes</logall>")
  AddIfMissing(ossec_conf, "<logall_json>yes</logall_json>")
  
  DOCKER_CP(ossec_conf, container, "/var/ossec/etc/ossec.conf")
  SET_PERMS(container, "/var/ossec/etc/ossec.conf", "root:wazuh", "0640")
  
  // Step 9: Restart if config changed
  IF any_file_changed:
    DOCKER_EXEC(container, "/var/ossec/bin/wazuh-control restart")
  END IF
  
  // Step 10: Configure filebeat
  ConfigureFilebeat(container)
  
  // Step 11: Setup filebeat pipelines
  DOCKER_EXEC(container, 
    "filebeat setup --pipelines --modules wazuh --strict.ssl=false",
    ignore_errors=TRUE)  // Non-critical
  
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
  //    - Use stage_dir for file transfers first
  //    - Use "become: true" for privilege escalation
  
  // Example:
  stage_dir ← CREATE_TEMP_DIR_ON_REMOTE(remote_host)
  SCP(scenario_path + "/*", remote_host:stage_dir)
  SSH_EXEC(remote_host, "docker cp " + stage_dir + "/* " + container + ":/tmp/")
  
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
  IF file_exists(scenario_path + "/email_ar.py"):
    SCP(scenario_path + "/email_ar.py",
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
    DOCKER_CP(".env", container + ":/var/ossec/active-response/bin/active_responses.env")
  END IF
  
  // Whitelist (geoip scenario)
  IF file_exists(scenario_path + "/whitelist_countries"):
    DOCKER_EXEC(container, "mkdir -p /var/ossec/etc/lists")
    DOCKER_CP(scenario_path + "/whitelist_countries",
              container + ":/var/ossec/etc/lists/whitelist_countries")
    SET_PERMS(container, "/var/ossec/etc/lists/whitelist_countries",
              "root:wazuh", "0644")
    AddToOssecConf(container, "<list>etc/lists/whitelist_countries</list>")
  END IF
  
  // Email active response
  IF file_exists(scenario_path + "/active_responses/email_ar.py"):
    COPY_IF_DIFFERENT(scenario_path + "/active_responses/email_ar.py",
                      container + ":/var/ossec/active-response/bin/email_ar.py")
  END IF
  
  // AD context helpers
  FOR each file IN ListDir(scenario_path + "/active_responses/ad_context_*.py"):
    COPY_IF_DIFFERENT(file, 
                      container + ":/var/ossec/active-response/bin/" + BASENAME(file))
  END FOR

END FUNCTION


FUNCTION ConfigureFilebeat(container):
  
  filebeat_yml ← DOCKER_CP(container, "/etc/filebeat/filebeat.yml", "/tmp/")
  
  // Enable archives
  REPLACE_IN_FILE(filebeat_yml, "enabled: false", "enabled: true",
                  within_section="archives")
  REPLACE_IN_FILE(filebeat_yml, "var.paths: []", 
                  "var.paths:\n  - /var/ossec/logs/archives/archives.json",
                  within_section="archives")
  
  IF file_changed:
    DOCKER_CP(filebeat_yml, container + ":/etc/filebeat/filebeat.yml")
    DOCKER_EXEC(container, "docker restart " + container)
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
    DOCKER_CP(src, container + ":" + dest_container_path)
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
| `_scenario_path` | Ansible fact | Path to scenario directory (e.g., `soar-radar/suspicious_login`) |
| `_mgr_mode` | Inventory host var | Deployment mode: `docker_local`, `docker_remote`, or `host_remote` |
| `_mgr_container` | Inventory (default: `wazuh.manager`) | Docker container name |
| `_list_marker` | Hardcoded | Marker for geoip whitelist insertion |
| `_email_ar_dest` | Hardcoded | Container path to email active response script |
| `_lists_dir` | Hardcoded | Container path to Wazuh lists directory |

### Logic
```yaml
- Check .env file existence on controller (for active response env vars)
- Set scenario paths and destination paths
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
Transfers scenario-specific files into container:

| File | Source | Destination | Purpose |
|------|--------|-------------|---------|
| `.env` | Controller | `/var/ossec/active-response/bin/active_responses.env` | Active response environment vars |
| `whitelist_countries` | Scenario dir | `/var/ossec/etc/lists/` | IP whitelist for geoip scenario |
| `email_ar.py` | Scenario dir | `/var/ossec/active-response/bin/` | Email active response script |
| `ad_context_*.py` | Scenario dir | `/var/ossec/active-response/bin/` | AD context helpers |
| RADAR snippets | Scenario dir | `/tmp/radar_snippets/` | Temporary staging for config insertion |

**Idempotency**: 
- Files only copied if source exists or checksum differs
- Ownership/perms set correctly (root:wazuh, 0640/0750)
- Whitelist insertion checks for duplicate marker before adding

---

#### 2.3 Decoder insertion
**What**: Append scenario decoders to `/var/ossec/etc/decoders/local_decoder.xml`

**Idempotency mechanism**:
```bash
marker: "<!-- RADAR_DECODERS: {{ scenario_name }} BEGIN -->"
marker: "<!-- RADAR_DECODERS: {{ scenario_name }} END -->"
```

**Key Fix**: Uses `touch` instead of truncation (`:> "$f"`) to preserve multiple scenarios

**Flow**:
1. Check if marker already present → skip if yes
2. Append decoder content between markers
3. Set ownership/perms

---

#### 2.4 Rules insertion
**Identical to decoders**, but for `/var/ossec/etc/rules/local_rules.xml`

---

#### 2.5 SSH decoder override
**When**: Only for `suspicious_login` or `geoip_detection` scenarios

**What**: 
- Copy custom `0310-ssh.xml` decoder override
- Exclude default Wazuh SSH decoders via `<decoder_exclude>`

**Why**: Custom SSH decoding rules may conflict with Wazuh defaults

---

#### 2.6 ossec.conf modification
**Complex multi-step process**:

1. **Pull**: Copy `/var/ossec/etc/ossec.conf` from container to `/tmp/ossec.conf.from_container`
2. **Insert RADAR snippet**: Use `blockinfile` with scenario-specific markers (idempotent)
3. **Add SSH decoder exclusion**: Insert `<decoder_exclude>` if custom override present
4. **Ensure logging**: Set `<logall>yes</logall>` and `<logall_json>yes</logall_json>`
5. **Push back**: Copy modified file to container
6. **Fix perms**: Set root:wazuh ownership, 0640 mode

**Idempotency**: 
- `blockinfile` with markers prevents duplicates
- `grep` checks before inserting decoder_exclude
- Conditional push only if file changed

---

#### 2.7 Service restart
**When**: If any of these changed:
- ossec.conf modifications
- Decoders
- Rules
- Active response scripts
- Whitelist insertion

**How**: `docker exec wazuh.manager /var/ossec/bin/wazuh-control restart`

---

#### 2.8 Filebeat configuration
**What**: Enable archives in filebeat.yml for log collection

**Steps**:
1. Pull `/etc/filebeat/filebeat.yml` from container
2. Modify to enable archives and set paths
3. Push back if changed
4. Restart container if needed

**Idempotency**: 
- Check if file exists before modification
- Conditional push only on changes
- Markers in regex replacements

---

#### 2.9 OpenSearch template upload
**What**: Upload wazuh-ad-log-volume index template to OpenSearch  
**How**: HTTP PUT request to `/_index_template/wazuh-ad-log-volume-*`  
**When**:  Only for scenario_name == 'log_volume'
**Idempotency**: Check HTTP status (200/201 = success)  
**TLS**: `validate_certs: no` (handles self-signed certs)
**Why**: This creates a template for index to store log volume metric events

---

#### 2.10 RADAR log_volume index template & archives pipeline routing
**What**: Configures a dedicated OpenSearch index for the log volume scenario and routes only `log_volume_metric` events into it via the Wazuh archives ingest pipeline.

**When**: Only for `scenario_name == 'log_volume'`

**Steps**:
1. Pull and patch Wazuh archives ingest pipeline `/usr/share/filebeat/module/wazuh/archives/ingest/pipeline.json` from the manager container to `/tmp/pipeline.wazuh.archives.orig.json` on the controller.
2. Keep a backup copy as `/tmp/pipeline.wazuh.archives.backup.json`.
3. Read a small text snippet (`radar-pipeline.txt`) from the scenario directory. This snippet contains two date_index_name processors:

  - If `predecoder.program_name == "log_volume_metric"` → index prefix `wazuh-ad-log-volume-*`
  - Else → fallback to the default `{{fields.index_prefix}}` (standard `wazuh-archives-*` behaviour).

4. Replace the original single `date_index_name` block in `pipeline.json` with this two-branch snippet.
5. Push patched pipeline back and reload Filebeat pipelines

**Why**: This isolates the log volume metrics into a RADAR-controlled index with correct mappings (e.g., `data.log_bytes` as numeric), without changing the global `wazuh-archives-*` schema or impacting existing dashboards. Any future events from the `log_volume_metric` program are now indexed into the dedicated `wazuh-ad-log-volume-*` indices, while all other archives events remain under the standard Wazuh index pattern.

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
Creates temporary directory on remote host using `tempfile` module  
**Why**: Clean, isolated staging area for all files before copying to container

```bash
_stage.path = /tmp/radar_mgr_XXXXX/
```

#### 3.2 Bootstrap manager option
**When**: If `manager_bootstrap == true` (i.e., manager doesn't exist yet)

**Steps**:
1. Create directory tree on remote
2. Copy docker-compose files, configs, certs
3. Run `docker-compose up -d`
4. Wait for container readiness (20 retries, 3sec delay)

**Why**: Enables automatic Wazuh stack provisioning from scratch

#### 3.3 File staging pattern
**Differences from docker_local**:
- Files copied to `_stage.path` first (not directly to container)
- Then batched copy into container via single `docker cp` command
- Reduces SSH overhead

**Pattern**:
```bash
Controller → (scp) → Remote _stage.path → (docker cp) → Container
```

#### 3.4 Webhook bootstrap
**When**: If `manager_bootstrap == true` AND webhook container not running

**Purpose**: Deploy webhook container alongside manager  
**Scope**: Out of manager scope, separate block

---

#### 3.5 Decoders/rules
**Identical logic to docker_local**, but executed on remote via `docker exec` + `become: true`

---

#### 3.6 ossec.conf handling
**Enhanced vs docker_local**:
- Additional checks for SSH decoder override
- Lineinfile module for whitelist insertion (alternative to sed)
- Better error handling with `become: true`

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
- Used for: email_ar.py, ad_context_*.py
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
controller:/home/user/soar-radar/{{ scenario_name }}/
├── radar-ossec-snippet.xml
├── local_decoder.xml
├── local_rules.xml
├── radar-template.json (if log_volume)
└── active_responses/
    ├── email_ar.py
    └── ad_context_*.py
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
- `/var/ossec/etc/ossec.conf`
- `/var/ossec/etc/decoders/local_decoder.xml`
- `/var/ossec/etc/rules/local_rules.xml`
- `/var/ossec/etc/lists/whitelist_countries` (conditional)
- `/var/ossec/active-response/bin/email_ar.py` (conditional)
- `/var/ossec/active-response/bin/ad_context_*.py` (conditional)
- `/etc/filebeat/filebeat.yml` (conditional)
- `/usr/share/filebeat/module/wazuh/archives/ingest/pipeline.json` (conditional, only for `log_volume` scenario)
- OpenSearch: `/_index_template/wazuh-alerts-*` (HTTP PUT)
- OpenSearch: `/_index_template/radar-log-volume` (conditional, HTTP PUT)

#### host_remote:
- Same files, modified directly on host

---

## Extending the playbook

### Adding a new scenario
1. Create directory: `soar-radar/{{ scenario_name }}/`
2. Populate with:
   - `radar-ossec-snippet.xml` → ossec.conf insertions
   - `local_decoder.xml` → custom decoders
   - `local_rules.xml` → custom rules
   - `active_responses/` → scripts
   - `radar-template.json` (optional) → index template
3. Conditionals in playbook automatically handle new scenario

### Adding a new deployment mode
1. Create new block with `when: _mgr_mode == 'new_mode'`
2. Adapt logic to target environment (e.g., Kubernetes, cloud)
3. Maintain same file modification pattern
