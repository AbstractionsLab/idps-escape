from __future__ import annotations

import shlex
import subprocess
import sys
from pathlib import Path
from typing import Iterator

from . import ar_config as ar_module
from . import connectors as conn_module
from . import vault as vault_module
from wazuh_api import config as config_module


def _validate_scenario(scenario: str, radar_root: str) -> None:
    scenarios = config_module.valid_scenarios(radar_root)
    if scenario not in scenarios:
        raise ValueError(f"Invalid scenario '{scenario}'. Must be one of: {sorted(scenarios)}")


def _prep_env(radar_root: str) -> dict:
    import os
    env = os.environ.copy()
    env.update(conn_module.load_env(radar_root))
    env.setdefault("PYTHONPATH", radar_root)
    env.setdefault("PYTHONUNBUFFERED", "1")
    return env


def _stream_process(cmd: list[str], cwd: str, env: dict, result: dict | None = None) -> Iterator[str]:
    yield f"$ {' '.join(shlex.quote(x) for x in cmd)}\n"
    try:
        proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 bufsize=1, text=True)
    except FileNotFoundError as e:
        yield f"[ERROR] executable not found: {e}\n"
        if result is not None:
            result["rc"] = 127
        return
    assert proc.stdout is not None
    try:
        for line in iter(proc.stdout.readline, ""):
            yield line
        proc.stdout.close()
        rc = proc.wait()
        yield f"\n[exit code: {rc}]\n"
        if result is not None:
            result["rc"] = rc
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def _import_wazuh_api(radar_root: str):
    if radar_root not in sys.path:
        sys.path.insert(0, radar_root)
    from wazuh_api.client import WazuhAPIClient
    from wazuh_api.manager_config import wait_for_api
    from wazuh_api.scenario_ops import (
        deploy_manager_config, deploy_scenario_config,
        undo_manager_config, undo_scenario_config,
    )
    return (WazuhAPIClient, wait_for_api, deploy_scenario_config, deploy_manager_config,
            undo_scenario_config, undo_manager_config)


def _run_cmd(radar_root: str, spec: dict) -> list[str]:
    scenario = spec.get("scenario", "")
    ingest = str(spec.get("ingest", False)).lower()
    _validate_scenario(scenario, radar_root)
    if ingest not in ("true", "false"):
        raise ValueError("ingest must be true or false")
    return ["bash", str(Path(radar_root) / "run-radar.sh"), scenario, "--ingest", ingest]


def preview(radar_root: str, spec: dict) -> dict:
    action = spec.get("action", "build")
    try:
        if action == "build":
            if spec.get("core_only"):
                steps = ["docker compose -f docker-compose.core.yml -f volumes.yml up -d",
                         "radar_deploy/manager-harden-enrollment.sh (post-boot: use_password=yes, purge=no, "
                         "port 1515 closed by default)",
                         "(no RADAR scenario applied -- plain Wazuh only)"]
                return {"ok": True, "cmd": "\n".join(steps)}
            scenario = spec.get("scenario", "")
            _validate_scenario(scenario, radar_root)
            steps = [f"radar_deploy/manager-apply-scenario.sh {scenario}",
                     "wazuh_api: deploy_scenario_config, deploy_manager_config (direct calls)"]
            return {"ok": True, "cmd": "\n".join(steps)}
        if action == "undo-scenario":
            scenario = spec.get("scenario", "")
            _validate_scenario(scenario, radar_root)
            steps = [f"radar_deploy/manager-undo-scenario.sh {scenario}",
                     "wazuh_api: undo-scenario-config, undo-manager-config (direct calls)",
                     "(shared ossec.conf blocks are always left in place; decoder/rule/list files are "
                     "removed once no other currently-deployed scenario still shares them)"]
            return {"ok": True, "cmd": "\n".join(steps)}
        if action == "health":
            scenario = spec.get("scenario", "all")
            if scenario != "all":
                _validate_scenario(scenario, radar_root)
            steps = [f"radar_deploy/manager-health.sh {scenario}",
                     f"wazuh_api.cli manager-health-api --scenario {scenario}"]
            if spec.get("agent_names"):
                steps.append(f"wazuh_api.cli agent-health --agent-name {spec['agent_names']} --scenario {scenario}")
            return {"ok": True, "cmd": "\n".join(steps)}
        cmd = _run_cmd(radar_root, spec)
        return {"ok": True, "cmd": " ".join(shlex.quote(x) for x in cmd)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _wait_for_api_with_progress(wait_for_api, dotenv: dict, client, result: dict) -> Iterator[str]:
    import queue
    import threading

    q: queue.Queue = queue.Queue()
    last_reported = [0]

    def on_tick(elapsed: float, timeout: float) -> None:
        bucket = int(elapsed) // 15
        if bucket > last_reported[0]:
            last_reported[0] = bucket
            q.put(f">>> still waiting for Wazuh API... ({int(elapsed)}s / {int(timeout)}s)\n")

    def worker() -> None:
        result["ok"] = wait_for_api(dotenv["WAZUH_API_URL"], dotenv["WAZUH_AUTH_USER"], dotenv["WAZUH_AUTH_PASS"],
                                     timeout=120, verify_ssl=client.verify_ssl, on_tick=on_tick)
        q.put(None)

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    while True:
        msg = q.get()
        if msg is None:
            break
        yield msg
    t.join()


def stream_build(radar_root: str, spec: dict, vault_session_id: str | None = None) -> Iterator[str]:
    core_only = bool(spec.get("core_only"))
    scenario = spec.get("scenario", "")
    if not core_only:
        try:
            _validate_scenario(scenario, radar_root)
        except Exception as e:
            yield f"[ERROR] {e}\n"
            return

    env = _prep_env(radar_root)
    root = Path(radar_root)

    manager_running = False
    try:
        ps_out = subprocess.run(["docker", "ps", "--format", "{{.Names}}"],
                                 capture_output=True, text=True, timeout=15)
        manager_running = "wazuh.manager" in ps_out.stdout.splitlines()
    except Exception as e:
        yield f"[ERROR] could not check docker ps: {e}\n"
        return

    if manager_running:
        yield ">>> Manager already running.\n"
    else:
        if not (vault_session_id and vault_module.has_sudo_password(vault_session_id)):
            yield "[ERROR] sudo password required to bring up the manager stack.\n"
            return

        with vault_module.sudo_askpass_env(vault_session_id, env) as sudo_env:
            yield ">>> Ensuring indexer/manager/dashboard TLS certs exist...\n"
            proc_result = {}
            yield from _stream_process(
                ["sudo", "-A", "bash", str(root / "radar_deploy" / "manager-ensure-certs.sh")],
                radar_root, sudo_env, proc_result,
            )
            if proc_result.get("rc", 0) != 0:
                yield "[ERROR] Failed to ensure TLS certs -- see the exit code above.\n"
                return

            pipeline_container_path = "/usr/share/filebeat/module/wazuh/archives/ingest/pipeline.json"
            pipeline_host_path = config_module.manager_volume_host_path_for(
                radar_root, pipeline_container_path, "wazuh.manager"
            )
            if not pipeline_host_path:
                yield (f"[ERROR] volumes.yml has no bind mount for {pipeline_container_path}.\n")
                return
            seed_script = (
                f'mkdir -p "$(dirname "{pipeline_host_path}")" && '
                f'([[ -d "{pipeline_host_path}" ]] && (rmdir "{pipeline_host_path}" 2>/dev/null || '
                f'rm -rf "{pipeline_host_path}") || true) && '
                f'if [[ ! -s "{pipeline_host_path}" ]]; then '
                f'cp "{root}/config/wazuh_cluster/pipeline-archives.json" "{pipeline_host_path}" && '
                f'chmod 644 "{pipeline_host_path}"; fi'
            )
            yield f">>> Seeding {pipeline_host_path} with default content before first container creation...\n"
            proc_result = {}
            yield from _stream_process(["sudo", "-A", "bash", "-c", seed_script], radar_root, sudo_env, proc_result)
            if proc_result.get("rc", 0) != 0:
                yield "[ERROR] Failed to seed the filebeat pipeline file -- see the exit code above.\n"
                return

            yield ">>> Bringing up local core stack (docker-compose.core.yml)...\n"
            proc_result = {}
            yield from _stream_process(
                ["sudo", "-A", "docker", "compose", "-f", "docker-compose.core.yml", "-f", "volumes.yml", "up", "-d"],
                radar_root, sudo_env, proc_result,
            )
            if proc_result.get("rc", 0) != 0:
                yield "[ERROR] Core stack failed to come up -- see the docker compose output above for the actual cause (e.g. a missing/misconfigured cert bind-mount). Stopping here rather than continuing to a misleading downstream failure.\n"
                return

    if not core_only and (root / "docker-compose.webhook.yml").is_file():
        yield ">>> Building webhook locally...\n"
        if not (vault_session_id and vault_module.has_sudo_password(vault_session_id)):
            yield "[ERROR] sudo password required to bring up the webhook.\n"
            return
        with vault_module.sudo_askpass_env(vault_session_id, env) as sudo_env:
            try:
                already_enrolled = subprocess.run(
                    ["sudo", "-A", "docker", "compose", "-f", "docker-compose.webhook.yml",
                     "run", "--rm", "--no-deps", "--build", "--entrypoint", "sh", "webhook",
                     "-c", "test -s /var/ossec/etc/client.keys"],
                    cwd=radar_root, env=sudo_env, capture_output=True, timeout=120,
                ).returncode == 0
            except Exception:
                already_enrolled = False

            sudo_env = dict(sudo_env)
            if already_enrolled:
                yield "OK - webhook already enrolled; no new token needed\n"
            else:
                yield ">>> Webhook not yet enrolled; minting a short-lived token...\n"
                mint_lines: list[str] = []
                mint_result: dict = {}
                for line in _stream_process(
                    ["sudo", "-A", "bash", str(root / "radar_deploy" / "manager-mint-token.sh"), "default", "60"],
                    radar_root, sudo_env, mint_result,
                ):
                    mint_lines.append(line)
                    yield line
                if mint_result.get("rc", 0) != 0:
                    yield "[ERROR] Could not mint an enrollment token for the webhook.\n"
                    return
                token = ""
                for line in mint_lines:
                    if line.startswith("TOKEN_VALUE="):
                        token = line.strip().split("=", 1)[1]
                        break
                if not token:
                    yield "[ERROR] Could not extract the enrollment token from manager-mint-token.sh output.\n"
                    return
                sudo_env["WAZUH_REGISTRATION_TOKEN"] = token

            webhook_up_cmd = ["sudo", "-A"]
            if sudo_env.get("WAZUH_REGISTRATION_TOKEN"):
                webhook_up_cmd += ["env", f"WAZUH_REGISTRATION_TOKEN={sudo_env['WAZUH_REGISTRATION_TOKEN']}"]
            webhook_up_cmd += ["docker", "compose", "-f", "docker-compose.webhook.yml", "up", "-d", "--build"]

            proc_result = {}
            yield from _stream_process(webhook_up_cmd, radar_root, sudo_env, proc_result)
            if proc_result.get("rc", 0) != 0:
                yield "[ERROR] Webhook container failed to come up -- see the docker compose output above.\n"
                return

    dotenv = conn_module.load_env(radar_root)
    if not all(dotenv.get(k) for k in ("WAZUH_API_URL", "WAZUH_AUTH_USER", "WAZUH_AUTH_PASS")):
        yield "[ERROR] WAZUH_API_URL / WAZUH_AUTH_USER / WAZUH_AUTH_PASS are not fully set in .env.\n"
        return

    yield ">>> Waiting for the Wazuh API to become reachable...\n"
    WazuhAPIClient, wait_for_api, deploy_scenario_config, deploy_manager_config, _, _ = _import_wazuh_api(radar_root)
    client = WazuhAPIClient(dotenv["WAZUH_API_URL"], dotenv["WAZUH_AUTH_USER"], dotenv["WAZUH_AUTH_PASS"])
    result = {"ok": False}
    yield from _wait_for_api_with_progress(wait_for_api, dotenv, client, result)
    if not result["ok"]:
        yield "[ERROR] Wazuh API did not become reachable within 120s.\n"
        return

    if core_only:
        if not (vault_session_id and vault_module.has_sudo_password(vault_session_id)):
            yield "[ERROR] sudo password required to harden enrollment.\n"
            return
        yield ">>> Hardening agent enrollment (require credential, disable auto-purge, close port 1515)...\n"
        with vault_module.sudo_askpass_env(vault_session_id, env) as sudo_env:
            proc_result = {}
            yield from _stream_process([
                "sudo", "-A", "bash", str(root / "radar_deploy" / "manager-harden-enrollment.sh")
            ], radar_root, sudo_env, proc_result)
            if proc_result.get("rc", 0) != 0:
                yield "[ERROR] Failed to harden enrollment -- see the exit code above.\n"
                return
        yield "\n=== SUCCESS: plain Wazuh manager/indexer/dashboard is up (no RADAR scenario applied) ===\n"
        yield "To layer a RADAR scenario on top later, run a normal build with a scenario selected.\n"
        return

    yield ">>> Applying manager-side scenario config (active responses, enrichment, filebeat)...\n"
    if not (vault_session_id and vault_module.has_sudo_password(vault_session_id)):
        yield "[ERROR] sudo password required to apply manager scenario.\n"
        return
    with vault_module.sudo_askpass_env(vault_session_id, env) as sudo_env:
        proc_result = {}
        yield from _stream_process([
            "sudo", "-A", "bash", str(Path(radar_root) / "radar_deploy" / "manager-apply-scenario.sh"), scenario
        ], radar_root, sudo_env, proc_result)
        if proc_result.get("rc", 0) != 0:
            yield "[ERROR] manager-apply-scenario.sh failed or was interrupted (exit code above) -- the manager container may be unhealthy. Check 'docker ps' and the container's own logs before retrying.\n"
            return

    yield f">>> Deploying '{scenario}' group/agent.conf via Wazuh API...\n"
    result = deploy_scenario_config(client, scenario, str(Path(radar_root) / "scenarios" / "agent_configs"))
    yield f"{result}\n"

    yield ">>> Deploying decoders/rules/lists and ossec.conf via Wazuh API...\n"
    result = deploy_manager_config(client, scenario, str(Path(radar_root) / "scenarios"),
                                    indexer_host=dotenv.get("WAZUH_INDEXER_HOST", "https://wazuh.indexer:9200"))
    yield f"{result}\n"

    verification = result.get("list_verification")
    if verification is not None and not verification.get("ok", True):
        yield (
            f"\n=== FAILED: CDB list(s) {verification['failures']} did not load on the manager "
            f"(see ossec.log) - rule(s) referencing them are silently inactive ===\n"
        )
        return

    try:
        ar_module.mark_deployed(radar_root, scenario, True)
    except Exception as e:
        yield f"[WARNING] deployment succeeded but could not record it as active in ar.yaml: {e}\n"

    yield f"\n=== SUCCESS: Wazuh manager and '{scenario}' deployment completed ===\n"


def stream_undo_scenario(radar_root: str, spec: dict) -> Iterator[str]:
    scenario = spec.get("scenario", "")
    try:
        _validate_scenario(scenario, radar_root)
    except Exception as e:
        yield f"[ERROR] {e}\n"
        return

    dotenv = conn_module.load_env(radar_root)
    if not all(dotenv.get(k) for k in ("WAZUH_API_URL", "WAZUH_AUTH_USER", "WAZUH_AUTH_PASS")):
        yield "[ERROR] WAZUH_API_URL / WAZUH_AUTH_USER / WAZUH_AUTH_PASS are not fully set in .env.\n"
        return

    (WazuhAPIClient, wait_for_api, _, _,
     undo_scenario_config, undo_manager_config) = _import_wazuh_api(radar_root)
    client = WazuhAPIClient(dotenv["WAZUH_API_URL"], dotenv["WAZUH_AUTH_USER"], dotenv["WAZUH_AUTH_PASS"])

    yield (f">>> Resetting '{scenario}' group agent.conf to empty, unenrolling its agents (and "
           f"'radar_shared' too, if no other shared scenario still needs it)...\n")
    result = undo_scenario_config(client, scenario, radar_root=radar_root)
    yield f"{result}\n"

    yield (f">>> Removing '{scenario}' ossec.conf block and any decoder/rule/list files no longer needed "
           f"by another currently-deployed scenario (restarts the manager only if something actually "
           f"changed)...\n")
    scenarios_dir = str(Path(radar_root) / "scenarios")
    result = undo_manager_config(client, scenario, scenarios_dir)
    yield f"{result}\n"
    if result.get("restart_triggered") and not result.get("api_back_up", True):
        yield "[ERROR] Manager restart triggered but the API did not respond in time -- check the manager manually.\n"
        return

    try:
        ar_module.mark_deployed(radar_root, scenario, False)
    except Exception as e:
        yield f"[WARNING] undo succeeded but could not record it as inactive in ar.yaml: {e}\n"

    yield f"\n=== SUCCESS: undo for '{scenario}' completed ===\n"
    yield ("Note: this is a partial, conservative undo. Run this scenario's build again any "
           "time to redeploy.\n")


def stream_run(radar_root: str, spec: dict) -> Iterator[str]:
    try:
        cmd = _run_cmd(radar_root, spec)
    except Exception as e:
        yield f"[ERROR] {e}\n"
        return
    yield from _stream_process(cmd, radar_root, _prep_env(radar_root))


def stream_health(radar_root: str, spec: dict) -> Iterator[str]:
    scenario = spec.get("scenario", "all")
    agent_names = spec.get("agent_names", "")
    try:
        if scenario != "all":
            _validate_scenario(scenario, radar_root)
    except Exception as e:
        yield f"[ERROR] {e}\n"
        return

    env = _prep_env(radar_root)

    yield "=== MANAGER (filesystem/container) ===\n"
    yield from _stream_process(["bash", str(Path(radar_root) / "radar_deploy" / "manager-health.sh"), scenario],
                                radar_root, env)

    yield "\n=== MANAGER (Wazuh API / OpenSearch / webhook) ===\n"
    yield from _stream_process(["python3", "-m", "wazuh_api.cli", "manager-health-api", "--scenario", scenario],
                                radar_root, env)

    if agent_names:
        yield "\n=== AGENTS ===\n"
        yield from _stream_process(
            ["python3", "-m", "wazuh_api.cli", "agent-health", "--agent-name", agent_names, "--scenario", scenario],
            radar_root, env,
        )


def stream_teardown(radar_root: str, spec: dict, vault_session_id: str | None = None) -> Iterator[str]:
    if not spec.get("confirm"):
        yield "[ERROR] Teardown requires explicit confirmation. Refusing without --confirm.\n"
        return

    remove_data = bool(spec.get("remove_data"))

    root = Path(radar_root)
    env = _prep_env(radar_root)

    if not (vault_session_id and vault_module.has_sudo_password(vault_session_id)):
        yield "[ERROR] sudo password required to tear down the manager stack.\n"
        return

    host_paths = config_module.manager_volume_host_paths(radar_root, "wazuh.manager") if remove_data else []

    with vault_module.sudo_askpass_env(vault_session_id, env) as sudo_env:
        yield ">>> Bringing down containers" + (" and volumes" if remove_data else "") + "...\n"
        compose_files = ["docker-compose.core.yml"]
        if (root / "docker-compose.webhook.yml").is_file():
            compose_files.append("docker-compose.webhook.yml")
        compose_files.append("volumes.yml")

        cmd = ["sudo", "-A", "docker", "compose"]
        for f in compose_files:
            cmd += ["-f", f]
        cmd += ["down", "--remove-orphans"]
        if remove_data:
            cmd.append("-v")

        proc_result = {}
        yield from _stream_process(cmd, radar_root, sudo_env, proc_result)
        if proc_result.get("rc", 0) != 0:
            yield "[ERROR] docker compose down failed: see the output above.\n"
            return

        try:
            data = ar_module.load(radar_root)
            for name, cfg in (data.get("scenarios") or {}).items():
                if name != "default" and isinstance(cfg, dict) and cfg.get("active"):
                    ar_module.mark_deployed(radar_root, name, False)
            yield ">>> Marked all scenarios as not deployed in ar.yaml (manager stack is down).\n"
        except Exception as e:
            yield f"[WARNING] manager stack is down but could not reset ar.yaml's 'active' flags: {e}\n"

        if not remove_data:
            yield "\n=== SUCCESS: manager stack stopped: data left in place ===\n"
            return

        if not host_paths:
            yield "\n=== SUCCESS: manager stack and named volumes removed ===\n"
            return

        yield f">>> Removing host-side manager data ({len(host_paths)} path(s) from volumes.yml)...\n"
        for p in host_paths:
            yield f"    {p}\n"
        proc_result = {}
        yield from _stream_process(["sudo", "-A", "rm", "-rf", *host_paths], radar_root, sudo_env, proc_result)
        if proc_result.get("rc", 0) != 0:
            yield "[ERROR] Failed to remove one or more host paths -- see the output above.\n"
            return

    yield "\n=== SUCCESS: manager stack and data removed ===\n"


def stream_mint_token(radar_root: str, spec: dict, vault_session_id: str | None = None) -> Iterator[str]:
    groups = spec.get("groups", "")
    expiry_minutes = str(spec.get("expiry_minutes", 60))
    manager_address = spec.get("manager_address", "")

    if not groups:
        yield "[ERROR] at least one group is required\n"
        return
    try:
        int(expiry_minutes)
    except ValueError:
        yield "[ERROR] expiry_minutes must be a number\n"
        return

    env = _prep_env(radar_root)

    if not (vault_session_id and vault_module.has_sudo_password(vault_session_id)):
        yield "[ERROR] sudo password required (needed so the port 1515 enrollment window can actually open).\n"
        return

    with vault_module.sudo_askpass_env(vault_session_id, env) as sudo_env:
        cmd = ["sudo", "-A", "bash", str(Path(radar_root) / "radar_deploy" / "manager-mint-token.sh"),
               groups, expiry_minutes]
        if manager_address:
            cmd.append(manager_address)
        yield from _stream_process(cmd, radar_root, sudo_env)


def stream_assign_agent_group(radar_root: str, spec: dict) -> Iterator[str]:
    agent_name = spec.get("agent_name", "").strip()
    scenario = spec.get("scenario", "")
    agent_ip = spec.get("agent_ip", "").strip()

    if not agent_name and not agent_ip:
        yield "[ERROR] at least one of agent name or agent IP is required\n"
        return
    try:
        _validate_scenario(scenario, radar_root)
    except Exception as e:
        yield f"[ERROR] {e}\n"
        return

    env = _prep_env(radar_root)
    cmd = ["bash", str(Path(radar_root) / "radar_deploy" / "manager-assign-agent-group.sh"),
           "--scenario", scenario]
    if agent_name:
        cmd += ["--agent-name", agent_name]
    if agent_ip:
        cmd += ["--agent-ip", agent_ip]
    yield from _stream_process(cmd, radar_root, env)


def stream_unassign_agent_group(radar_root: str, spec: dict) -> Iterator[str]:
    """Undo of stream_assign_agent_group: removes the agent from the
    scenario's own group(s), leaving 'default' membership untouched."""
    agent_name = spec.get("agent_name", "").strip()
    scenario = spec.get("scenario", "")
    agent_ip = spec.get("agent_ip", "").strip()

    if not agent_name and not agent_ip:
        yield "[ERROR] at least one of agent name or agent IP is required\n"
        return
    try:
        _validate_scenario(scenario, radar_root)
    except Exception as e:
        yield f"[ERROR] {e}\n"
        return

    env = _prep_env(radar_root)
    cmd = ["bash", str(Path(radar_root) / "radar_deploy" / "manager-unassign-agent-group.sh"),
           "--scenario", scenario]
    if agent_name:
        cmd += ["--agent-name", agent_name]
    if agent_ip:
        cmd += ["--agent-ip", agent_ip]
    yield from _stream_process(cmd, radar_root, env)


def stream_deregister_agent(radar_root: str, spec: dict) -> Iterator[str]:
    agent_name = spec.get("agent_name", "").strip()
    agent_ip = spec.get("agent_ip", "").strip()
    no_purge = bool(spec.get("no_purge"))

    if not agent_name:
        yield "[ERROR] agent name is required\n"
        return

    env = _prep_env(radar_root)
    cmd = ["bash", str(Path(radar_root) / "radar_deploy" / "manager-deregister-agent.sh"),
           "--agent-name", agent_name]
    if agent_ip:
        cmd += ["--agent-ip", agent_ip]
    if no_purge:
        cmd.append("--no-purge")
    yield from _stream_process(cmd, radar_root, env)


def stream_enrollment_window(radar_root: str, spec: dict, vault_session_id: str | None = None) -> Iterator[str]:
    action = spec.get("action", "")
    if action not in ("open", "close", "status"):
        yield "[ERROR] action must be one of: open, close, status\n"
        return

    root = Path(radar_root)
    env = _prep_env(radar_root)

    if not (vault_session_id and vault_module.has_sudo_password(vault_session_id)):
        yield "[ERROR] sudo password required to check or change the port 1515 enrollment window.\n"
        return

    with vault_module.sudo_askpass_env(vault_session_id, env) as sudo_env:
        cmd = ["sudo", "-A", "bash", str(root / "radar_deploy" / "manager-enrollment-window.sh"), action]
        if action == "open":
            minutes = str(spec.get("minutes", 30))
            cmd += ["--minutes", minutes]
        yield from _stream_process(cmd, radar_root, sudo_env)