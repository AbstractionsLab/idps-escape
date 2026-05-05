import os
import sys
from flask import Flask, render_template, jsonify, request, Response, stream_with_context, g, make_response
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from orchestrator import ar_config as ar_module
from orchestrator import inventory as inv_module
from orchestrator import health as health_module
from orchestrator import deploy as deploy_module
from orchestrator import vault as vault_module
from orchestrator import connectors as conn_module

app = Flask(__name__)

RADAR_ROOT = str(Path(os.environ.get("RADAR_ROOT", Path(__file__).parent.parent)).resolve())
VAULT_COOKIE = "radar_vault_sid"

SCENARIOS = [
    {"id": "geoip_detection", "name": "GeoIP Detection", "type": "signature",
     "type_label": "Signature", "description": "Detects logins from non-approved countries via whitelist comparison.",
     "status": "active", "rule_ids": [100900, 100901, 100902]},
    {"id": "suspicious_login", "name": "Suspicious Login", "type": "hybrid",
     "type_label": "Hybrid", "description": "Brute force and impossible travel detection using signature + RCF baseline.",
     "status": "active", "rule_ids": [210012, 210013, 210020, 210021, 210022, 210030, 210031]},
    {"id": "log_volume", "name": "Log Volume Growth", "type": "anomaly",
     "type_label": "Anomaly ML", "description": "Unusual spikes in log generation.",
     "status": "active", "rule_ids": [100300, 100309]}
]

KNOWN_MITIGATIONS = ["firewall-drop", "lock_user_linux", "terminate_service"]


def _enriched_scenarios():
    try:
        bound_ids = set(ar_module.list_bound_scenarios(RADAR_ROOT))
    except Exception:
        bound_ids = set()
    result = []
    for s in SCENARIOS:
        entry = {**s, "bound": s["id"] in bound_ids}
        if entry["bound"]:
            try:
                entry["ar_config"] = ar_module.get_scenario(RADAR_ROOT, s["id"])
            except Exception:
                entry["ar_config"] = {}
        else:
            entry["ar_config"] = {}
        result.append(entry)
    return result


def _bound_scenario_ids():
    try:
        return ar_module.list_bound_scenarios(RADAR_ROOT)
    except Exception:
        return []


def _get_vault_sid(create=False):
    sid = request.cookies.get(VAULT_COOKIE)
    if not sid and create:
        sid = vault_module.new_session_id()
        g._new_vault_sid = sid
    return sid


def _attach_vault_cookie(resp):
    sid = getattr(g, "_new_vault_sid", None)
    if sid:
        resp.set_cookie(VAULT_COOKIE, sid, httponly=True, samesite="Lax")
    return resp


def _vault_error():
    return jsonify({"ok": False, "error": "vault password required", "need_vault": True}), 403


def _ssh_error():
    return jsonify({"ok": False, "error": "ssh passphrase required", "need_ssh": True}), 403


def _needs_ssh(node):
    return node.get("connection") == "remote" or node.get("agent_mode") == "ssh"


def _needs_vault(node):
    if not node.get("has_credential"):
        return False
    p = Path(RADAR_ROOT) / "host_vars" / f"{node['name']}.yml"
    if not p.exists():
        return False
    return p.read_text(errors="ignore")[:32].startswith("$ANSIBLE_VAULT")


def _deploy_needs_vault(spec):
    if spec.get("action") == "run":
        return False
    if not (spec.get("manager_mode") == "remote" or spec.get("agent_mode") == "remote"):
        return False
    hv = Path(RADAR_ROOT) / "host_vars"
    if not hv.exists():
        return False
    for p in hv.glob("*.yml"):
        try:
            if p.read_text(errors="ignore")[:32].startswith("$ANSIBLE_VAULT"):
                return True
        except OSError:
            continue
    return False


def _has_encrypted_files():
    hv = Path(RADAR_ROOT) / "host_vars"
    if not hv.exists():
        return False
    for p in hv.glob("*.yml"):
        try:
            if p.read_text(errors="ignore")[:32].startswith("$ANSIBLE_VAULT"):
                return True
        except OSError:
            pass
    return False


# ── Pages ──

@app.route("/")

@app.route("/infrastructure")
def infrastructure():
    try:
        summary = inv_module.get_summary(RADAR_ROOT)
    except Exception as e:
        summary = {"managers": [], "agents": [], "manager_count": 0, "agent_count": 0,
                   "local_managers": [], "remote_managers": [], "container_agents": [],
                   "ssh_agents": [], "error": str(e)}
    return render_template("infrastructure.html", summary=summary,
                           bound_scenarios=_bound_scenario_ids())


@app.route("/active-responses")
@app.route("/active-responses/<scenario_id>")
def active_responses(scenario_id=None):
    all_scenarios = _enriched_scenarios()
    bound_list = [s for s in all_scenarios if s["bound"] and s["status"] == "active"]
    if not bound_list:
        return render_template("active_responses.html",
                               bound_scenarios=[], active_id=None,
                               active_scenario=None, cfg=None,
                               known_mitigations=KNOWN_MITIGATIONS)
    if scenario_id and any(s["id"] == scenario_id for s in bound_list):
        active_id = scenario_id
    else:
        active_id = bound_list[0]["id"]
    active_scenario = next(s for s in bound_list if s["id"] == active_id)
    try:
        cfg = ar_module.get_scenario(RADAR_ROOT, active_id)
    except Exception:
        cfg = {}
    return render_template("active_responses.html",
                           bound_scenarios=bound_list,
                           active_id=active_id,
                           active_scenario=active_scenario,
                           cfg=cfg,
                           known_mitigations=KNOWN_MITIGATIONS)


@app.route("/connectors")
def connectors():
    try:
        env = conn_module.load_env(RADAR_ROOT)
    except Exception:
        env = {}
    connector_status = conn_module.has_passwords(env)
    return render_template("connectors.html", env=env, connector_status=connector_status)


@app.route("/deploy")
def deploy():
    try:
        summary = inv_module.get_summary(RADAR_ROOT)
    except Exception as e:
        summary = {"managers": [], "agents": [], "error": str(e)}
    return render_template("deploy.html",
                           summary=summary,
                           scenarios=[s for s in _enriched_scenarios() if s["status"] == "active"],
                           bound_scenarios=_bound_scenario_ids())


# ── API: Scenarios ──

@app.route("/api/scenarios")
def api_scenarios():
    return jsonify(_enriched_scenarios())


@app.route("/api/scenarios/<scenario_id>")
def api_get_scenario(scenario_id):
    scenario = next((x for x in _enriched_scenarios() if x["id"] == scenario_id), None)
    if not scenario:
        return jsonify({"ok": False, "error": "not found"}), 404
    return jsonify(scenario)


@app.route("/api/scenarios/<scenario_id>/ar-config")
def api_get_ar_config(scenario_id):
    scenario = next((x for x in SCENARIOS if x["id"] == scenario_id), None)
    if not scenario:
        return jsonify({"ok": False, "error": "not found"}), 404
    try:
        cfg = ar_module.get_scenario(RADAR_ROOT, scenario_id)
        return jsonify(cfg)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/scenarios/<scenario_id>/bind", methods=["POST"])
def api_bind_scenario(scenario_id):
    scenario = next((x for x in SCENARIOS if x["id"] == scenario_id), None)
    if not scenario:
        return jsonify({"ok": False, "error": "not found"}), 404
    if scenario["status"] == "demo":
        return jsonify({"ok": False, "error": "demo scenarios cannot be bound"}), 400
    body = request.get_json(force=True) or {}
    mitigations = body.get("mitigations", [])
    try:
        ar_module.bind_scenario(RADAR_ROOT, scenario_id, mitigations=mitigations)
        return jsonify({"ok": True, "bound": True, "id": scenario_id})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/scenarios/<scenario_id>/unbind", methods=["POST"])
def api_unbind_scenario(scenario_id):
    scenario = next((x for x in SCENARIOS if x["id"] == scenario_id), None)
    if not scenario:
        return jsonify({"ok": False, "error": "not found"}), 404
    try:
        ar_module.unbind_scenario(RADAR_ROOT, scenario_id)
        return jsonify({"ok": True, "bound": False, "id": scenario_id})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/scenarios/<scenario_id>/ar-config", methods=["PUT"])
def api_update_ar_config(scenario_id):
    scenario = next((x for x in SCENARIOS if x["id"] == scenario_id), None)
    if not scenario:
        return jsonify({"ok": False, "error": "not found"}), 404
    patch = request.get_json(force=True) or {}
    try:
        ar_module.update_scenario(RADAR_ROOT, scenario_id, patch)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── API: Connectors ──

@app.route("/api/connectors")
def api_get_connectors():
    try:
        env = conn_module.load_env(RADAR_ROOT)
        public = {k: v for k, v in env.items() if k not in conn_module.PASSWORD_KEYS.values()}
        status = conn_module.has_passwords(env)
        return jsonify({"env": public, "password_status": status})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/connectors/<name>", methods=["PUT"])
def api_save_connector(name):
    fields = request.get_json(force=True) or {}
    try:
        conn_module.save_connector(RADAR_ROOT, name, fields)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/connectors/reveal", methods=["POST"])
def api_reveal_connector_secret():
    body = request.get_json(force=True) or {}
    env_key = body.get("key", "")
    if not env_key:
        return jsonify({"ok": False, "error": "key is required"}), 400
    allowed = set(conn_module.PASSWORD_KEYS.values())
    if env_key not in allowed:
        return jsonify({"ok": False, "error": "key not allowed"}), 403
    value = conn_module.reveal_password(RADAR_ROOT, env_key)
    if value is None:
        return jsonify({"ok": False, "error": "not set"})
    return jsonify({"ok": True, "value": value})


@app.route("/api/connectors/<name>/test", methods=["POST"])
def api_test_connector(name):
    try:
        result = conn_module.test_connector(RADAR_ROOT, name)
        return jsonify(result)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── API: Infrastructure ──

@app.route("/api/infrastructure")
def api_infrastructure():
    try:
        return jsonify(inv_module.get_summary(RADAR_ROOT))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/infrastructure/managers")
def api_get_managers():
    try:
        return jsonify(inv_module.get_managers(RADAR_ROOT))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/infrastructure/managers/<name>")
def api_get_manager(name):
    try:
        mgr = next((m for m in inv_module.get_managers(RADAR_ROOT) if m["name"] == name), None)
        if not mgr:
            return jsonify({"ok": False, "error": "not found"}), 404
        return jsonify(mgr)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/infrastructure/agents")
def api_get_agents():
    try:
        return jsonify(inv_module.get_agents(RADAR_ROOT))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/infrastructure/agents/<name>")
def api_get_agent(name):
    try:
        agent = next((a for a in inv_module.get_agents(RADAR_ROOT) if a["name"] == name), None)
        if not agent:
            return jsonify({"ok": False, "error": "not found"}), 404
        return jsonify(agent)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── API: Vault ──

@app.route("/api/vault/status")
def api_vault_status():
    sid = _get_vault_sid(create=False)
    unlocked = bool(sid and vault_module.has_password(sid))
    vault_exists = _has_encrypted_files()
    return jsonify({
        "unlocked": unlocked,
        "any_encrypted": vault_exists,
        "vault_exists": vault_exists,
        "session_has_password": unlocked,
    })


@app.route("/api/vault/unlock", methods=["POST"])
def api_vault_unlock():
    body = request.get_json(force=True) or {}
    pw = body.get("password", "")
    if not pw:
        return jsonify({"ok": False, "error": "password is required"}), 400
    sid = _get_vault_sid(create=True)
    vault_module.set_password(sid, pw)
    hv = Path(RADAR_ROOT) / "host_vars"
    if hv.exists():
        for enc in hv.glob("*.yml"):
            if enc.read_text(errors="ignore")[:32].startswith("$ANSIBLE_VAULT"):
                if not vault_module.verify_password(sid, enc):
                    vault_module.clear_password(sid)
                    return jsonify({"ok": False, "error": f"password does not decrypt {enc.name}"}), 400
                break
    return _attach_vault_cookie(make_response(jsonify({"ok": True})))


@app.route("/api/vault/create", methods=["POST"])
def api_vault_create():
    body = request.get_json(force=True) or {}
    pw = body.get("password", "")
    if not pw:
        return jsonify({"ok": False, "error": "password is required"}), 400
    if _has_encrypted_files():
        return jsonify({"ok": False, "error": "encrypted files already exist — use Unlock instead"}), 400
    hv = Path(RADAR_ROOT) / "host_vars"
    hv.mkdir(parents=True, exist_ok=True)
    sid = _get_vault_sid(create=True)
    vault_module.set_password(sid, pw)
    return _attach_vault_cookie(make_response(jsonify({"ok": True})))


@app.route("/api/vault/lock", methods=["POST"])
def api_vault_lock():
    sid = _get_vault_sid(create=False)
    if sid:
        vault_module.clear_password(sid)
    return jsonify({"ok": True})


# ── API: SSH ──

@app.route("/api/ssh/status")
def api_ssh_status():
    sid = _get_vault_sid(create=False)
    return jsonify({"set": bool(sid and vault_module.has_ssh_passphrase(sid))})


@app.route("/api/ssh/set", methods=["POST"])
def api_ssh_set():
    body = request.get_json(force=True) or {}
    passphrase = body.get("passphrase")
    if passphrase is None:
        return jsonify({"ok": False, "error": "passphrase is required"}), 400
    sid = _get_vault_sid(create=True)
    vault_module.set_ssh_passphrase(sid, passphrase)
    return _attach_vault_cookie(make_response(jsonify({"ok": True})))


@app.route("/api/ssh/clear", methods=["POST"])
def api_ssh_clear():
    sid = _get_vault_sid(create=False)
    if sid:
        vault_module.clear_ssh_passphrase(sid)
    return jsonify({"ok": True})


# ── API: Infrastructure managers ──

@app.route("/api/infrastructure/managers", methods=["POST"])
def api_add_manager():
    spec = request.get_json(force=True) or {}
    if not spec.get("name"):
        return jsonify({"ok": False, "error": "name is required"}), 400
    if not (spec.get("manager_mode") or spec.get("ui_kind")):
        return jsonify({"ok": False, "error": "manager kind is required"}), 400
    resolved = inv_module._resolve_manager_mode(spec)
    if resolved != "docker_local" and not spec.get("ip"):
        return jsonify({"ok": False, "error": "ip is required for remote managers"}), 400
    sid = _get_vault_sid(create=False)
    if spec.get("become_password") and not (sid and vault_module.has_password(sid)):
        return _vault_error()
    try:
        inv_module.add_manager(RADAR_ROOT, spec)
        if spec.get("become_password"):
            inv_module.save_credential(RADAR_ROOT, spec["name"], spec["become_password"], sid)
        return jsonify({"ok": True})
    except vault_module.VaultPasswordMissing:
        return _vault_error()
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/infrastructure/managers/<name>", methods=["PUT"])
def api_update_manager(name):
    spec = request.get_json(force=True) or {}
    spec["name"] = name
    if not (spec.get("manager_mode") or spec.get("ui_kind")):
        return jsonify({"ok": False, "error": "manager kind is required"}), 400
    resolved = inv_module._resolve_manager_mode(spec)
    if resolved != "docker_local" and not spec.get("ip"):
        return jsonify({"ok": False, "error": "ip is required for remote managers"}), 400
    sid = _get_vault_sid(create=False)
    if spec.get("become_password") and not (sid and vault_module.has_password(sid)):
        return _vault_error()
    try:
        inv_module.update_manager(RADAR_ROOT, name, spec)
        if spec.get("become_password"):
            inv_module.save_credential(RADAR_ROOT, name, spec["become_password"], sid)
        return jsonify({"ok": True})
    except vault_module.VaultPasswordMissing:
        return _vault_error()
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/infrastructure/managers/<name>", methods=["DELETE"])
def api_delete_manager(name):
    try:
        inv_module.delete_manager(RADAR_ROOT, name)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/infrastructure/managers/<name>/credential", methods=["POST"])
def api_save_manager_credential(name):
    body = request.get_json(force=True) or {}
    pw = body.get("become_password", "")
    if not pw:
        return jsonify({"ok": False, "error": "become_password is required"}), 400
    sid = _get_vault_sid(create=False)
    if not (sid and vault_module.has_password(sid)):
        return _vault_error()
    try:
        inv_module.save_credential(RADAR_ROOT, name, pw, sid)
        return jsonify({"ok": True})
    except vault_module.VaultPasswordMissing:
        return _vault_error()
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/infrastructure/managers/<name>/credential", methods=["DELETE"])
def api_delete_manager_credential(name):
    try:
        inv_module.delete_credential(RADAR_ROOT, name)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── API: Infrastructure agents ──

@app.route("/api/infrastructure/agents", methods=["POST"])
def api_add_agent():
    spec = request.get_json(force=True) or {}
    if not spec.get("name"):
        return jsonify({"ok": False, "error": "name is required"}), 400
    if not spec.get("agent_mode"):
        return jsonify({"ok": False, "error": "agent_mode is required"}), 400
    if spec["agent_mode"] == "ssh" and not spec.get("ip"):
        return jsonify({"ok": False, "error": "ip is required for SSH agents"}), 400
    sid = _get_vault_sid(create=False)
    if spec.get("become_password") and not (sid and vault_module.has_password(sid)):
        return _vault_error()
    try:
        inv_module.add_agent(RADAR_ROOT, spec)
        if spec.get("become_password"):
            inv_module.save_credential(RADAR_ROOT, spec["name"], spec["become_password"], sid)
        return jsonify({"ok": True})
    except vault_module.VaultPasswordMissing:
        return _vault_error()
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/infrastructure/agents/<name>", methods=["PUT"])
def api_update_agent(name):
    spec = request.get_json(force=True) or {}
    spec["name"] = name
    if not spec.get("agent_mode"):
        return jsonify({"ok": False, "error": "agent_mode is required"}), 400
    if spec["agent_mode"] == "ssh" and not spec.get("ip"):
        return jsonify({"ok": False, "error": "ip is required for SSH agents"}), 400
    sid = _get_vault_sid(create=False)
    if spec.get("become_password") and not (sid and vault_module.has_password(sid)):
        return _vault_error()
    try:
        inv_module.update_agent(RADAR_ROOT, name, spec)
        if spec.get("become_password"):
            inv_module.save_credential(RADAR_ROOT, name, spec["become_password"], sid)
        return jsonify({"ok": True})
    except vault_module.VaultPasswordMissing:
        return _vault_error()
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/infrastructure/agents/<name>", methods=["DELETE"])
def api_delete_agent(name):
    try:
        inv_module.delete_agent(RADAR_ROOT, name)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/infrastructure/agents/<name>/credential", methods=["POST"])
def api_save_agent_credential(name):
    body = request.get_json(force=True) or {}
    pw = body.get("become_password", "")
    if not pw:
        return jsonify({"ok": False, "error": "become_password is required"}), 400
    sid = _get_vault_sid(create=False)
    if not (sid and vault_module.has_password(sid)):
        return _vault_error()
    try:
        inv_module.save_credential(RADAR_ROOT, name, pw, sid)
        return jsonify({"ok": True})
    except vault_module.VaultPasswordMissing:
        return _vault_error()
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/infrastructure/agents/<name>/credential", methods=["DELETE"])
def api_delete_agent_credential(name):
    try:
        inv_module.delete_credential(RADAR_ROOT, name)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── API: Health ──

@app.route("/api/infrastructure/health/manager/<name>", methods=["POST"])
def api_health_manager(name):
    body = request.get_json(force=True) or {}
    try:
        mgr = next((m for m in inv_module.get_managers(RADAR_ROOT) if m["name"] == name), None)
        if not mgr:
            return jsonify({"error": "not found"}), 404
        sid = _get_vault_sid(create=False)
        if _needs_vault(mgr) and not (sid and vault_module.has_password(sid)):
            return _vault_error()
        if _needs_ssh(mgr) and not (sid and vault_module.has_ssh_passphrase(sid)):
            return _ssh_error()
        result = health_module.check_manager(
            radar_root=RADAR_ROOT, manager=mgr,
            bound_scenarios=_bound_scenario_ids(),
            ssh_key_path=body.get("ssh_key_path"),
            vault_session_id=sid, ssh_session_id=sid,
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/infrastructure/health/agent/<name>", methods=["POST"])
def api_health_agent(name):
    body = request.get_json(force=True) or {}
    try:
        agent = next((a for a in inv_module.get_agents(RADAR_ROOT) if a["name"] == name), None)
        if not agent:
            return jsonify({"error": "not found"}), 404
        sid = _get_vault_sid(create=False)
        if _needs_vault(agent) and not (sid and vault_module.has_password(sid)):
            return _vault_error()
        if _needs_ssh(agent) and not (sid and vault_module.has_ssh_passphrase(sid)):
            return _ssh_error()
        result = health_module.check_agent(
            radar_root=RADAR_ROOT, agent=agent,
            ssh_key_path=body.get("ssh_key_path"),
            vault_session_id=sid, ssh_session_id=sid,
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/infrastructure/health", methods=["POST"])
def api_health_all():
    sid = _get_vault_sid(create=False)
    results = []
    for mgr in inv_module.get_managers(RADAR_ROOT):
        if _needs_vault(mgr) and not (sid and vault_module.has_password(sid)):
            return _vault_error()
        try:
            r = health_module.check_manager(
                radar_root=RADAR_ROOT, manager=mgr,
                bound_scenarios=_bound_scenario_ids(),
                ssh_key_path=None, vault_session_id=sid,
            )
        except Exception as e:
            r = {"name": mgr["name"], "type": "manager",
                 "checks": [{"status": "fail", "detail": str(e)}],
                 "ok": 0, "warn": 0, "fail": 1, "overall": "fail"}
        results.append(r)
    for agent in inv_module.get_agents(RADAR_ROOT):
        if _needs_vault(agent) and not (sid and vault_module.has_password(sid)):
            return _vault_error()
        try:
            r = health_module.check_agent(
                radar_root=RADAR_ROOT, agent=agent,
                ssh_key_path=None, vault_session_id=sid,
            )
        except Exception as e:
            r = {"name": agent["name"], "type": "agent",
                 "checks": [{"status": "fail", "detail": str(e)}],
                 "ok": 0, "warn": 0, "fail": 1, "overall": "fail"}
        results.append(r)
    return jsonify(results)


# ── API: Deploy ──

def _deploy_needs_ssh(spec):
    if spec.get("action") == "run":
        return False
    return spec.get("manager_mode") == "remote" or spec.get("agent_mode") == "remote"


@app.route("/api/deploy/build", methods=["POST"])
def api_deploy_build():
    spec = request.get_json(force=True) or {}
    spec["action"] = "build"
    sid = _get_vault_sid(create=False)
    if _deploy_needs_vault(spec) and not (sid and vault_module.has_password(sid)):
        return _vault_error()
    if _deploy_needs_ssh(spec) and not (sid and vault_module.has_ssh_passphrase(sid)):
        return _ssh_error()
    def generate():
        try:
            for chunk in deploy_module.stream_build(RADAR_ROOT, spec, vault_session_id=sid):
                yield chunk
        except Exception as e:
            yield f"[ERROR] {e}\n"
    return Response(stream_with_context(generate()), mimetype="text/plain")


@app.route("/api/deploy/run", methods=["POST"])
def api_deploy_run():
    spec = request.get_json(force=True) or {}
    spec["action"] = "run"
    def generate():
        try:
            for chunk in deploy_module.stream_run(RADAR_ROOT, spec):
                yield chunk
        except Exception as e:
            yield f"[ERROR] {e}\n"
    return Response(stream_with_context(generate()), mimetype="text/plain")


@app.route("/api/deploy/health", methods=["POST"])
def api_deploy_health():
    spec = request.get_json(force=True) or {}
    spec["action"] = "health"
    sid = _get_vault_sid(create=False)
    if _deploy_needs_vault(spec) and not (sid and vault_module.has_password(sid)):
        return _vault_error()
    if _deploy_needs_ssh(spec) and not (sid and vault_module.has_ssh_passphrase(sid)):
        return _ssh_error()
    def generate():
        try:
            for chunk in deploy_module.stream_health(RADAR_ROOT, spec, vault_session_id=sid):
                yield chunk
        except Exception as e:
            yield f"[ERROR] {e}\n"
    return Response(stream_with_context(generate()), mimetype="text/plain")


@app.route("/api/deploy/preview", methods=["POST"])
def api_deploy_preview():
    spec = request.get_json(force=True) or {}
    try:
        return jsonify(deploy_module.preview(RADAR_ROOT, spec))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/deploy/status", methods=["GET"])
def api_deploy_status():
    sid = _get_vault_sid(create=False)
    try:
        summary = inv_module.get_summary(RADAR_ROOT)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    bound = _bound_scenario_ids()
    agents = summary.get("agents", [])
    managers = summary.get("managers", [])
    ssh_key = request.args.get("ssh_key") or None
    results = []
    for mgr in managers:
        needs_ssh = mgr.get("connection") == "remote"
        if needs_ssh and not (sid and vault_module.has_ssh_passphrase(sid)):
            results.append({"name": mgr["name"], "type": "manager", "overall": "unknown",
                            "checks": [{"status": "warn", "detail": "SSH passphrase not set — set it in the header to run checks"}]})
            continue
        try:
            r = health_module.check_manager(
                RADAR_ROOT, mgr, bound,
                ssh_key_path=ssh_key,
                vault_session_id=sid,
                ssh_session_id=sid,
            )
        except Exception as e:
            r = {"name": mgr["name"], "type": "manager", "overall": "fail",
                 "checks": [{"status": "fail", "detail": f"FAIL - {e}"}], "ok": 0, "warn": 0, "fail": 1}
        results.append(r)
    for agent in agents:
        needs_ssh = agent.get("agent_mode") == "ssh"
        if needs_ssh and not (sid and vault_module.has_ssh_passphrase(sid)):
            results.append({"name": agent["name"], "type": "agent", "overall": "unknown",
                            "checks": [{"status": "warn", "detail": "SSH passphrase not set — set it in the header to run checks"}]})
            continue
        try:
            r = health_module.check_agent(
                RADAR_ROOT, agent,
                ssh_key_path=ssh_key,
                vault_session_id=sid,
                ssh_session_id=sid,
            )
        except Exception as e:
            r = {"name": agent["name"], "type": "agent", "overall": "fail",
                 "checks": [{"status": "fail", "detail": f"FAIL - {e}"}], "ok": 0, "warn": 0, "fail": 1}
        results.append(r)
    return jsonify({"ok": True, "results": results, "bound_scenarios": bound})


@app.after_request
def _ensure_cookie(resp):
    return _attach_vault_cookie(resp)


if __name__ == "__main__":
    app.run(debug=True, port=5000, threaded=True)