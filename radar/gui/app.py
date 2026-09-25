import hmac
import os
import re
import secrets
import sys
import subprocess
from urllib.parse import urlsplit
from flask import Flask, render_template, jsonify, request, Response, stream_with_context, g, make_response, redirect
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))  # repo root, so `import wazuh_api` resolves

from orchestrator import ar_config as ar_module
from orchestrator import deploy as deploy_module
from orchestrator import vault as vault_module
from orchestrator import connectors as conn_module
from wazuh_api import config as config_module
from wazuh_api import infra as infra_module

app = Flask(__name__)

GUI_HOST = os.environ.get("RADAR_GUI_HOST", "127.0.0.1").strip() or "127.0.0.1"
GUI_PORT = int(os.environ.get("RADAR_GUI_PORT", "5000"))
GUI_DEBUG = os.environ.get("RADAR_GUI_DEBUG", "").strip() == "1"

GUI_TOKEN = os.environ.get("RADAR_GUI_TOKEN", "").strip() or secrets.token_urlsafe(32)
GUI_AUTH_ENABLED = os.environ.get("RADAR_GUI_AUTH", "").strip().lower() not in ("off", "0", "false", "no")
AUTH_COOKIE = "radar_gui_auth"
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _allowed_hosts() -> set:
    hosts = {f"127.0.0.1:{GUI_PORT}", f"localhost:{GUI_PORT}", f"[::1]:{GUI_PORT}"}
    if GUI_HOST not in ("0.0.0.0", "::", "127.0.0.1", "localhost", "::1"):
        hosts.add(f"{GUI_HOST}:{GUI_PORT}".lower())
    for h in os.environ.get("RADAR_GUI_ALLOWED_HOSTS", "").split(","):
        h = h.strip().lower()
        if h:
            hosts.add(h)
    return hosts


def _refuse(status: int, message: str):
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": message}), status
    return Response(message + "\n", status=status, mimetype="text/plain")


@app.before_request
def _check_host():
    host = (request.host or "").lower()
    if host not in _allowed_hosts():
        return _refuse(403, f"Host '{host}' is not allowed. Add it to RADAR_GUI_ALLOWED_HOSTS "
                            "if this is how operators reach the GUI.")


@app.before_request
def _check_login_token():
    if not GUI_AUTH_ENABLED:
        return None
    supplied = request.args.get("token")
    if supplied is not None:
        if request.method == "GET" and hmac.compare_digest(supplied, GUI_TOKEN):
            resp = redirect(request.path)
            resp.set_cookie(AUTH_COOKIE, GUI_TOKEN, httponly=True, samesite="Strict",
                            secure=request.is_secure)
            return resp
        return _refuse(401, "Invalid login token.")
    cookie = request.cookies.get(AUTH_COOKIE, "")
    if cookie and hmac.compare_digest(cookie, GUI_TOKEN):
        return None
    return _refuse(401, "Not logged in. Open the login URL printed in the RADAR GUI console "
                        "(http://127.0.0.1:<port>/?token=...).")


@app.before_request
def _check_csrf():
    if request.method not in STATE_CHANGING_METHODS:
        return None
    if request.mimetype != "application/json":
        return _refuse(415, "State-changing requests must use Content-Type: application/json.")
    if request.headers.get("Sec-Fetch-Site", "").lower() in ("cross-site", "same-site"):
        return _refuse(403, "Cross-site request refused.")
    origin = request.headers.get("Origin")
    if origin:
        netloc = urlsplit(origin).netloc.lower()
        if origin == "null" or netloc not in _allowed_hosts():
            return _refuse(403, "Cross-origin request refused.")
    return None


RADAR_ROOT = str(Path(os.environ.get("RADAR_ROOT", Path(__file__).parent.parent)).resolve())
VAULT_COOKIE = "radar_vault_sid"
DEFAULT_SCENARIO_ID = "default"

_RULE_ID_RE = re.compile(r'\bid="(\d+)"')


def _scenario_rule_ids(scenario_id: str) -> list[int]:
    rules_dir = Path(RADAR_ROOT) / "scenarios" / "rules" / scenario_id
    ids = set()
    if rules_dir.is_dir():
        for f in rules_dir.glob("*.xml"):
            ids.update(int(m) for m in _RULE_ID_RE.findall(f.read_text()))
    return sorted(ids)


def _scenario_type(ar_cfg: dict) -> tuple[str, str]:
    w_ad = ar_cfg.get("w_ad", 0.0)
    w_sig = ar_cfg.get("w_sig", 0.0)
    if w_ad > 0 and w_sig > 0:
        return "hybrid", "Hybrid"
    if w_sig > 0:
        return "signature", "Signature"
    if w_ad > 0:
        return "anomaly", "Anomaly ML"
    return "unknown", "Unknown"


def _build_scenarios() -> list[dict]:
    result = []
    for scenario_id in config_module.gui_visible_scenarios(RADAR_ROOT):
        info = config_module.scenario_display_info(RADAR_ROOT, scenario_id)
        try:
            ar_cfg = ar_module.get_scenario(RADAR_ROOT, scenario_id)
        except Exception:
            ar_cfg = {}
        scenario_type, type_label = _scenario_type(ar_cfg)
        result.append({
            "id": scenario_id,
            "name": info["display_name"],
            "description": info["description"],
            "status": info["status"],
            "type": scenario_type,
            "type_label": type_label,
            "rule_ids": _scenario_rule_ids(scenario_id),
        })
    return result


def _default_scenario_entry() -> dict:
    try:
        ar_cfg = ar_module.get_scenario(RADAR_ROOT, DEFAULT_SCENARIO_ID)
    except Exception:
        ar_cfg = {}
    scenario_type, type_label = _scenario_type(ar_cfg)
    return {
        "id": DEFAULT_SCENARIO_ID,
        "name": "Default (baseline)",
        "description": "Baseline PowerShell / Command Shell detection, applied fleet-wide. "
                        "Inherited as defaults by every other scenario.",
        "status": "active",
        "type": scenario_type,
        "type_label": type_label,
        "rule_ids": _scenario_rule_ids(DEFAULT_SCENARIO_ID),
        "bound": True,
        "shared": False,
        "ar_config": ar_cfg,
    }


def _enriched_scenarios():
    try:
        bound_ids = set(ar_module.list_bound_scenarios(RADAR_ROOT))
    except Exception:
        bound_ids = set()
    shared_ids = config_module.shared_scenarios(RADAR_ROOT)
    result = []
    for s in _build_scenarios():
        entry = {**s, "bound": s["id"] in bound_ids, "shared": s["id"] in shared_ids}
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
    # Despite the name (kept for compatibility with the cookie already set in
    # people's browsers), this cookie only ever gates the sudo-password vault
    # now -- see orchestrator/vault.py.
    sid = request.cookies.get(VAULT_COOKIE)
    if not sid and create:
        sid = vault_module.new_session_id()
        g._new_vault_sid = sid
    return sid


def _attach_vault_cookie(resp):
    sid = getattr(g, "_new_vault_sid", None)
    if sid:
        resp.set_cookie(VAULT_COOKIE, sid, httponly=True, samesite="Strict", secure=request.is_secure)
    return resp


def _sudo_error():
    return jsonify({"ok": False, "error": "sudo password required", "need_sudo": True}), 403


# ── Pages ──

@app.route("/")
@app.route("/active-responses")
@app.route("/active-responses/<scenario_id>")
def active_responses(scenario_id=None):
    bound_list = [_default_scenario_entry()]
    bound_list += [s for s in _enriched_scenarios() if s["bound"] and s["status"] == "active"]
    known_mitigations = ar_module.list_known_mitigations(RADAR_ROOT)
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
                           known_mitigations=known_mitigations)


@app.route("/connectors")
def connectors():
    try:
        env = conn_module.load_env(RADAR_ROOT)
    except Exception:
        env = {}
    connector_status = conn_module.has_passwords(env)
    return render_template("connectors.html", env=conn_module.public_env(env), connector_status=connector_status)


@app.route("/infrastructure")
def infrastructure():
    dashboard = infra_module.get_component(RADAR_ROOT, "dashboard")
    manager_nodes = infra_module.list_nodes(RADAR_ROOT, "manager")
    indexer_nodes = infra_module.list_nodes(RADAR_ROOT, "indexer")
    return render_template("infrastructure.html", dashboard=dashboard,
                           manager_nodes=manager_nodes, indexer_nodes=indexer_nodes)


@app.route("/api/infra/detect-ip")
def api_detect_ip():
    try:
        result = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=5)
        ips = [ip for ip in (result.stdout or "").split() if ip and not ip.startswith("127.")]
        return jsonify({"ok": True, "ips": ips})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


def _resync_ar_env_best_effort():
    try:
        conn_module._sync_active_responses_env(RADAR_ROOT)
    except Exception:
        pass


def _component_body():
    body = request.get_json(silent=True) or {}
    container_name = (body.get("container_name") or "").strip()
    host = (body.get("host") or "").strip()
    port = body.get("port")
    scheme = body.get("scheme") or "https"
    if not container_name:
        raise ValueError("container_name is required")
    return {"container_name": container_name, "host": host, "port": port, "scheme": scheme}


@app.route("/api/infra/dashboard")
def api_get_dashboard():
    return jsonify({"ok": True, "component": infra_module.get_component(RADAR_ROOT, "dashboard")})


@app.route("/api/infra/dashboard", methods=["PUT"])
def api_save_dashboard():
    try:
        cfg = _component_body()
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    try:
        infra_module.upsert_component(RADAR_ROOT, "dashboard", cfg)
        return jsonify({"ok": True})
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/infra/dashboard", methods=["DELETE"])
def api_delete_dashboard():
    infra_module.delete_component(RADAR_ROOT, "dashboard")
    return jsonify({"ok": True})


# ── API: Infrastructure -- indexer/manager nodes (each can be a cluster) ──

@app.route("/api/infra/nodes/<role>")
def api_list_nodes(role):
    if role not in infra_module.MULTI_COMPONENTS:
        return jsonify({"ok": False, "error": f"Unknown role '{role}'"}), 400
    return jsonify({"ok": True, "nodes": infra_module.list_nodes(RADAR_ROOT, role)})


def _vault_locked_for(role: str) -> bool:
    if role != "indexer":
        return False
    sid = _get_vault_sid(create=False)
    return not (sid and vault_module.has_sudo_password(sid))


def _node_body():
    cfg = _component_body()
    cfg["primary"] = bool((request.get_json(silent=True) or {}).get("primary", False))
    return cfg


@app.route("/api/infra/nodes/<role>", methods=["POST"])
def api_add_node(role):
    if role not in infra_module.MULTI_COMPONENTS:
        return jsonify({"ok": False, "error": f"Unknown role '{role}'"}), 400
    if _vault_locked_for(role):
        return _sudo_error()
    try:
        cfg = _node_body()
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    try:
        node = infra_module.upsert_node(RADAR_ROOT, role, cfg)
        _resync_ar_env_best_effort()
        return jsonify({"ok": True, "node": node})
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/infra/nodes/<role>/<node_id>", methods=["PUT"])
def api_edit_node(role, node_id):
    if role not in infra_module.MULTI_COMPONENTS:
        return jsonify({"ok": False, "error": f"Unknown role '{role}'"}), 400
    if _vault_locked_for(role):
        return _sudo_error()
    try:
        cfg = _node_body()
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    try:
        node = infra_module.upsert_node(RADAR_ROOT, role, cfg, node_id=node_id)
        _resync_ar_env_best_effort()
        return jsonify({"ok": True, "node": node})
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/infra/nodes/<role>/<node_id>", methods=["DELETE"])
def api_delete_node(role, node_id):
    if _vault_locked_for(role):
        return _sudo_error()
    try:
        infra_module.delete_node(RADAR_ROOT, role, node_id)
        _resync_ar_env_best_effort()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/infra/nodes/<role>/<node_id>/set-primary", methods=["POST"])
def api_set_primary_node(role, node_id):
    if _vault_locked_for(role):
        return _sudo_error()
    try:
        infra_module.set_primary_node(RADAR_ROOT, role, node_id)
        _resync_ar_env_best_effort()
        return jsonify({"ok": True})
    except KeyError as e:
        return jsonify({"ok": False, "error": str(e)}), 404
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/infra/test-link", methods=["POST"])
def api_test_infra_link():
    body = request.get_json(silent=True) or {}
    from_c, to_c = body.get("from"), body.get("to")
    if not from_c or not to_c:
        return jsonify({"ok": False, "error": "'from' and 'to' are required"}), 400
    return jsonify(infra_module.test_reachable(RADAR_ROOT, from_c, to_c))


@app.route("/deploy")
def deploy():
    return render_template("deploy.html",
                           scenarios=[s for s in _enriched_scenarios() if s["status"] == "active"],
                           bound_scenarios=_bound_scenario_ids())


# ── API: Scenarios ──

@app.route("/api/scenarios")
def api_scenarios():
    return jsonify(_enriched_scenarios())


@app.route("/api/scenarios/<scenario_id>")
def api_get_scenario(scenario_id):
    if scenario_id == DEFAULT_SCENARIO_ID:
        return jsonify(_default_scenario_entry())
    scenario = next((x for x in _enriched_scenarios() if x["id"] == scenario_id), None)
    if not scenario:
        return jsonify({"ok": False, "error": "not found"}), 404
    return jsonify(scenario)


@app.route("/api/scenarios/<scenario_id>/ar-config")
def api_get_ar_config(scenario_id):
    if scenario_id != DEFAULT_SCENARIO_ID and not any(x["id"] == scenario_id for x in _build_scenarios()):
        return jsonify({"ok": False, "error": "not found"}), 404
    try:
        cfg = ar_module.get_scenario(RADAR_ROOT, scenario_id)
        return jsonify(cfg)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/scenarios/<scenario_id>/bind", methods=["POST"])
def api_bind_scenario(scenario_id):
    if scenario_id == DEFAULT_SCENARIO_ID:
        return jsonify({"ok": False, "error": "the default scenario is always on and cannot be bound/unbound"}), 400
    scenario = next((x for x in _build_scenarios() if x["id"] == scenario_id), None)
    if not scenario:
        return jsonify({"ok": False, "error": "not found"}), 404
    if scenario["status"] == "demo":
        return jsonify({"ok": False, "error": "demo scenarios cannot be bound"}), 400
    body = request.get_json(silent=True) or {}
    mitigations = body.get("mitigations", [])
    try:
        ar_module.bind_scenario(RADAR_ROOT, scenario_id, mitigations=mitigations)
        return jsonify({"ok": True, "bound": True, "id": scenario_id})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/scenarios/<scenario_id>/unbind", methods=["POST"])
def api_unbind_scenario(scenario_id):
    if scenario_id == DEFAULT_SCENARIO_ID:
        return jsonify({"ok": False, "error": "the default scenario is always on and cannot be bound/unbound"}), 400
    scenario = next((x for x in _build_scenarios() if x["id"] == scenario_id), None)
    if not scenario:
        return jsonify({"ok": False, "error": "not found"}), 404
    try:
        ar_module.unbind_scenario(RADAR_ROOT, scenario_id)
        return jsonify({"ok": True, "bound": False, "id": scenario_id})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/scenarios/<scenario_id>/ar-config", methods=["PUT"])
def api_update_ar_config(scenario_id):
    if scenario_id != DEFAULT_SCENARIO_ID and not any(x["id"] == scenario_id for x in _build_scenarios()):
        return jsonify({"ok": False, "error": "not found"}), 404
    patch = request.get_json(silent=True) or {}
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
        status = conn_module.has_passwords(env)
        return jsonify({"env": conn_module.public_env(env), "password_status": status})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/connectors/<name>", methods=["PUT"])
def api_save_connector(name):
    fields = request.get_json(silent=True) or {}
    if not isinstance(fields, dict):
        return jsonify({"ok": False, "error": "expected a JSON object"}), 400
    sid = _get_vault_sid(create=False)
    try:
        result = conn_module.save_connector(RADAR_ROOT, name, fields,
                                            vault_unlocked=bool(sid and vault_module.has_sudo_password(sid)))
        response = {"ok": True}
        if not result.get("synced", True):
            response["warning"] = (
                "Saved, but could not apply to the running manager: "
                f"{result.get('sync_error')}"
            )
        return jsonify(response)
    except conn_module.VaultRequired:
        return _sudo_error()
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/connectors/reveal", methods=["POST"])
def api_reveal_connector_secret():
    body = request.get_json(silent=True) or {}
    env_key = body.get("key", "")
    if not env_key:
        return jsonify({"ok": False, "error": "key is required"}), 400
    allowed = set(conn_module.PASSWORD_KEYS.values())
    if env_key not in allowed:
        return jsonify({"ok": False, "error": "key not allowed"}), 403
    sid = _get_vault_sid(create=False)
    if not (sid and vault_module.has_sudo_password(sid)):
        return _sudo_error()
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


# ── API: sudo (local docker compose privilege escalation) ──

@app.route("/api/sudo/status")
def api_sudo_status():
    sid = _get_vault_sid(create=False)
    return jsonify({"unlocked": bool(sid and vault_module.has_sudo_password(sid))})


@app.route("/api/sudo/unlock", methods=["POST"])
def api_sudo_unlock():
    body = request.get_json(silent=True) or {}
    pw = body.get("password", "")
    if not pw:
        return jsonify({"ok": False, "error": "password is required"}), 400
    ok, why = vault_module.verify_sudo_password(pw)
    if not ok:
        return jsonify({"ok": False, "error": why}), 403
    sid = _get_vault_sid(create=True)
    vault_module.set_sudo_password(sid, pw)
    return _attach_vault_cookie(make_response(jsonify({"ok": True})))


@app.route("/api/sudo/lock", methods=["POST"])
def api_sudo_lock():
    sid = _get_vault_sid(create=False)
    if sid:
        vault_module.clear_sudo_password(sid)
    return jsonify({"ok": True})


# ── API: Deploy ──


@app.route("/api/deploy/build", methods=["POST"])
def api_deploy_build():
    spec = request.get_json(silent=True) or {}
    spec["action"] = "build"
    sid = _get_vault_sid(create=False)

    # Sudo is required unconditionally: even when the manager stack is
    # already running (skipping the docker compose up step), stream_build()
    # still needs it later for manager-apply-scenario.sh.
    if not (sid and vault_module.has_sudo_password(sid)):
        return _sudo_error()

    def generate():
        try:
            for chunk in deploy_module.stream_build(RADAR_ROOT, spec, vault_session_id=sid):
                yield chunk
        except Exception as e:
            yield f"[ERROR] {e}\n"
    return Response(stream_with_context(generate()), mimetype="text/plain")


@app.route("/api/deploy/undo-scenario", methods=["POST"])
def api_deploy_undo_scenario():
    spec = request.get_json(silent=True) or {}
    def generate():
        try:
            for chunk in deploy_module.stream_undo_scenario(RADAR_ROOT, spec):
                yield chunk
        except Exception as e:
            yield f"[ERROR] {e}\n"
    return Response(stream_with_context(generate()), mimetype="text/plain")


@app.route("/api/deploy/teardown", methods=["POST"])
def api_deploy_teardown():
    spec = request.get_json(silent=True) or {}
    sid = _get_vault_sid(create=False)

    if not (sid and vault_module.has_sudo_password(sid)):
        return _sudo_error()

    def generate():
        try:
            for chunk in deploy_module.stream_teardown(RADAR_ROOT, spec, vault_session_id=sid):
                yield chunk
        except Exception as e:
            yield f"[ERROR] {e}\n"
    return Response(stream_with_context(generate()), mimetype="text/plain")


@app.route("/api/deploy/run", methods=["POST"])
def api_deploy_run():
    spec = request.get_json(silent=True) or {}
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
    spec = request.get_json(silent=True) or {}
    spec["action"] = "health"
    def generate():
        try:
            for chunk in deploy_module.stream_health(RADAR_ROOT, spec):
                yield chunk
        except Exception as e:
            yield f"[ERROR] {e}\n"
    return Response(stream_with_context(generate()), mimetype="text/plain")


@app.route("/api/deploy/mint-token", methods=["POST"])
def api_deploy_mint_token():
    spec = request.get_json(silent=True) or {}
    sid = _get_vault_sid(create=False)

    if not (sid and vault_module.has_sudo_password(sid)):
        return _sudo_error()

    def generate():
        try:
            for chunk in deploy_module.stream_mint_token(RADAR_ROOT, spec, vault_session_id=sid):
                yield chunk
        except Exception as e:
            yield f"[ERROR] {e}\n"
    return Response(stream_with_context(generate()), mimetype="text/plain")


@app.route("/api/deploy/assign-agent-group", methods=["POST"])
def api_deploy_assign_agent_group():
    spec = request.get_json(silent=True) or {}
    def generate():
        try:
            for chunk in deploy_module.stream_assign_agent_group(RADAR_ROOT, spec):
                yield chunk
        except Exception as e:
            yield f"[ERROR] {e}\n"
    return Response(stream_with_context(generate()), mimetype="text/plain")


@app.route("/api/deploy/unassign-agent-group", methods=["POST"])
def api_deploy_unassign_agent_group():
    spec = request.get_json(silent=True) or {}
    def generate():
        try:
            for chunk in deploy_module.stream_unassign_agent_group(RADAR_ROOT, spec):
                yield chunk
        except Exception as e:
            yield f"[ERROR] {e}\n"
    return Response(stream_with_context(generate()), mimetype="text/plain")


@app.route("/api/deploy/deregister-agent", methods=["POST"])
def api_deploy_deregister_agent():
    spec = request.get_json(silent=True) or {}
    def generate():
        try:
            for chunk in deploy_module.stream_deregister_agent(RADAR_ROOT, spec):
                yield chunk
        except Exception as e:
            yield f"[ERROR] {e}\n"
    return Response(stream_with_context(generate()), mimetype="text/plain")


@app.route("/api/deploy/enrollment-window", methods=["POST"])
def api_deploy_enrollment_window():
    spec = request.get_json(silent=True) or {}
    sid = _get_vault_sid(create=False)

    if not (sid and vault_module.has_sudo_password(sid)):
        return _sudo_error()

    def generate():
        try:
            for chunk in deploy_module.stream_enrollment_window(RADAR_ROOT, spec, vault_session_id=sid):
                yield chunk
        except Exception as e:
            yield f"[ERROR] {e}\n"
    return Response(stream_with_context(generate()), mimetype="text/plain")


@app.route("/api/deploy/preview", methods=["POST"])
def api_deploy_preview():
    spec = request.get_json(silent=True) or {}
    try:
        return jsonify(deploy_module.preview(RADAR_ROOT, spec))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.after_request
def _ensure_cookie(resp):
    return _attach_vault_cookie(resp)


if __name__ == "__main__":
    if GUI_HOST not in ("127.0.0.1", "localhost", "::1"):
        print(f"[!] RADAR GUI is listening on {GUI_HOST}:{GUI_PORT}. Restrict this port to admin "
              "hosts, and list the name operators use in RADAR_GUI_ALLOWED_HOSTS.", file=sys.stderr)
    if GUI_DEBUG:
        print("[!] RADAR_GUI_DEBUG=1: the Werkzeug debugger is enabled. "
              "Never use this on a reachable interface.", file=sys.stderr)
    if GUI_AUTH_ENABLED:
        print(f"\n>>> RADAR GUI login URL (keep it private):\n    http://127.0.0.1:{GUI_PORT}/?token={GUI_TOKEN}\n",
              file=sys.stderr, flush=True)
    else:
        print("[!] RADAR_GUI_AUTH=off: the GUI accepts every request that reaches it.", file=sys.stderr)
    app.run(host=GUI_HOST, debug=GUI_DEBUG, port=GUI_PORT, threaded=True)
