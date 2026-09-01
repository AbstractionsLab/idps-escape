import os
import re
import sys
from flask import Flask, render_template, jsonify, request, Response, stream_with_context, g, make_response
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))  # repo root, so `import wazuh_api` resolves

from orchestrator import ar_config as ar_module
from orchestrator import deploy as deploy_module
from orchestrator import vault as vault_module
from orchestrator import connectors as conn_module
from wazuh_api import config as config_module

app = Flask(__name__)

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
        resp.set_cookie(VAULT_COOKIE, sid, httponly=True, samesite="Lax")
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
    return render_template("connectors.html", env=env, connector_status=connector_status)


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
    body = request.get_json(force=True) or {}
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
        result = conn_module.save_connector(RADAR_ROOT, name, fields)
        response = {"ok": True}
        if not result.get("synced", True):
            response["warning"] = (
                "Saved, but could not apply to the running manager: "
                f"{result.get('sync_error')}"
            )
        return jsonify(response)
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


# ── API: sudo (local docker compose privilege escalation) ──

@app.route("/api/sudo/status")
def api_sudo_status():
    sid = _get_vault_sid(create=False)
    return jsonify({"unlocked": bool(sid and vault_module.has_sudo_password(sid))})


@app.route("/api/sudo/unlock", methods=["POST"])
def api_sudo_unlock():
    body = request.get_json(force=True) or {}
    pw = body.get("password", "")
    if not pw:
        return jsonify({"ok": False, "error": "password is required"}), 400
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
    spec = request.get_json(force=True) or {}
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
    spec = request.get_json(force=True) or {}
    def generate():
        try:
            for chunk in deploy_module.stream_undo_scenario(RADAR_ROOT, spec):
                yield chunk
        except Exception as e:
            yield f"[ERROR] {e}\n"
    return Response(stream_with_context(generate()), mimetype="text/plain")


@app.route("/api/deploy/teardown", methods=["POST"])
def api_deploy_teardown():
    spec = request.get_json(force=True) or {}
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
    def generate():
        try:
            for chunk in deploy_module.stream_health(RADAR_ROOT, spec):
                yield chunk
        except Exception as e:
            yield f"[ERROR] {e}\n"
    return Response(stream_with_context(generate()), mimetype="text/plain")


@app.route("/api/deploy/mint-token", methods=["POST"])
def api_deploy_mint_token():
    spec = request.get_json(force=True) or {}
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
    spec = request.get_json(force=True) or {}
    def generate():
        try:
            for chunk in deploy_module.stream_assign_agent_group(RADAR_ROOT, spec):
                yield chunk
        except Exception as e:
            yield f"[ERROR] {e}\n"
    return Response(stream_with_context(generate()), mimetype="text/plain")


@app.route("/api/deploy/unassign-agent-group", methods=["POST"])
def api_deploy_unassign_agent_group():
    spec = request.get_json(force=True) or {}
    def generate():
        try:
            for chunk in deploy_module.stream_unassign_agent_group(RADAR_ROOT, spec):
                yield chunk
        except Exception as e:
            yield f"[ERROR] {e}\n"
    return Response(stream_with_context(generate()), mimetype="text/plain")


@app.route("/api/deploy/deregister-agent", methods=["POST"])
def api_deploy_deregister_agent():
    spec = request.get_json(force=True) or {}
    def generate():
        try:
            for chunk in deploy_module.stream_deregister_agent(RADAR_ROOT, spec):
                yield chunk
        except Exception as e:
            yield f"[ERROR] {e}\n"
    return Response(stream_with_context(generate()), mimetype="text/plain")


@app.route("/api/deploy/enrollment-window", methods=["POST"])
def api_deploy_enrollment_window():
    spec = request.get_json(force=True) or {}
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
    spec = request.get_json(force=True) or {}
    try:
        return jsonify(deploy_module.preview(RADAR_ROOT, spec))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.after_request
def _ensure_cookie(resp):
    return _attach_vault_cookie(resp)


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True, port=5000, threaded=True)