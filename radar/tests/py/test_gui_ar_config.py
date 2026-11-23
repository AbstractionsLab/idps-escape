"""GUI: mitigations offered and accepted come from Wazuh built-ins plus the
endpoint catalog (radar-agent/ar-scripts.yaml); the GUI never writes it."""

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
GUI_DIR = REPO_ROOT / "gui"
sys.path.insert(0, str(GUI_DIR))

from orchestrator import ar_config  # noqa: E402

CATALOG = """scripts:
  lock_user_linux.sh: active_responses/lock_user_linux_v1.sh
  terminate_service.sh: active_responses/terminate_service_v1.sh
"""


@pytest.fixture
def root(tmp_path):
    """A RADAR_ROOT with the real ar.yaml and a known catalog."""
    ar_dir = tmp_path / "scenarios" / "active_responses"
    ar_dir.mkdir(parents=True)
    shutil.copy(REPO_ROOT / "scenarios" / "active_responses" / "ar.yaml", ar_dir / "ar.yaml")
    (tmp_path / "radar-agent").mkdir()
    (tmp_path / "radar-agent" / "ar-scripts.yaml").write_text(CATALOG)
    return tmp_path


def _catalog(root, text):
    (root / "radar-agent" / "ar-scripts.yaml").write_text(text)


def _ar(root):
    return yaml.safe_load((root / "scenarios" / "active_responses" / "ar.yaml").read_text())


# --- reading the catalog -----------------------------------------------------

def test_load_catalog(root):
    assert ar_config.load_catalog(root) == {
        "lock_user_linux.sh": "active_responses/lock_user_linux_v1.sh",
        "terminate_service.sh": "active_responses/terminate_service_v1.sh",
    }
    assert ar_config.catalog_problem(root) is None


def test_load_catalog_empty_is_valid(root):
    _catalog(root, "scripts: {}\n")
    assert ar_config.load_catalog(root) == {}
    _catalog(root, "scripts:\n")
    assert ar_config.load_catalog(root) == {}


@pytest.mark.parametrize("text, fragment", [
    (None, "not found"),
    ("scripts: [a, b\n", "not valid YAML"),
    ("scripts: [a.sh]\n", "must map"),
    ("scripts:\n  ../a.sh: active_responses/a.sh\n", "invalid active response name"),
    ("scripts:\n  a.sh: /etc/passwd\n", "invalid script path"),
    ("scripts:\n  a.sh: active_responses/../../x.sh\n", "invalid script path"),
    ("scripts:\n  a.sh: other/a.sh\n", "invalid script path"),
    ("scripts:\n  a.sh: 3\n", "invalid script path"),
])
def test_load_catalog_rejects_bad_catalogs(root, text, fragment):
    if text is None:
        (root / "radar-agent" / "ar-scripts.yaml").unlink()
    else:
        _catalog(root, text)
    with pytest.raises(ar_config.CatalogError, match=fragment):
        ar_config.load_catalog(root)
    assert fragment in ar_config.catalog_problem(root)


# --- what the picker offers --------------------------------------------------

def test_known_mitigations_are_builtins_plus_catalog(root):
    assert ar_config.list_known_mitigations(root) == [
        "firewall-drop", "lock_user_linux.sh", "terminate_service.sh",
    ]


def test_known_mitigations_follow_the_catalog(root):
    _catalog(root, "scripts:\n  block_usb.sh: active_responses/block_usb_v1.sh\n")
    assert ar_config.list_known_mitigations(root) == ["firewall-drop", "block_usb.sh"]


def test_broken_catalog_offers_only_builtins(root):
    _catalog(root, "scripts: nope\n")
    assert ar_config.list_known_mitigations(root) == ["firewall-drop"]


def test_shipped_repo_offers_the_sh_names(tmp_path):
    names = ar_config.list_known_mitigations(REPO_ROOT)
    assert "lock_user_linux.sh" in names and "terminate_service.sh" in names
    assert "lock_user_linux" not in names and "terminate_service" not in names


# --- validating what is saved ------------------------------------------------

def test_normalize_keeps_order_and_drops_duplicates(root):
    assert ar_config.normalize_mitigations(
        root, ["terminate_service.sh", "firewall-drop", "terminate_service.sh"]
    ) == ["terminate_service.sh", "firewall-drop"]


def test_normalize_rewrites_legacy_names(root):
    assert ar_config.normalize_mitigations(
        root, ["lock_user_linux", "lock_user_linux.sh", " terminate_service "]
    ) == ["lock_user_linux.sh", "terminate_service.sh"]


def test_normalize_none_and_empty(root):
    assert ar_config.normalize_mitigations(root, None) == []
    assert ar_config.normalize_mitigations(root, []) == []


def test_normalize_rejects_unknown_names_and_lists_what_is_available(root):
    with pytest.raises(ValueError) as e:
        ar_config.normalize_mitigations(root, ["firewall-drop", "rm_rf.sh"])
    msg = str(e.value)
    assert "rm_rf.sh" in msg
    assert "firewall-drop, lock_user_linux.sh, terminate_service.sh" in msg
    assert "radar-agent/ar-scripts.yaml" in msg


@pytest.mark.parametrize("value", ["firewall-drop", [1], [None], {"a": 1}])
def test_normalize_rejects_non_string_lists(root, value):
    with pytest.raises(ValueError, match="must be a list"):
        ar_config.normalize_mitigations(root, value)


def test_normalize_with_broken_catalog_explains_why(root):
    _catalog(root, "scripts: nope\n")
    with pytest.raises(ValueError, match="catalog is unusable"):
        ar_config.normalize_mitigations(root, ["lock_user_linux.sh"])
    assert ar_config.normalize_mitigations(root, ["firewall-drop"]) == ["firewall-drop"]


# --- writing ar.yaml ---------------------------------------------------------

def test_update_scenario_normalizes_every_tier(root):
    ar_config.update_scenario(root, "suspicious_login", {
        "mitigations_tier2": ["firewall-drop", "firewall-drop"],
        "mitigations_tier3": ["lock_user_linux"],
        "mitigations_tier4": ["terminate_service"],
    })
    cfg = _ar(root)["scenarios"]["suspicious_login"]
    assert cfg["mitigations_tier2"] == ["firewall-drop"]
    assert cfg["mitigations_tier3"] == ["lock_user_linux.sh"]
    assert cfg["mitigations_tier4"] == ["terminate_service.sh"]


def test_update_scenario_rejects_unknown_and_leaves_ar_yaml_untouched(root):
    before = (root / "scenarios" / "active_responses" / "ar.yaml").read_text()
    with pytest.raises(ValueError):
        ar_config.update_scenario(root, "suspicious_login",
                                  {"w_ad": 0.5, "mitigations_tier3": ["nope.sh"]})
    assert (root / "scenarios" / "active_responses" / "ar.yaml").read_text() == before


def test_update_scenario_without_mitigations_is_not_validated(root):
    _catalog(root, "scripts: nope\n")
    ar_config.update_scenario(root, "suspicious_login", {"w_ad": 0.25})
    assert _ar(root)["scenarios"]["suspicious_login"]["w_ad"] == 0.25


def test_update_scenario_rejects_non_dict_patch(root):
    with pytest.raises(ValueError, match="JSON object"):
        ar_config.update_scenario(root, "suspicious_login", ["w_ad"])


def test_mark_deployed_still_works(root):
    ar_config.mark_deployed(root, "suspicious_login", True)
    assert _ar(root)["scenarios"]["suspicious_login"]["active"] is True


def test_bind_new_scenario_normalizes(root):
    ar_config.bind_scenario(root, "new_scenario", mitigations=["terminate_service"])
    cfg = _ar(root)["scenarios"]["new_scenario"]
    assert cfg["mitigations_tier2"] == ["terminate_service.sh"]
    assert cfg["mitigations_tier3"] == ["terminate_service.sh"]


def test_bind_existing_scenario_normalizes(root):
    ar_config.bind_scenario(root, "suspicious_login", mitigations=["lock_user_linux"])
    cfg = _ar(root)["scenarios"]["suspicious_login"]
    assert cfg["mitigations_tier2"] == ["lock_user_linux.sh"]
    assert cfg["mitigations_tier3"] == ["lock_user_linux.sh"]


def test_bind_rejects_unknown_before_writing(root):
    with pytest.raises(ValueError):
        ar_config.bind_scenario(root, "new_scenario", mitigations=["nope.sh"])
    assert "new_scenario" not in _ar(root)["scenarios"]


def test_gui_never_writes_the_catalog(root):
    before = (root / "radar-agent" / "ar-scripts.yaml").read_text()
    ar_config.update_scenario(root, "suspicious_login", {"mitigations_tier3": ["lock_user_linux.sh"]})
    ar_config.bind_scenario(root, "new_scenario", mitigations=["firewall-drop"])
    assert (root / "radar-agent" / "ar-scripts.yaml").read_text() == before


# --- HTTP routes and page ----------------------------------------------------

@pytest.fixture
def client(root, monkeypatch):
    spec = importlib.util.spec_from_file_location("radar_gui_app_under_test", GUI_DIR / "app.py")
    app_mod = importlib.util.module_from_spec(spec)
    # Flask locates templates/ and static/ through the module's file.
    monkeypatch.setitem(sys.modules, spec.name, app_mod)
    spec.loader.exec_module(app_mod)
    for name in ("config.yaml", "infra.yaml"):
        if (REPO_ROOT / name).exists():
            shutil.copy(REPO_ROOT / name, root / name)
    (root / "scenarios" / "rules").mkdir(exist_ok=True)
    monkeypatch.setattr(app_mod, "RADAR_ROOT", str(root))
    # Authentication and host checks are tested elsewhere; not the subject here.
    monkeypatch.setattr(app_mod.app, "before_request_funcs", {})
    app_mod.app.testing = True
    return app_mod.app.test_client()


def test_put_ar_config_saves_normalized(client, root):
    r = client.put("/api/scenarios/suspicious_login/ar-config",
                   json={"mitigations_tier3": ["firewall-drop", "lock_user_linux"]})
    assert r.status_code == 200 and r.json == {"ok": True}
    assert _ar(root)["scenarios"]["suspicious_login"]["mitigations_tier3"] == ["firewall-drop", "lock_user_linux.sh"]


def test_put_ar_config_unknown_mitigation_is_a_400_with_reason(client):
    r = client.put("/api/scenarios/suspicious_login/ar-config", json={"mitigations_tier2": ["nope.sh"]})
    assert r.status_code == 400
    assert r.json["ok"] is False and "nope.sh" in r.json["error"]


def test_put_ar_config_non_list_is_a_400(client):
    r = client.put("/api/scenarios/suspicious_login/ar-config", json={"mitigations_tier2": "firewall-drop"})
    assert r.status_code == 400


def test_bind_unknown_mitigation_is_a_400(client):
    r = client.post("/api/scenarios/suspicious_login/bind", json={"mitigations": ["nope.sh"]})
    assert r.status_code == 400
    assert "nope.sh" in r.json["error"]


def test_bind_legacy_mitigation_is_saved_normalized(client, root):
    r = client.post("/api/scenarios/suspicious_login/bind", json={"mitigations": ["lock_user_linux"]})
    assert r.status_code == 200
    assert _ar(root)["scenarios"]["suspicious_login"]["mitigations_tier3"] == ["lock_user_linux.sh"]


def test_page_offers_catalog_actions(client):
    r = client.get("/active-responses/suspicious_login")
    assert r.status_code == 200
    for name in ("firewall-drop", "lock_user_linux.sh", "terminate_service.sh"):
        assert f'<option value="{name}">'.encode() in r.data
    assert b'<option value="lock_user_linux">' not in r.data
    assert b"catalog unusable" not in r.data


def test_page_shows_legacy_names_normalized_and_flags_unknown_ones(client, root):
    data = _ar(root)
    data["scenarios"]["suspicious_login"]["mitigations_tier2"] = ["terminate_service", "custom_x.sh"]
    (root / "scenarios" / "active_responses" / "ar.yaml").write_text(yaml.safe_dump(data))
    r = client.get("/active-responses/suspicious_login")
    assert b'<span class="mit-tag" data-value="terminate_service.sh">' in r.data
    assert b'mit-tag--unknown" data-value="custom_x.sh"' in r.data


def test_page_warns_when_catalog_is_broken(client, root):
    _catalog(root, "scripts: nope\n")
    r = client.get("/active-responses/suspicious_login")
    assert r.status_code == 200
    assert b"catalog unusable" in r.data
    assert b'<option value="lock_user_linux.sh">' not in r.data
