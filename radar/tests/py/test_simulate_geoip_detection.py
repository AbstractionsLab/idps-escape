import re
import importlib.util
from pathlib import Path

import pytest

SCRIPT_PATH = Path("radar-test-framework/simulate/scenarios/geoip_detection.py").resolve()


def _load_script(script_path: Path):
    spec = importlib.util.spec_from_file_location(script_path.stem, script_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def mod():
    return _load_script(SCRIPT_PATH)


@pytest.fixture
def recorder(mod, monkeypatch):
    calls = []
    monkeypatch.setattr(mod, "_append", lambda line, path, sudo_tee: calls.append((line, path, sudo_tee)))
    return calls


@pytest.fixture
def emitter(mod, tmp_path):
    auth_path = str(tmp_path / "auth.log")
    web_path = str(tmp_path / "access.log")
    mod.CONFIG.update({"auth_log_path": auth_path, "web_log_path": web_path})
    return mod.Emitter(auth_path, web_path, False, mod.CONFIG)


# --- CASES / EXPECT consistency -------------------------------------------

def test_every_case_has_an_expect_entry(mod):
    assert set(mod.CASES) == set(mod.EXPECT)


def test_every_expected_present_rule_has_a_level(mod):
    for name, expect in mod.EXPECT.items():
        for entry in expect["present"]:
            assert "rule" in entry and "level" in entry, name


@pytest.mark.parametrize("name", [
    "ssh_whitelisted", "ssh_non_whitelisted", "ssh_private",
    "web_ip", "web_ip_whitelisted", "web_private",
    "web_domain", "web_domainport", "web_ip_ip",
])
def test_case_output_mentions_every_expected_src_ip(mod, recorder, emitter, name):
    mod.CASES[name](emitter, mod.CONFIG)
    all_lines = "\n".join(line for line, _, _ in recorder)
    for ip in mod.EXPECT[name]["src_ips"]:
        assert ip in all_lines, f"{name}: expected src_ip {ip!r} not found in emitted lines"


# --- individual case behavior -----------------------------------------------

def test_ssh_whitelisted_writes_one_ssh_line_to_auth_log(mod, recorder, emitter):
    mod.case_ssh_whitelisted(emitter, mod.CONFIG)
    assert len(recorder) == 1
    line, path, sudo_tee = recorder[0]
    assert path == emitter.auth_log_path
    assert sudo_tee is False
    assert "Accepted publickey for test01" in line
    assert f"from {mod.SOURCES['ssh_whitelisted']} port 60850 ssh2:" in line


def test_ssh_non_whitelisted_writes_one_ssh_line(mod, recorder, emitter):
    mod.case_ssh_non_whitelisted(emitter, mod.CONFIG)
    assert len(recorder) == 1
    line, path, _ = recorder[0]
    assert path == emitter.auth_log_path
    assert f"from {mod.SOURCES['ssh_non_whitelisted']} port 60850 ssh2:" in line


def test_ssh_private_writes_one_ssh_line(mod, recorder, emitter):
    mod.case_ssh_private(emitter, mod.CONFIG)
    assert len(recorder) == 1
    line, path, _ = recorder[0]
    assert path == emitter.auth_log_path
    assert f"from {mod.SOURCES['ssh_private']} port 60850 ssh2:" in line


def test_web_ip_writes_plain_ip_format(mod, recorder, emitter):
    mod.case_web_ip(emitter, mod.CONFIG)
    assert len(recorder) == 1
    line, path, _ = recorder[0]
    assert path == emitter.web_log_path
    assert line.startswith(f"{mod.SOURCES['web_ip']} - - [")
    assert '"GET /index.html HTTP/1.1" 404 4096 "-" "curl/8.5.0"' in line


def test_web_ip_whitelisted_uses_ip_format_too(mod, recorder, emitter):
    mod.case_web_ip_whitelisted(emitter, mod.CONFIG)
    line, path, _ = recorder[0]
    assert path == emitter.web_log_path
    assert line.startswith(f"{mod.SOURCES['web_ip_whitelisted']} - - [")


def test_web_private_uses_ip_format(mod, recorder, emitter):
    mod.case_web_private(emitter, mod.CONFIG)
    line, _, _ = recorder[0]
    assert line.startswith(f"{mod.SOURCES['web_private']} - - [")


def test_web_domain_format_has_domain_before_ip(mod, recorder, emitter):
    mod.case_web_domain(emitter, mod.CONFIG)
    line, _, _ = recorder[0]
    assert line.startswith(f"shop.example.com {mod.SOURCES['web_domain']} - - [")


def test_web_domainport_format_has_domain_colon_port_before_ip(mod, recorder, emitter):
    mod.case_web_domainport(emitter, mod.CONFIG)
    line, _, _ = recorder[0]
    assert line.startswith(f"shop.example.com:8443 {mod.SOURCES['web_domainport']} - - [")


def test_web_ip_ip_format_has_vhost_ip_before_srcip(mod, recorder, emitter):
    mod.case_web_ip_ip(emitter, mod.CONFIG)
    line, _, _ = recorder[0]
    assert line.startswith(f"203.0.113.10 {mod.SOURCES['web_ip_ip']} - - [")


def test_unknown_web_format_raises(mod):
    with pytest.raises(ValueError):
        mod._web_line("1.2.3.4", "bogus-format", mod.CONFIG)


# --- filesystem helpers ------------------------------------------------------

def test_ensure_log_dir_creates_missing_directory(mod, tmp_path):
    log_path = tmp_path / "nested" / "does" / "not" / "exist" / "auth.log"
    mod._ensure_log_dir(str(log_path), False)
    assert log_path.parent.is_dir()


def test_ensure_log_dir_noop_for_bare_filename(mod):
    # os.path.dirname("auth.log") == "" -> function must not raise
    mod._ensure_log_dir("auth.log", False)


def test_append_actually_writes_via_tee(mod, tmp_path):
    log_path = tmp_path / "auth.log"
    mod._append("hello world", str(log_path), False)
    assert log_path.read_text() == "hello world\n"


# --- _confirm_verified -------------------------------------------------------

@pytest.mark.parametrize("answer,expected", [
    ("y", True), ("yes", True), ("YES", True),
    ("n", False), ("no", False),
    ("q", None), ("quit", None),
])
def test_confirm_verified_parses_answers(mod, monkeypatch, answer, expected):
    monkeypatch.setattr("builtins.input", lambda prompt: answer)
    assert mod._confirm_verified("some_case") is expected


def test_confirm_verified_reprompts_on_garbage(mod, monkeypatch):
    answers = iter(["maybe", "later", "y"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    assert mod._confirm_verified("some_case") is True


# --- main(): CLI parsing and end-to-end behavior -----------------------------

def test_main_batch_mode_runs_every_case_and_writes_expected_line_counts(mod, monkeypatch, tmp_path):
    auth_path = tmp_path / "auth.log"
    web_path = tmp_path / "access.log"
    mod.CONFIG.update({"auth_log_path": str(auth_path), "web_log_path": str(web_path), "case_gap_seconds": 0})
    monkeypatch.setattr(mod.sys, "argv", ["geoip_detection.py", "-b"])

    mod.main()

    ssh_case_count = sum(1 for name in mod.CASES if name.startswith("ssh_"))
    web_case_count = sum(1 for name in mod.CASES if name.startswith("web_"))

    assert len(auth_path.read_text().splitlines()) == ssh_case_count
    assert len(web_path.read_text().splitlines()) == web_case_count


def test_main_single_case_selection_only_runs_that_case(mod, monkeypatch, tmp_path):
    auth_path = tmp_path / "auth.log"
    web_path = tmp_path / "access.log"
    mod.CONFIG.update({"auth_log_path": str(auth_path), "web_log_path": str(web_path)})
    monkeypatch.setattr(mod.sys, "argv", ["geoip_detection.py", "ssh_whitelisted", "-b"])

    mod.main()

    assert len(auth_path.read_text().splitlines()) == 1
    assert not web_path.exists()


def test_main_unknown_case_exits_with_code_2(mod, monkeypatch, capsys):
    monkeypatch.setattr(mod.sys, "argv", ["geoip_detection.py", "not_a_real_case", "-b"])
    with pytest.raises(SystemExit) as exc_info:
        mod.main()
    assert exc_info.value.code == 2
    assert "unknown case" in capsys.readouterr().err.lower()


def test_main_never_touches_real_filesystem_when_append_mocked(mod, monkeypatch, tmp_path):
    auth_path = tmp_path / "auth.log"
    web_path = tmp_path / "access.log"
    mod.CONFIG.update({"auth_log_path": str(auth_path), "web_log_path": str(web_path)})
    monkeypatch.setattr(mod, "_append", lambda *a, **kw: None)
    monkeypatch.setattr(mod.sys, "argv", ["geoip_detection.py", "-b"])

    mod.main()

    assert not auth_path.exists()
    assert not web_path.exists()


def test_main_interactive_quit_stops_after_first_case(mod, monkeypatch, tmp_path, capsys):
    auth_path = tmp_path / "auth.log"
    web_path = tmp_path / "access.log"
    mod.CONFIG.update({"auth_log_path": str(auth_path), "web_log_path": str(web_path)})
    monkeypatch.setattr(mod.sys, "argv", ["geoip_detection.py"])
    monkeypatch.setattr("builtins.input", lambda prompt: "q")

    mod.main()

    assert "stopped early" in capsys.readouterr().out
    # only the first case (ssh_whitelisted) should have run before quitting
    assert len(auth_path.read_text().splitlines()) == 1