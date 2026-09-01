import importlib.util
from pathlib import Path


def _load_script(script_path: Path):
    spec = importlib.util.spec_from_file_location(script_path.stem, script_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def test_suspicious_login_writes_failed_and_success_lines(tmp_path, monkeypatch):
    calls = []

    script = Path("radar-test-framework/simulate/scenarios/suspicious_login.py").resolve()
    mod = _load_script(script)

    mod.CONFIG.update({
        "timezone_offset": "+01:00",
        "hostname": "edge.vm",
        "log_path": str(tmp_path / "auth.log"),
        "sudo_tee": False,
        "user": "test01",
        "sshd_pid": 999,
        "fail_port": 1045,
        "success_port": 60850,
        "key_fingerprint_fail": "ED25519 SHA256:A.",
        "key_fingerprint_success": "ED25519 SHA256:OK",
        "ip_pool": ["1.1.1.1", "2.2.2.2", "3.3.3.3"],
        "window_seconds": 60,
    })
    monkeypatch.setattr(mod, "append_line_authlog", lambda line, path, sudo_tee: calls.append((line, path, sudo_tee)))

    mod.main()

    assert len(calls) == 4

    failed = [c[0] for c in calls[:-1]]
    success = calls[-1][0]

    for i, line in enumerate(failed):
        assert "Failed password for test01" in line
        assert f"from {['1.1.1.1', '2.2.2.2', '3.3.3.3'][i]} port 1045" in line

    assert "Accepted publickey for test01" in success
    assert "from 1.1.1.1 port 60850" in success

    # every call targets the configured log path with the configured sudo_tee flag
    for _, path, sudo_tee in calls:
        assert path == str(tmp_path / "auth.log")
        assert sudo_tee is False


def test_suspicious_login_never_touches_the_real_filesystem(tmp_path, monkeypatch):
    script = Path("radar-test-framework/simulate/scenarios/suspicious_login.py").resolve()
    mod = _load_script(script)

    log_path = tmp_path / "auth.log"
    mod.CONFIG.update({"log_path": str(log_path), "ip_pool": ["1.1.1.1"], "window_seconds": 10})
    monkeypatch.setattr(mod, "append_line_authlog", lambda *a, **kw: None)

    mod.main()

    assert not log_path.exists()


def test_suspicious_login_creates_missing_log_directory(tmp_path):
    script = Path("radar-test-framework/simulate/scenarios/suspicious_login.py").resolve()
    mod = _load_script(script)

    log_path = tmp_path / "nested" / "does" / "not" / "exist" / "auth.log"
    mod.CONFIG.update({"log_path": str(log_path), "ip_pool": ["1.1.1.1"], "window_seconds": 10})

    mod.main()

    assert log_path.exists()