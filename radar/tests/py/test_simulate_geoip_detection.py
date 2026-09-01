import importlib.util
from pathlib import Path


def _load_script(script_path: Path):
    spec = importlib.util.spec_from_file_location(script_path.stem, script_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def test_geoip_detection_writes_one_line(tmp_path, monkeypatch):
    calls = []

    script = Path("radar-test-framework/simulate/scenarios/geoip_detection.py").resolve()
    mod = _load_script(script)

    mod.CONFIG.update({
        "timezone_offset": "+01:00",
        "hostname": "edge.vm",
        "log_path": str(tmp_path / "auth.log"),
        "sudo_tee": False,
        "user": "test01",
        "sshd_pid": 123,
        "success_port": 60850,
        "ip": "8.8.8.8",
        "key_fingerprint_success": "ED25519 SHA256:XXX",
    })
    monkeypatch.setattr(mod, "append_line_authlog", lambda line, path, sudo_tee: calls.append((line, path, sudo_tee)))
    monkeypatch.setattr(mod, "detect_authlog_timestamp_format", lambda ts, tz, auth_path: "Feb 17 12:00:04")

    mod.main()

    assert len(calls) == 1
    line, path, sudo_tee = calls[0]
    assert path == str(tmp_path / "auth.log")
    assert sudo_tee is False
    assert line.startswith("Feb 17 12:00:04 edge.vm sshd[123]: Accepted publickey for test01")
    assert "from 8.8.8.8 port 60850 ssh2: ED25519 SHA256:XXX" in line


def test_geoip_detection_never_touches_the_real_filesystem(tmp_path, monkeypatch):
    script = Path("radar-test-framework/simulate/scenarios/geoip_detection.py").resolve()
    mod = _load_script(script)

    log_path = tmp_path / "auth.log"
    mod.CONFIG.update({"log_path": str(log_path)})
    monkeypatch.setattr(mod, "append_line_authlog", lambda *a, **kw: None)

    mod.main()

    assert not log_path.exists()


def test_geoip_detection_creates_missing_log_directory(tmp_path):
    script = Path("radar-test-framework/simulate/scenarios/geoip_detection.py").resolve()
    mod = _load_script(script)

    log_path = tmp_path / "nested" / "does" / "not" / "exist" / "auth.log"
    mod.CONFIG.update({"log_path": str(log_path)})

    mod.main()

    assert log_path.exists()