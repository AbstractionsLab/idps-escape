import sys
import types
import importlib.util
from pathlib import Path


def _load_script_with_common(script_path: Path, common_stub: types.ModuleType):
    sys.modules["common"] = common_stub
    spec = importlib.util.spec_from_file_location(script_path.stem, script_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def test_suspicious_login_writes_failed_and_success_lines(tmp_path):
    calls = []

    common = types.ModuleType("common")
    common.load_config = lambda: {
        "common": {"timezone_offset": "+01:00", "hostname": "edge.vm"},
        "suspicious_login": {
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
        },
    }
    common.detect_authlog_timestamp_format = lambda ts, tz, auth_path: "Feb 17 12:00:04"
    common.append_line_authlog = lambda line, path, sudo_tee: calls.append((line, path, sudo_tee))

    script = Path("radar-test-framework/simulate/scenarios/suspicious_login.py").resolve()
    mod = _load_script_with_common(script, common)
    mod.main()

    assert len(calls) == 4

    failed = [c[0] for c in calls[:-1]]
    success = calls[-1][0]

    for i, line in enumerate(failed):
        assert "Failed password for test01" in line
        assert f"from {['1.1.1.1','2.2.2.2','3.3.3.3'][i]} port 1045" in line

    assert "Accepted publickey for test01" in success
    assert "from 1.1.1.1 port 60850" in success