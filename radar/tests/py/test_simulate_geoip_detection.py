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


def test_geoip_detection_writes_one_line(tmp_path):
    calls = []

    common = types.ModuleType("common")
    common.load_config = lambda: {
        "common": {"timezone_offset": "+01:00", "hostname": "edge.vm"},
        "geoip_detection": {
            "log_path": str(tmp_path / "auth.log"),
            "sudo_tee": False,
            "user": "test01",
            "sshd_pid": 123,
            "success_port": 60850,
            "ip": "8.8.8.8",
            "key_fingerprint_success": "ED25519 SHA256:XXX",
        },
    }
    common.detect_authlog_timestamp_format = lambda ts, tz, auth_path: "Feb 17 12:00:04"
    common.append_line_authlog = lambda line, path, sudo_tee: calls.append((line, path, sudo_tee))

    script = Path("radar-test-framework/simulate/scenarios/geoip_detection.py").resolve()
    mod = _load_script_with_common(script, common)
    mod.main()

    assert len(calls) == 1
    line, path, sudo_tee = calls[0]
    assert path == str(tmp_path / "auth.log")
    assert sudo_tee is False
    assert line.startswith("Feb 17 12:00:04 edge.vm sshd[123]: Accepted publickey for test01")
    assert "from 8.8.8.8 port 60850 ssh2: ED25519 SHA256:XXX" in line