import importlib.util
from pathlib import Path


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def test_log_volume_creates_and_grows_file(tmp_path, monkeypatch):
    script = Path("radar-test-framework/simulate/scenarios/log_volume.py").resolve()
    mod = _load_module(script, "log_volume_mod")

    mod.CONFIG.update({
        "target_dir": str(tmp_path),
        "spike_filename": "ratf_log_volume_spike.log",
        "steps": 3,
        "start_bytes": 1024,
        "growth_factor": 2.0,
        "sleep_seconds": 0,
        "max_total_bytes": 10_000,
        "max_step_bytes": 10_000,
        "cleanup_minutes": 0,
    })
    # No real sleeping in a unit test regardless of sleep_seconds above.
    monkeypatch.setattr(mod.time, "sleep", lambda *_: None)

    mod.main()

    f = tmp_path / "ratf_log_volume_spike.log"
    assert f.exists()
    assert f.stat().st_size == (1024 + 2048 + 4096)  # 7168


def test_log_volume_caps_growth_at_max_total_bytes(tmp_path, monkeypatch):
    script = Path("radar-test-framework/simulate/scenarios/log_volume.py").resolve()
    mod = _load_module(script, "log_volume_mod_capped")

    mod.CONFIG.update({
        "target_dir": str(tmp_path),
        "spike_filename": "ratf_log_volume_spike.log",
        "steps": 10,
        "start_bytes": 1024,
        "growth_factor": 2.0,
        "sleep_seconds": 0,
        "max_total_bytes": 5000,
        "max_step_bytes": 10_000,
        "cleanup_minutes": 0,
    })
    monkeypatch.setattr(mod.time, "sleep", lambda *_: None)

    mod.main()

    f = tmp_path / "ratf_log_volume_spike.log"
    assert f.stat().st_size == 5000


def test_log_volume_caps_each_step_at_max_step_bytes(tmp_path, monkeypatch):
    script = Path("radar-test-framework/simulate/scenarios/log_volume.py").resolve()
    mod = _load_module(script, "log_volume_mod_stepcap")

    mod.CONFIG.update({
        "target_dir": str(tmp_path),
        "spike_filename": "ratf_log_volume_spike.log",
        "steps": 3,
        "start_bytes": 1024,
        "growth_factor": 10.0,   # would blow past max_step_bytes immediately
        "sleep_seconds": 0,
        "max_total_bytes": 100_000,
        "max_step_bytes": 2000,
        "cleanup_minutes": 0,
    })
    monkeypatch.setattr(mod.time, "sleep", lambda *_: None)

    mod.main()

    f = tmp_path / "ratf_log_volume_spike.log"
    # step 1 = start_bytes (1024, under the cap), steps 2-3 capped at 2000 each
    assert f.stat().st_size == (1024 + 2000 + 2000)


def test_log_volume_schedules_cleanup_when_configured(tmp_path, monkeypatch):
    script = Path("radar-test-framework/simulate/scenarios/log_volume.py").resolve()
    mod = _load_module(script, "log_volume_mod_cleanup")

    mod.CONFIG.update({
        "target_dir": str(tmp_path),
        "spike_filename": "ratf_log_volume_spike.log",
        "steps": 1,
        "start_bytes": 128,
        "growth_factor": 1.0,
        "sleep_seconds": 0,
        "max_total_bytes": 10_000,
        "max_step_bytes": 10_000,
        "cleanup_minutes": 5,
    })
    monkeypatch.setattr(mod.time, "sleep", lambda *_: None)

    scheduled = {}

    def fake_schedule_cleanup(file_path, cleanup_minutes):
        scheduled["file_path"] = file_path
        scheduled["cleanup_minutes"] = cleanup_minutes

    monkeypatch.setattr(mod, "_schedule_cleanup", fake_schedule_cleanup)

    mod.main()

    assert scheduled["cleanup_minutes"] == 5
    assert scheduled["file_path"] == tmp_path / "ratf_log_volume_spike.log"