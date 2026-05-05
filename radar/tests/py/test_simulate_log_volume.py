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

    cfg = {
        "log_volume": {
            "target_dir": str(tmp_path),
            "spike_filename": "ratf_log_volume_spike.log",
            "steps": 3,
            "start_bytes": 1024,
            "growth_factor": 2.0,
            "sleep_seconds": 0,
            "max_total_bytes": 10_000,
            "max_step_bytes": 10_000,
            "cleanup_minutes": 0,
        }
    }

    monkeypatch.setattr(mod, "load_config", lambda: cfg)
    monkeypatch.setattr(mod, "get_scenario_simulate", lambda cfg, scenario: cfg[scenario])

    mod.main()

    f = tmp_path / "ratf_log_volume_spike.log"
    assert f.exists()
    assert f.stat().st_size == (1024 + 2048 + 4096)  # 7168