from wazuh_api import config


def _write_config(tmp_path, scenarios: dict):
    import yaml
    (tmp_path / "config.yaml").write_text(yaml.dump({"scenarios": scenarios}))
    config.load.cache_clear()


def test_valid_scenarios_excludes_default(tmp_path):
    _write_config(tmp_path, {"default": {}, "suspicious_login": {}, "log_volume": {}})
    assert config.valid_scenarios(str(tmp_path)) == {"suspicious_login", "log_volume"}


def test_agent_service_by_scenario_only_includes_container_name(tmp_path):
    _write_config(tmp_path, {
        "default": {},
        "suspicious_login": {"container_name": "agent.suspicious"},
        "scanning_detection": {},
    })
    result = config.agent_service_by_scenario(str(tmp_path))
    assert result == {"suspicious_login": "agent.suspicious"}


def test_missing_config_file_returns_empty(tmp_path):
    config.load.cache_clear()
    assert config.valid_scenarios(str(tmp_path)) == set()
    assert config.agent_service_by_scenario(str(tmp_path)) == {}


def test_load_is_cached_per_radar_root(tmp_path):
    _write_config(tmp_path, {"suspicious_login": {}})
    first = config.load(str(tmp_path))
    (tmp_path / "config.yaml").write_text("scenarios: {}")
    second = config.load(str(tmp_path))
    assert first == second


def test_real_repo_config_has_expected_scenarios():
    config.load.cache_clear()
    scenarios = config.valid_scenarios(".")
    assert "suspicious_login" in scenarios
    assert "geoip_detection" in scenarios
    assert "default" not in scenarios