import importlib.util
import json
from pathlib import Path

import pytest


def _load_script(script_path: Path):
    spec = importlib.util.spec_from_file_location(script_path.stem, script_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


SCRIPT = Path("radar-test-framework/simulate/scenarios/scanning_detection.py").resolve()


@pytest.fixture
def mod(tmp_path):
    m = _load_script(SCRIPT)
    m.CONFIG.update({
        "log_path": str(tmp_path / "radar-access.json.log"),
        "sudo_tee": False,
        "indicator_gap_seconds": 0,
    })
    return m


def _lines(mod):
    return Path(mod.CONFIG["log_path"]).read_text().splitlines()


def _records(mod):
    return [json.loads(line) for line in _lines(mod)]


def test_record_matches_the_suricata_eve_shape(mod):
    record = json.loads(mod._line("1.2.3.4", "GET", "/index.php", 200, "Mozilla/5.0", "app.test"))

    assert record["event_type"] == "http"
    assert record["src_ip"] == "1.2.3.4"
    assert record["http"]["http_method"] == "GET"
    assert record["http"]["url"] == "/index.php"
    assert record["http"]["status"] == "200"
    assert record["http"]["hostname"] == "app.test"
    assert record["http"]["http_user_agent"] == "Mozilla/5.0"


def test_alert_records_carry_an_alert_object(mod):
    """Indicators 1 and 3 must work on the alert stream, which is the only
    stream this deployment currently emits."""
    record = json.loads(mod._line("1.2.3.4", "TRACE", "/", 405, "nikto", "h", "alert"))
    assert record["event_type"] == "alert"
    assert "signature" in record["alert"]
    assert record["http"]["http_method"] == "TRACE"


def test_status_is_a_string(mod):
    """Rule 100815 matches ^(401|403|404)$ against http.status."""
    record = json.loads(mod._line("1.2.3.4", "GET", "/x", 404, "UA", "h"))
    assert record["http"]["status"] == "404"
    assert isinstance(record["http"]["status"], str)


def test_user_agent_quotes_are_escaped(mod):
    """A malformed line is dropped by the JSON decoder, taking the request out
    of detection entirely. This is the failure mode Apache's CustomLog has."""
    line = mod._line("1.2.3.4", "GET", "/", 200, 'sqlmap "1.7" (x)', "h")
    assert json.loads(line)["http"]["http_user_agent"] == 'sqlmap "1.7" (x)'


def test_every_emitted_line_parses_as_json(mod, monkeypatch):
    monkeypatch.setattr(mod.sys, "argv", ["scanning_detection.py", "-b"])
    mod.main()
    for line in _lines(mod):
        json.loads(line)


# ---------------------------------------------------------------------------
# Indicator cases
# ---------------------------------------------------------------------------

def test_i1_only_emits_the_scanner_user_agent_on_both_streams(mod):
    mod.CASES["i1_only"](mod.Emitter(mod.CONFIG["log_path"], False, "app.test"), mod.CONFIG)

    records = _records(mod)
    # one http record and one alert record: the rules bind by group and are
    # evaluated under 86601 and 86602 alike
    assert len(records) == 2
    assert {r["event_type"] for r in records} == {"http", "alert"}
    assert all("sqlmap" in r["http"]["http_user_agent"].lower() for r in records)


def test_i2_only_emits_exactly_the_threshold_count_of_failed_requests(mod):
    mod.CASES["i2_only"](mod.Emitter(mod.CONFIG["log_path"], False, "app.test"), mod.CONFIG)

    records = _records(mod)
    assert len(records) == mod.CONFIG["fail_threshold"]
    assert all(r["http"]["status"] == "404" for r in records)
    assert len({r["src_ip"] for r in records}) == 1


def test_i2_below_emits_one_fewer_than_the_threshold(mod):
    """Criterion 8: one event fewer must not fire 100825."""
    mod.CASES["i2_below"](mod.Emitter(mod.CONFIG["log_path"], False, "app.test"), mod.CONFIG)
    assert len(_records(mod)) == mod.CONFIG["fail_threshold"] - 1


def test_i2_spread_distributes_the_threshold_across_distinct_sources(mod):
    """Criterion 6: correlation is per-source, so this must reach no threshold."""
    mod.CASES["i2_spread"](mod.Emitter(mod.CONFIG["log_path"], False, "app.test"), mod.CONFIG)

    records = _records(mod)
    assert len(records) == mod.CONFIG["fail_threshold"]
    sources = [r["src_ip"] for r in records]
    assert len(set(sources)) > 1
    # No single source may reach the threshold on its own.
    assert max(sources.count(s) for s in set(sources)) < mod.CONFIG["fail_threshold"]


def test_i3_only_uses_a_browser_user_agent(mod):
    """Criterion 7: method abuse must be detected independently of the UA value."""
    mod.CASES["i3_only"](mod.Emitter(mod.CONFIG["log_path"], False, "app.test"), mod.CONFIG)

    records = _records(mod)
    assert {r["http"]["http_method"] for r in records} == {"TRACE", "PROPFIND"}
    assert "alert" in {r["event_type"] for r in records}
    assert all("sqlmap" not in r["http"]["http_user_agent"].lower() for r in records)


def test_i3_excluded_emits_only_methods_the_indicator_ignores(mod):
    mod.CASES["i3_excluded"](mod.Emitter(mod.CONFIG["log_path"], False, "app.test"), mod.CONFIG)

    methods = {r["http"]["http_method"] for r in _records(mod)}
    assert methods <= {"OPTIONS", "PUT", "DELETE", "PATCH"}
    assert "OPTIONS" in methods


# ---------------------------------------------------------------------------
# Confirmation cases
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("case,expected_indicators", [
    ("confirm_1_2", {"ua", "rate"}),
    ("confirm_1_3", {"ua", "method"}),
    ("confirm_2_3", {"rate", "method"}),
])
def test_confirmation_cases_emit_two_distinct_indicators_from_one_source(mod, case, expected_indicators):
    mod.CASES[case](mod.Emitter(mod.CONFIG["log_path"], False, "app.test"), mod.CONFIG)
    records = _records(mod)

    assert len({r["src_ip"] for r in records}) == 1, "confirmation requires a single source"

    seen = set()
    if any("sqlmap" in r["http"]["http_user_agent"].lower() for r in records):
        seen.add("ua")
    if any(r["http"]["http_method"] in ("TRACE", "PROPFIND") for r in records):
        seen.add("method")
    if sum(1 for r in records if r["http"]["status"] in ("401", "403", "404")) >= mod.CONFIG["fail_threshold"]:
        seen.add("rate")

    assert seen == expected_indicators


def test_confirm_split_uses_two_different_sources(mod):
    """Criterion 11: two indicators on two sources must not confirm."""
    mod.CASES["confirm_split"](mod.Emitter(mod.CONFIG["log_path"], False, "app.test"), mod.CONFIG)

    records = _records(mod)
    assert len({r["src_ip"] for r in records}) == 2


def test_legit_emits_no_scanner_user_agent_and_no_abused_method(mod):
    mod.CASES["legit"](mod.Emitter(mod.CONFIG["log_path"], False, "app.test"), mod.CONFIG)

    for r in _records(mod):
        assert "sqlmap" not in r["http"]["http_user_agent"].lower()
        assert r["http"]["http_method"] not in ("TRACE", "TRACK", "CONNECT", "PROPFIND")


# ---------------------------------------------------------------------------
# CLI and filesystem safety
# ---------------------------------------------------------------------------

def test_main_runs_every_case_by_default(mod, monkeypatch):
    monkeypatch.setattr(mod.sys, "argv", ["scanning_detection.py", "-b"])
    ran = []
    for name, fn in list(mod.CASES.items()):
        mod.CASES[name] = lambda em, cfg, _n=name: ran.append(_n)

    mod.main()

    assert ran == list(mod.CASES)


def test_main_runs_only_the_requested_case(mod, monkeypatch):
    monkeypatch.setattr(mod.sys, "argv", ["scanning_detection.py", "-b", "confirm_1_3"])
    mod.main()

    records = _records(mod)
    assert len({r["src_ip"] for r in records}) == 1
    assert any("sqlmap" in r["http"]["http_user_agent"].lower() for r in records)


def test_main_rejects_an_unknown_case(mod, monkeypatch):
    monkeypatch.setattr(mod.sys, "argv", ["scanning_detection.py", "not_a_case"])

    with pytest.raises(SystemExit) as exc:
        mod.main()
    assert exc.value.code == 2
    assert not Path(mod.CONFIG["log_path"]).exists()


def test_main_never_touches_the_real_access_log(mod, monkeypatch):
    log_path = Path(mod.CONFIG["log_path"])
    monkeypatch.setattr(mod.sys, "argv", ["scanning_detection.py", "-b", "i1_only"])
    monkeypatch.setattr(mod, "_append", lambda *a, **kw: None)

    mod.main()

    assert not log_path.exists()


def test_main_creates_missing_log_directory(mod, tmp_path, monkeypatch):
    log_path = tmp_path / "nested" / "does" / "not" / "exist" / "access.json.log"
    mod.CONFIG["log_path"] = str(log_path)
    monkeypatch.setattr(mod.sys, "argv", ["scanning_detection.py", "-b", "i1_only"])

    mod.main()

    assert log_path.exists()
    assert len(log_path.read_text().splitlines()) == 2  # http + alert record