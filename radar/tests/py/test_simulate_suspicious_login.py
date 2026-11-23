import importlib.util
from pathlib import Path

import pytest

SCRIPT_PATH = Path("radar-test-framework/simulate/scenarios/suspicious_login.py").resolve()


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
def pauses():
    return []


@pytest.fixture
def emitter(mod, tmp_path, pauses):
    log_path = str(tmp_path / "auth.log")
    mod.CONFIG.update({"log_path": log_path})
    return mod.Emitter(log_path, False, mod.CONFIG, sleep=pauses.append)


@pytest.fixture
def no_sleep(mod, monkeypatch):
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)


# --- CASES / EXPECT consistency -------------------------------------------

def test_every_case_has_an_expect_entry(mod):
    assert set(mod.CASES) == set(mod.EXPECT)


def test_every_expected_present_rule_has_a_level(mod):
    for name, expect in mod.EXPECT.items():
        for entry in expect["present"]:
            assert "rule" in entry and "level" in entry, name


@pytest.mark.parametrize("name", ["burst", "travel", "failed_travel", "composite", "benign"])
def test_case_output_mentions_every_expected_src_ip(mod, recorder, emitter, name):
    mod.CASES[name](emitter, mod.CONFIG)
    all_lines = "\n".join(line for line, _, _ in recorder)
    for ip in mod.EXPECT[name]["src_ips"]:
        assert ip in all_lines, f"{name}: expected src_ip {ip!r} not found in emitted lines"


# --- individual case behavior -----------------------------------------------

def test_burst_writes_threshold_plus_margin_fails_then_one_success(mod, recorder, emitter):
    mod.case_burst(emitter, mod.CONFIG)
    n = mod.CONFIG["fail_threshold"] + mod.CONFIG["fail_margin"]
    assert len(recorder) == n + 1

    fail_lines = recorder[:n]
    success_line, success_path, success_sudo = recorder[n]

    for i, (line, path, sudo_tee) in enumerate(fail_lines):
        assert path == emitter.log_path
        assert sudo_tee is False
        assert f"Failed password for {mod.USERS['burst']}" in line
        assert f"from {mod.BURST_IPS[i]} port {mod.CONFIG['fail_port']}" in line

    assert f"Accepted publickey for {mod.USERS['burst']}" in success_line
    assert f"from {mod.BURST_IPS[0]} port {mod.CONFIG['success_port']}" in success_line


def test_burst_ips_all_share_one_subnet(mod):
    # regression guard: burst must stay single-country so it can't also trip
    # the impossible-travel rules via incidental country-hopping between fails
    prefixes = {".".join(ip.split(".")[:3]) for ip in mod.BURST_IPS}
    assert len(prefixes) == 1


def test_travel_writes_three_successes_in_order(mod, recorder, emitter):
    mod.case_travel(emitter, mod.CONFIG)
    assert len(recorder) == 3
    for (line, path, _), (_, ip) in zip(recorder, mod.TRAVEL_IPS):
        assert path == emitter.log_path
        assert f"Accepted publickey for {mod.USERS['travel']}" in line
        assert f"from {ip} port {mod.CONFIG['success_port']}" in line


def test_failed_travel_writes_three_failures_in_order(mod, recorder, emitter):
    mod.case_failed_travel(emitter, mod.CONFIG)
    assert len(recorder) == 3
    for (line, path, _), (_, ip) in zip(recorder, mod.FAILED_TRAVEL_IPS):
        assert path == emitter.log_path
        assert f"Failed password for {mod.USERS['failed_travel']}" in line
        assert f"from {ip} port {mod.CONFIG['fail_port']}" in line


def test_composite_writes_baseline_then_burst_then_success(mod, recorder, emitter):
    mod.case_composite(emitter, mod.CONFIG)
    n = mod.CONFIG["fail_threshold"] + mod.CONFIG["fail_margin"]
    assert len(recorder) == n + 2

    baseline_line = recorder[0][0]
    burst_lines = recorder[1:1 + n]
    success_line = recorder[1 + n][0]

    assert f"Accepted publickey for {mod.USERS['composite']}" in baseline_line
    assert f"from {mod.COMPOSITE_BASELINE_IP} port {mod.CONFIG['success_port']}" in baseline_line

    for i, (line, path, _) in enumerate(burst_lines):
        assert path == emitter.log_path
        assert f"Failed password for {mod.USERS['composite']}" in line
        assert f"from {mod.COMPOSITE_BURST_IPS[i]} port {mod.CONFIG['fail_port']}" in line

    assert f"Accepted publickey for {mod.USERS['composite']}" in success_line
    assert f"from {mod.COMPOSITE_SUCCESS_IP} port {mod.CONFIG['success_port']}" in success_line


def test_composite_burst_ips_all_share_one_subnet(mod):
    # regression guard: mixed-country burst IPs risk tripping the failure-side
    # impossible-travel rule on every hop, which can prevent the composite
    # rule from correlating cleanly
    prefixes = {".".join(ip.split(".")[:3]) for ip in mod.COMPOSITE_BURST_IPS}
    assert len(prefixes) == 1


def test_benign_writes_two_successes_one_hour_apart(mod, monkeypatch, emitter):
    captured = []
    monkeypatch.setattr(mod, "_line", lambda user, srcip, outcome, ts, cfg: captured.append((user, srcip, outcome, ts)) or "line")
    mod.case_benign(emitter, mod.CONFIG)

    assert len(captured) == 2
    (_, ip0, outcome0, ts0), (_, ip1, outcome1, ts1) = captured
    assert outcome0 == outcome1 == "success"
    assert ip0 == mod.BENIGN_IPS[0]
    assert ip1 == mod.BENIGN_IPS[1]
    assert (ts1 - ts0).total_seconds() == 3600


# --- filesystem helpers ------------------------------------------------------

def test_ensure_log_dir_creates_missing_directory(mod, tmp_path):
    log_path = tmp_path / "nested" / "does" / "not" / "exist" / "auth.log"
    mod._ensure_log_dir(str(log_path), False)
    assert log_path.parent.is_dir()


def test_ensure_log_dir_noop_for_bare_filename(mod):
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

def test_main_batch_mode_runs_every_case_and_writes_expected_line_count(mod, monkeypatch, tmp_path, no_sleep):
    log_path = tmp_path / "auth.log"
    mod.CONFIG.update({"log_path": str(log_path), "case_gap_seconds": 0})
    monkeypatch.setattr(mod.sys, "argv", ["suspicious_login.py", "-b"])

    mod.main()

    n = mod.CONFIG["fail_threshold"] + mod.CONFIG["fail_margin"]
    expected_total = (n + 1) + 3 + 3 + (n + 2) + 2  # burst + travel + failed_travel + composite + benign
    assert len(log_path.read_text().splitlines()) == expected_total


def test_main_single_case_selection_only_runs_that_case(mod, monkeypatch, tmp_path, no_sleep):
    log_path = tmp_path / "auth.log"
    mod.CONFIG.update({"log_path": str(log_path)})
    monkeypatch.setattr(mod.sys, "argv", ["suspicious_login.py", "travel", "-b"])

    mod.main()

    assert len(log_path.read_text().splitlines()) == 3


def test_main_unknown_case_exits_with_code_2(mod, monkeypatch, capsys):
    monkeypatch.setattr(mod.sys, "argv", ["suspicious_login.py", "not_a_real_case", "-b"])
    with pytest.raises(SystemExit) as exc_info:
        mod.main()
    assert exc_info.value.code == 2
    assert "unknown case" in capsys.readouterr().err.lower()


def test_main_never_touches_real_filesystem_when_append_mocked(mod, monkeypatch, tmp_path, no_sleep):
    log_path = tmp_path / "auth.log"
    mod.CONFIG.update({"log_path": str(log_path)})
    monkeypatch.setattr(mod, "_append", lambda *a, **kw: None)
    monkeypatch.setattr(mod.sys, "argv", ["suspicious_login.py", "-b"])

    mod.main()

    assert not log_path.exists()


def test_main_interactive_quit_stops_after_first_case(mod, monkeypatch, tmp_path, capsys, no_sleep):
    log_path = tmp_path / "auth.log"
    mod.CONFIG.update({"log_path": str(log_path)})
    monkeypatch.setattr(mod.sys, "argv", ["suspicious_login.py"])
    monkeypatch.setattr("builtins.input", lambda prompt: "q")

    mod.main()

    assert "stopped early" in capsys.readouterr().out
    # only the first case (burst) should have run before quitting
    n = mod.CONFIG["fail_threshold"] + mod.CONFIG["fail_margin"]
    assert len(log_path.read_text().splitlines()) == n + 1


@pytest.fixture
def timeline(mod, monkeypatch, tmp_path):
    """Records sends and pauses in order, with each line's timestamp."""
    events = []
    monkeypatch.setattr(mod, "_append", lambda line, path, sudo_tee: None)
    real_line = mod._line
    monkeypatch.setattr(mod, "_line", lambda user, srcip, outcome, ts, cfg:
                        events.append(("send", outcome, srcip, ts)) or real_line(user, srcip, outcome, ts, cfg))
    em = mod.Emitter(str(tmp_path / "auth.log"), False, mod.CONFIG,
                     sleep=lambda sec: events.append(("pause", sec)))
    return em, events


def _step(mod):
    n = mod.CONFIG["fail_threshold"] + mod.CONFIG["fail_margin"]
    return n, max(1, mod.CONFIG["burst_window_seconds"] // (n + 1))


def test_burst_pauses_between_every_line(mod, timeline):
    em, events = timeline
    n, step = _step(mod)
    mod.case_burst(em, mod.CONFIG)
    kinds = [e[0] for e in events]
    assert kinds == ["send", "pause"] * n + ["send"]
    assert all(e[1] == step for e in events if e[0] == "pause")


def test_burst_lines_are_stamped_when_written(mod, timeline):
    em, events = timeline
    before = dt_now(mod)
    mod.case_burst(em, mod.CONFIG)
    after = dt_now(mod)
    for _, _, _, ts in (e for e in events if e[0] == "send"):
        assert before <= ts <= after


def test_burst_threshold_fits_the_rule_timeframe(mod):
    n, step = _step(mod)
    # the threshold-th failure must arrive within 60s of the first
    assert (mod.CONFIG["fail_threshold"] - 1) * step < mod.CONFIG["burst_window_seconds"]
    # and each line has time to be enriched before the next one arrives
    assert step >= 5


def test_composite_baseline_is_hours_old_and_never_impossible_travel(mod, timeline):
    em, events = timeline
    mod.case_composite(em, mod.CONFIG)
    sends = [e for e in events if e[0] == "send"]
    baseline_ts = sends[0][3]
    first_fail_ts = sends[1][3]
    age_h = (first_fail_ts - baseline_ts).total_seconds() / 3600
    assert age_h >= mod.CONFIG["baseline_age_hours"]
    # half the Earth's circumference over that time stays under the 900 km/h rule threshold
    assert 20016 / age_h < 900


def test_composite_paces_burst_then_waits_before_the_success(mod, timeline):
    em, events = timeline
    n, step = _step(mod)
    mod.case_composite(em, mod.CONFIG)
    kinds = [e[0] if e[0] == "pause" else e[1] for e in events]
    assert kinds == ["success", "pause"] + ["fail", "pause"] * n + ["pause", "success"]
    pauses = [e[1] for e in events if e[0] == "pause"]
    assert pauses[-1] + pauses[-2] == mod.CONFIG["composite_success_delay_seconds"]


def test_composite_fits_the_rule_timeframe(mod):
    n, step = _step(mod)
    total = step + n * step + max(0, mod.CONFIG["composite_success_delay_seconds"] - step)
    assert total < 300


def test_composite_success_is_stamped_after_the_burst(mod, timeline):
    em, events = timeline
    mod.case_composite(em, mod.CONFIG)
    sends = [e for e in events if e[0] == "send"]
    fail_ts = [e[3] for e in sends if e[1] == "fail"]
    assert sends[-1][1] == "success"
    assert sends[-1][3] >= max(fail_ts)


def test_printed_window_leaves_time_for_enrichment(mod):
    end = "2026-11-17T09:44:51.382542+01:00"
    settled = mod._settled(end, mod.CONFIG)
    delta = mod.dt.datetime.fromisoformat(settled) - mod.dt.datetime.fromisoformat(end)
    assert delta.total_seconds() == mod.CONFIG["alert_settle_seconds"]


def dt_now(mod):
    return mod.dt.datetime.now()