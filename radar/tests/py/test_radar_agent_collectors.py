"""Static checks on radar-agent/collectors/ and on the scripts that install
and remove them: the files of each collector must reference each other
consistently, and nothing may still be hard-coded in the bootstrapper or the
uninstaller."""

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
AGENT_DIR = REPO_ROOT / "radar-agent"
COLLECTORS = sorted(p for p in (AGENT_DIR / "collectors").iterdir() if p.is_dir())
DISPATCHER_MARKER = "# RADAR active response dispatcher."


def _files(c: Path, suffix: str) -> list[Path]:
    return sorted(c.glob(f"*{suffix}"))


def test_there_are_collectors():
    assert [c.name for c in COLLECTORS] == ["linux_resource_utilization", "log_volume"]


@pytest.mark.parametrize("c", COLLECTORS, ids=lambda p: p.name)
def test_collector_is_named_after_a_real_scenario(c):
    assert (REPO_ROOT / "scenarios" / "rules" / c.name).is_dir() or \
        (REPO_ROOT / "scenarios" / "ossec" / f"radar-{c.name.replace('_', '-')}-ossec-snippet.xml").is_file(), \
        f"collectors/{c.name} does not match any scenario"


@pytest.mark.parametrize("c", COLLECTORS, ids=lambda p: p.name)
def test_timers_point_at_a_service_of_the_same_collector(c):
    services = {p.name for p in _files(c, ".service")}
    timers = _files(c, ".timer")
    assert timers
    for t in timers:
        m = re.search(r"^Unit=(\S+)$", t.read_text(), re.M)
        assert m and m.group(1) in services, f"{t.name} must start a .service shipped next to it"
        assert re.search(r"^WantedBy=timers\.target$", t.read_text(), re.M), f"{t.name} cannot be enabled"


@pytest.mark.parametrize("c", COLLECTORS, ids=lambda p: p.name)
def test_services_run_a_script_of_the_same_collector(c):
    scripts = {p.name for p in _files(c, ".sh")}
    for s in _files(c, ".service"):
        m = re.search(r"^ExecStart=/usr/local/bin/(\S+)$", s.read_text(), re.M)
        assert m and m.group(1) in scripts, f"{s.name} must run a script shipped next to it"


@pytest.mark.parametrize("c", COLLECTORS, ids=lambda p: p.name)
def test_logrotate_rotates_the_log_the_script_writes(c):
    written = set()
    for sh in _files(c, ".sh"):
        written |= set(re.findall(r'^LOG_FILE="(/var/log/radar/[^"]+)"$', sh.read_text(), re.M))
    assert written
    for lr in _files(c, ".logrotate"):
        rotated = set(re.findall(r"^(/var/log/radar/\S+)\s*\{", lr.read_text(), re.M))
        assert rotated and rotated <= written, f"{lr.name} rotates {rotated}, scripts write {written}"


@pytest.mark.parametrize("c", COLLECTORS, ids=lambda p: p.name)
def test_scripts_have_a_shebang_and_strict_mode(c):
    for sh in _files(c, ".sh"):
        text = sh.read_text()
        assert text.startswith("#!/usr/bin/env bash\n")
        assert "set -euo pipefail" in text


def test_bootstrapper_embeds_no_files_any_more():
    text = (AGENT_DIR / "bootstrap-agent.sh").read_text()
    heredocs = re.findall(r"<<-?\s*'?\"?[A-Z_]+'?\"?\s*$", text, re.M)
    assert heredocs == [], f"heredocs left in bootstrap-agent.sh: {heredocs}"
    assert "cat >" not in text


@pytest.mark.parametrize("script", ["bootstrap-agent.sh", "uninstall-agent.sh"])
def test_no_collector_names_are_hard_coded(script):
    text = (AGENT_DIR / script).read_text()
    for c in COLLECTORS:
        for f in c.iterdir():
            stem = f.name.split(".")[0]
            assert stem not in text, f"{script} still names {stem}; it must follow collectors/"


def test_yum_repo_is_shipped_and_used():
    repo = (AGENT_DIR / "packaging" / "wazuh.repo").read_text()
    assert repo.startswith("[wazuh]\n") and "gpgcheck=1" in repo and "packages.wazuh.com" in repo
    assert "packaging/wazuh.repo" in (AGENT_DIR / "bootstrap-agent.sh").read_text()


def test_dispatcher_marker_is_the_same_everywhere():
    dispatcher = (AGENT_DIR / "helpers" / "ar-dispatch.sh").read_text().splitlines()
    assert dispatcher[1] == DISPATCHER_MARKER
    for script in ("bootstrap-agent.sh", "uninstall-agent.sh"):
        assert f'AR_DISPATCHER_MARKER="{DISPATCHER_MARKER}"' in (AGENT_DIR / script).read_text()
