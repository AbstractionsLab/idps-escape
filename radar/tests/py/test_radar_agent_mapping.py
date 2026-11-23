"""Cross-checks for radar-agent/ar-scripts.yaml, the endpoint script catalog.

The bash parser in radar-agent/helpers/ar-mapping.sh handles a YAML subset and
the GUI reads the same file with PyYAML, so these tests confirm both readers
agree on the shipped catalog, and that the catalog stays consistent with
everything that names an active response: ossec snippets, ar.yaml and the
actions radar_ar.py knows how to target.
"""

import importlib.machinery
import importlib.util
import re
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
AGENT_DIR = REPO_ROOT / "radar-agent"
CATALOG = AGENT_DIR / "ar-scripts.yaml"
LIB = AGENT_DIR / "helpers" / "ar-mapping.sh"
BUILTINS = {"firewall-drop"}


def _bash_parse(path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", 'source "$1"; ar_mapping_parse "$2"', "_", str(LIB), str(path)],
        capture_output=True,
        text=True,
    )


def _catalog() -> dict:
    return yaml.safe_load(CATALOG.read_text())["scripts"] or {}


def _radar_ar():
    path = REPO_ROOT / "scenarios" / "active_responses" / "radar_ar.py"
    loader = importlib.machinery.SourceFileLoader("radar_ar_catalog_check", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_bash_parser_agrees_with_pyyaml_on_shipped_catalog():
    result = _bash_parse(CATALOG)
    assert result.returncode == 0, result.stderr
    parsed = [tuple(line.split("\t")) for line in result.stdout.splitlines()]
    assert parsed == list(_catalog().items())


def test_gui_loader_agrees_with_bash_parser_on_shipped_catalog():
    import sys
    sys.path.insert(0, str(REPO_ROOT / "gui"))
    from orchestrator import ar_config
    result = _bash_parse(CATALOG)
    assert ar_config.load_catalog(REPO_ROOT) == dict(
        line.split("\t") for line in result.stdout.splitlines()
    )


def test_every_listed_script_is_shipped_with_a_shebang():
    for name, rel in _catalog().items():
        script = AGENT_DIR / rel
        assert script.is_file(), f"{name} -> {rel} is missing from radar-agent/"
        assert script.read_text().startswith("#!"), f"{rel} has no shebang"


def test_catalog_names_are_exactly_the_shell_actions_radar_ar_can_target():
    supported = _radar_ar().SUPPORTED_MITIGATIONS
    catalog = set(_catalog())
    assert catalog <= supported, f"in the catalog but radar_ar.py cannot target: {catalog - supported}"
    assert supported - BUILTINS <= catalog, \
        f"radar_ar.py targets these but endpoints would not have them: {(supported - BUILTINS) - catalog}"


@pytest.mark.parametrize(
    "snippet",
    sorted((REPO_ROOT / "scenarios" / "ossec").glob("radar-*-ossec-snippet.xml")),
    ids=lambda p: p.name,
)
def test_snippet_shell_executables_are_in_the_catalog(snippet):
    executables = re.findall(r"<executable>\s*([^<\s]+\.sh)\s*</executable>", snippet.read_text())
    if not executables:
        pytest.skip("no shell active response in this snippet")
    for exe in executables:
        assert exe in _catalog(), f"{snippet.name} runs {exe}, which is not in ar-scripts.yaml"


def test_ar_yaml_mitigations_are_builtins_or_in_the_catalog():
    ar = yaml.safe_load((REPO_ROOT / "scenarios" / "active_responses" / "ar.yaml").read_text())
    allowed = BUILTINS | set(_catalog())
    for scenario, cfg in ar["scenarios"].items():
        for key in ("mitigations_tier2", "mitigations_tier3", "mitigations_tier4"):
            for m in cfg.get(key) or []:
                assert m in allowed, f"ar.yaml {scenario}.{key} uses {m}, which endpoints cannot run"


def test_scripts_are_no_longer_embedded_in_bootstrap():
    bootstrap = (AGENT_DIR / "bootstrap-agent.sh").read_text()
    assert "AR_SCRIPT_EOF" not in bootstrap
    assert "write_ar_script" not in bootstrap


def test_old_standalone_copies_are_gone():
    old = REPO_ROOT / "scenarios" / "active_responses"
    assert not (old / "lock_user_linux.sh").exists()
    assert not (old / "terminate_service.sh").exists()
