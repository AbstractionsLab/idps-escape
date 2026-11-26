"""The RADAR presentation page draws its numbers from docs/website/assets/radar-config.json.

That file is generated from ar.yaml, config.yaml, radar_ar.py and off_hours.py, so a
change to any of them must be followed by regenerating it. These tests fail when it is
stale, and check the facts the page's prose relies on.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
GENERATOR = REPO / "docs/website/tools/build_radar_config.py"
CONFIG_JSON = REPO / "docs/website/assets/radar-config.json"

pytestmark = pytest.mark.skipif(not GENERATOR.exists(), reason="docs/ not available (RADAR-only test container)")


def test_generated_config_is_up_to_date():
    result = subprocess.run([sys.executable, str(GENERATOR), "--check"], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr or result.stdout


def test_bundle_is_self_contained(tmp_path):
    out = tmp_path / "standalone.html"
    # Build the bundle without rewriting the committed data files
    sys.path.insert(0, str(GENERATOR.parent))
    try:
        import build_radar_config as gen
    finally:
        sys.path.pop(0)
    gen.bundle(out, gen.render()[gen.OUTPUT_JS])
    html = out.read_text(encoding="utf-8")
    assert "window.RADAR_CONFIG" in html
    assert 'src="assets/' not in html
    assert 'href="assets/' not in html
    assert "data:image/png;base64," in html


def test_page_example_scenario_is_hybrid_with_fusion_and_decipher():
    # radar-decipher.html walks a suspicious_login alert through fusion and DECIPHER
    s = json.loads(CONFIG_JSON.read_text(encoding="utf-8"))["scenarios"]["suspicious_login"]
    assert s["type"] == "hybrid"
    assert s["fusion"] is not None
    assert s["decipher_endpoint"]
    assert any(src["kind"] == "rcf" for src in s["anomaly_sources"])
    assert any("210013" in e.get("rule_ids", []) for e in s["signature_likelihood"])
