#!/usr/bin/env python3
"""Generate the RADAR presentation page's data from RADAR's own configuration.

The RADAR presentation page (radar-decipher.html) draws its tables and charts
from this data, so weights, tiers, mitigations, detectors and DECIPHER endpoints
follow the code instead of being copied by hand. Two files carry the same data:

  docs/website/assets/radar-config.json   the readable, diffable copy
  docs/website/assets/radar-config.js     the same object as window.RADAR_CONFIG, which the
                                          page loads with <script>, so it also works from file://

Sources:
  radar/scenarios/active_responses/ar.yaml   risk weights, tiers, mitigations, fusion, rule IDs
  radar/config.yaml                          anomaly detectors (RCF) and off-hours modes
  radar/scenarios/active_responses/radar_ar.py   DECIPHER endpoints, tier priority, never_block defaults
  radar/anomaly_detector/off_hours.py        off-hours monitor, detector and feature names

The Python sources are parsed with `ast`, never imported, so this runs without
RADAR's runtime environment.

Usage (from the repository root):
  python docs/website/tools/build_radar_config.py                   # write both data files
  python docs/website/tools/build_radar_config.py --check           # exit 1 if either is stale
  python docs/website/tools/build_radar_config.py --bundle OUT.html # also write a single-file page

The bundle inlines the stylesheet, scripts, data and images, and points relative
links at the published site, so it can be opened anywhere or sent as one file.
It is a snapshot: rebuild it after regenerating the data.
"""

import argparse
import ast
import base64
import json
import re
import logging
import sys
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

REPO = Path(__file__).resolve().parents[3]
AR_YAML = REPO / "radar/scenarios/active_responses/ar.yaml"
CONFIG_YAML = REPO / "radar/config.yaml"
RADAR_AR = REPO / "radar/scenarios/active_responses/radar_ar.py"
OFF_HOURS = REPO / "radar/anomaly_detector/off_hours.py"
WEBSITE = REPO / "docs/website"
OUTPUT_JSON = WEBSITE / "assets/radar-config.json"
OUTPUT_JS = WEBSITE / "assets/radar-config.js"
PAGE = WEBSITE / "radar-decipher.html"
SITE_URL = "https://abstractionslab.github.io/idps-escape/website/"


def _class_constants(path: Path, class_name: str, names: set[str]) -> dict[str, Any]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            out = {}
            for stmt in node.body:
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                    if stmt.targets[0].id in names:
                        out[stmt.targets[0].id] = ast.literal_eval(stmt.value)
            missing = names - out.keys()
            if missing:
                raise SystemExit(f"{path}: {class_name} lacks {sorted(missing)}")
            return out
    raise SystemExit(f"{path}: class {class_name} not found")


def _module_constant(path: Path, name: str) -> Any:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name) and stmt.targets[0].id == name:
            return ast.literal_eval(stmt.value)
    raise SystemExit(f"{path}: module constant {name} not found")


def _ids(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


def _likelihood(raw: Any) -> list[dict[str, Any]]:
    """Normalise signature_likelihood: a scalar or a list of rule_id / rule_group entries."""
    if isinstance(raw, (int, float)):
        return [{"default": float(raw)}] if raw else []
    out = []
    for entry in raw or []:
        item = {"weight": float(entry.get("weight", 0.0))}
        if "rule_id" in entry:
            item["rule_ids"] = _ids(entry["rule_id"])
        if "rule_group" in entry:
            item["rule_groups"] = _ids(entry["rule_group"])
        out.append(item)
    return out


def _detection_type(ad_ids: list[str], sig_ids: list[str], sig_groups: list[str]) -> str:
    has_ad = bool(ad_ids)
    has_sig = bool(sig_ids or sig_groups)
    if has_ad and has_sig:
        return "hybrid"
    return "anomaly" if has_ad else "signature"


def _anomaly_sources(name: str, scfg: dict[str, Any], oh: dict[str, Any]) -> list[dict[str, Any]]:
    """The anomaly detection behind a scenario's AD rule IDs, from radar/config.yaml."""
    off_hours = scfg.get("off_hours")
    if off_hours:
        modes = {g.get("mode") for g in (off_hours.get("groups") or {}).values()}
        out = []
        if "rule" in modes:
            rm = off_hours.get("rule_mode") or {}
            out.append({"kind": "query monitor", "name": oh["RULE_MONITOR_NAME"], "entity": "radar.user", "interval_minutes": rm.get("interval_minutes"), "note": "Declared working hours; fixed grade and confidence"})
        if "model" in modes:
            mm = off_hours.get("model_mode") or {}
            out.append({"kind": "rcf", "name": oh["MODEL_DETECTOR_NAME"], "entity": "radar.user", "interval_minutes": mm.get("interval_minutes"), "features": [oh["MODEL_FEATURE"]], "note": "Per-user baseline of off-hours activity"})
        return out
    if "features" in scfg:
        return [
            {
                "kind": "rcf",
                "name": f"{name.upper()}_DETECTOR",
                "entity": scfg.get("categorical_field"),
                "interval_minutes": scfg.get("detector_interval"),
                "features": [f["feature_name"] for f in scfg["features"] if f.get("feature_enabled", True)],
                "note": scfg.get("description", ""),
            }
        ]
    return []


def build() -> dict[str, Any]:
    ar = yaml.safe_load(AR_YAML.read_text(encoding="utf-8"))
    cfg = yaml.safe_load(CONFIG_YAML.read_text(encoding="utf-8")).get("scenarios") or {}
    decipher = _class_constants(RADAR_AR, "DecipherClient", {"ANALYZE_ENDPOINTS", "HEALTH_ENDPOINT", "INCIDENT_ENDPOINT", "TIER_PRIORITY"})
    never_block = _class_constants(RADAR_AR, "NeverBlock", {"DEFAULTS"})["DEFAULTS"]
    oh = {k: _module_constant(OFF_HOURS, k) for k in ("RULE_MONITOR_NAME", "MODEL_DETECTOR_NAME", "MODEL_FEATURE")}

    scenarios = {}
    for name, s in (ar.get("scenarios") or {}).items():
        ad_ids = _ids((s.get("ad") or {}).get("rule_ids"))
        sig = s.get("signature") or {}
        sig_ids, sig_groups = _ids(sig.get("rule_ids")), _ids(sig.get("rule_groups"))
        tiers = s.get("tiers") or {}
        fusion = s.get("fusion") or {}
        scenarios[name] = {
            "type": _detection_type(ad_ids, sig_ids, sig_groups),
            "weights": {"A": float(s.get("w_ad", 0.0)), "S": float(s.get("w_sig", 0.0)), "T": float(s.get("w_cti", 0.0))},
            "tiers": [float(tiers.get("tier1_min", 0.0)), float(tiers.get("tier1_max", 0.0)), float(tiers.get("tier2_max", 0.0))],
            "mitigations": {"tier2": [str(m) for m in s.get("mitigations_tier2") or []], "tier3": [str(m) for m in s.get("mitigations_tier3") or []]},
            "allow_mitigation": bool(s.get("allow_mitigation", False)),
            "signature_impact": float(s.get("signature_impact", 0.0)),
            "signature_likelihood": _likelihood(s.get("signature_likelihood")),
            "signature_rule_ids": sig_ids,
            "signature_rule_groups": sig_groups,
            "ad_rule_ids": ad_ids,
            "anomaly_sources": _anomaly_sources(name, cfg.get(name) or {}, oh) if ad_ids else [],
            "fusion": {"window_minutes": fusion.get("window_minutes"), "ad_lead_minutes": fusion.get("ad_lead_minutes")} if fusion.get("enabled") else None,
            "decipher_endpoint": decipher["ANALYZE_ENDPOINTS"].get(name),
        }

    return {
        "_generated": "Do not edit. Regenerate with: python docs/website/tools/build_radar_config.py",
        "scenarios": scenarios,
        "decipher": {
            "health": decipher["HEALTH_ENDPOINT"],
            "incident": decipher["INCIDENT_ENDPOINT"],
            "tier_priority": {str(k): v for k, v in sorted(decipher["TIER_PRIORITY"].items())},
        },
        "never_block_defaults": list(never_block),
    }


def render() -> dict[Path, str]:
    data = json.dumps(build(), indent=2, ensure_ascii=False)
    js = "// Generated by docs/website/tools/build_radar_config.py from RADAR's config. Do not edit.\nwindow.RADAR_CONFIG = " + data + ";\n"
    return {OUTPUT_JSON: data + "\n", OUTPUT_JS: js}


def _inline_script(text: str) -> str:
    # A literal </script> inside inlined code would end the element early
    return re.sub(r"</(script)", r"<\\/\1", text, flags=re.IGNORECASE)


def _data_uri(path: Path) -> str:
    mime = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".svg": "image/svg+xml"}[path.suffix.lower()]
    return f"data:{mime};base64," + base64.b64encode(path.read_bytes()).decode("ascii")


def bundle(out: Path, js_config: str) -> None:
    """Write radar-decipher.html as one file: no server, no sibling assets."""
    html = PAGE.read_text(encoding="utf-8")

    def css(m: re.Match) -> str:
        return "<style>\n" + (WEBSITE / m.group(1)).read_text(encoding="utf-8") + "\n</style>"

    def script(m: re.Match) -> str:
        src = m.group(1)
        body = js_config if src == "assets/radar-config.js" else (WEBSITE / src).read_text(encoding="utf-8")
        return "<script>\n" + _inline_script(body) + "\n</script>"

    html = re.sub(r'<link href="(assets/[^"]+\.css)" rel="stylesheet">', css, html)
    html = re.sub(r'<script src="(assets/[^"]+\.js)"[^>]*></script>', script, html)
    html = re.sub(r'src="(assets/[^"]+)"', lambda m: f'src="{_data_uri(WEBSITE / m.group(1))}"', html)
    # Remaining relative links (other pages, full-size images) go to the published site
    html = re.sub(r'href="(?!https?:|#|data:)([^"]+)"', lambda m: f'href="{SITE_URL}{m.group(1)}"', html)
    left = re.findall(r'(?:src|href)="(assets/[^"]+)"', html)
    if left:
        raise SystemExit(f"bundle: references left unresolved: {left}")
    out.write_text(html, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if the committed data files differ from the generated ones")
    parser.add_argument("--bundle", type=Path, metavar="OUT", help="also write a single-file copy of radar-decipher.html to OUT")
    args = parser.parse_args(argv)
    files = render()
    if args.check:
        stale = [p for p, text in files.items() if not p.exists() or p.read_text(encoding="utf-8") != text]
        for p in stale:
            logger.error("%s is stale; run: python docs/website/tools/build_radar_config.py", p.relative_to(REPO))
        if not stale:
            logger.info("data files are up to date")
        return 1 if stale else 0
    for p, text in files.items():
        p.write_text(text, encoding="utf-8")
        logger.info("wrote %s", p.relative_to(REPO))
    if args.bundle:
        bundle(args.bundle, files[OUTPUT_JS])
        logger.info("wrote %s", args.bundle)
    return 0


if __name__ == "__main__":
    sys.exit(main())
