from __future__ import annotations

import re
import datetime as dt
from pathlib import Path
from typing import Any, Dict, Optional
import os

try:
    import yaml
except Exception:
    yaml = None

_SYSLOG_RE = re.compile(r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b")
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\b")


def load_config() -> Dict[str, Any]:
    """Load radar/config.yaml and return the full mapping."""
    if yaml is None:
        raise RuntimeError("PyYAML is not installed. Install with: pip3 install pyyaml")

    env_path = os.environ.get("RADAR_CONFIG")
    if env_path:
        cfg_path = Path(env_path)
    else:
        p = Path(__file__).resolve().parent
        cfg_path = None
        for candidate in [p / "config.yaml", *[anc / "config.yaml" for anc in p.parents]]:
            if candidate.exists():
                cfg_path = candidate
                break
        if cfg_path is None:
            raise FileNotFoundError(f"config.yaml not found in {p} or any parent directory.")

    with cfg_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError("config.yaml must contain a YAML mapping at top-level.")
    return data


def get_scenario(cfg: Dict[str, Any], scenario: str) -> Dict[str, Any]:
    """Return the scenario sub-tree, raising clearly if absent."""
    try:
        return cfg["scenarios"][scenario]
    except KeyError:
        raise KeyError(
            f"config.yaml is missing scenarios.{scenario}. "
            "Make sure you are using the unified radar/config.yaml."
        )


def get_scenario_simulate(cfg: Dict[str, Any], scenario: str) -> Dict[str, Any]:
    """Return scenarios.<scenario>.simulate, raising clearly if absent."""
    sc = get_scenario(cfg, scenario)
    try:
        return sc["simulate"]
    except KeyError:
        raise KeyError(
            f"config.yaml scenarios.{scenario} is missing a 'simulate' sub-key."
        )


def get_scenario_ingest(cfg: Dict[str, Any], scenario: str) -> Dict[str, Any]:
    """Return scenarios.<scenario>.ingest, raising clearly if absent."""
    sc = get_scenario(cfg, scenario)
    try:
        return sc["ingest"]
    except KeyError:
        raise KeyError(
            f"config.yaml scenarios.{scenario} is missing an 'ingest' sub-key."
        )


def iso_with_offset(ts: dt.datetime, offset: str, micros: int = 227122) -> str:
    base = ts.replace(microsecond=micros).strftime("%Y-%m-%dT%H:%M:%S.%f")
    return f"{base}{offset}"


def append_line_authlog(line: str, auth_log_path: str, sudo_tee: bool) -> None:
    import subprocess

    cmd = ["tee", "-a", auth_log_path]
    if sudo_tee:
        cmd = ["sudo"] + cmd
    subprocess.run(cmd, input=(line + "\n").encode("utf-8"), stdout=subprocess.DEVNULL, check=True)


def detect_authlog_timestamp_format(
    ts: Optional[dt.datetime],
    tz_offset: str,
    auth_log_path: str,
    max_lines: int = 200,
    micros: int = 227122,
) -> str:
    """Return a formatted timestamp string matching the existing auth log format."""
    ts = ts or dt.datetime.now()
    fmt = "syslog"
    p = Path(auth_log_path)

    if p.exists():
        try:
            with p.open("rb") as f:
                data = f.read(64 * 1024)
            lines_seen = 0
            for raw in data.splitlines():
                if lines_seen >= max_lines:
                    break
                line = raw.decode("utf-8", errors="ignore").strip()
                if not line:
                    continue
                lines_seen += 1
                if _SYSLOG_RE.match(line):
                    fmt = "syslog"
                    break
                if _ISO_RE.match(line):
                    fmt = "iso"
                    break
        except Exception:
            pass

    if fmt == "iso":
        base = ts.replace(microsecond=micros).strftime("%Y-%m-%dT%H:%M:%S.%f")
        return f"{base}{tz_offset}"

    return ts.strftime("%b %d %H:%M:%S")


def load_dotenv(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    out = {}
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def find_repo_root(start: Path) -> Path:
    p = start.resolve()
    for _ in range(12):
        if (p / "inventory.yaml").exists():
            return p
        if p.parent == p:
            break
        p = p.parent
    raise FileNotFoundError("Could not find repo root containing inventory.yaml")