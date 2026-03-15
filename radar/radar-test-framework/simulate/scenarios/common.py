from __future__ import annotations

import re
import datetime as dt
from pathlib import Path
from typing import Any, Dict

try:
    import yaml
except Exception:
    yaml = None

_SYSLOG_RE = re.compile(r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b")
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\b")


def load_config() -> Dict[str, Any]:
    if yaml is None:
        raise RuntimeError("PyYAML is not installed. Install with: pip3 install pyyaml")
    cfg_path = Path(__file__).resolve().parent / "config.yaml"
    with cfg_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError("config.yaml must contain a YAML mapping/object at top-level.")
    return data


def iso_with_offset(ts: dt.datetime, offset: str, micros: int = 227122) -> str:
    base = ts.replace(microsecond=micros).strftime("%Y-%m-%dT%H:%M:%S.%f")
    return f"{base}{offset}"


def append_line_authlog(line: str, auth_log_path: str, sudo_tee: bool) -> None:
    import subprocess

    cmd = ["tee", "-a", auth_log_path]
    if sudo_tee:
        cmd = ["sudo"] + cmd
    subprocess.run(cmd, input=(line + "\n").encode("utf-8"), stdout=subprocess.DEVNULL, check=True)


def detect_authlog_timestamp_format(ts: Optional[dt.datetime], tz_offset: str, auth_log_path: str, max_lines: int = 200) -> str:
    ts = ts or dt.datetime.now()
    fmt = "syslog"
    p = Path(auth_log_path)

    if p.exists():
        try:
            with p.open("rb") as f:
                data = f.read(64 * 1024)
            for raw in data.splitlines():
                line = raw.decode("utf-8", errors="ignore").strip()
                if not line:
                    continue
                if _SYSLOG_RE.match(line):
                    fmt = "syslog"
                    break
                if _ISO_RE.match(line):
                    fmt = "iso"
                    break
        except Exception:
            pass

    if fmt == "iso":
        base = ts.replace(microsecond=227122).strftime("%Y-%m-%dT%H:%M:%S.%f")
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