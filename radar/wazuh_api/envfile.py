from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Optional

KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_LINE_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
_BARE_SAFE_RE = re.compile(r"^[A-Za-z0-9_@%+=:,./-]+$")
_DQ_ESCAPES = {"\\", '"', "$", "`"}
_FORBIDDEN = ("\r", "\n", "\x00")


def parse_value(raw: str) -> Optional[str]:
    raw = raw.strip()
    if raw.startswith("'"):
        end = raw.find("'", 1)
        if end < 0:
            return None
        rest = raw[end + 1:].strip()
        if rest and not rest.startswith("#"):
            return None
        return raw[1:end]
    if raw.startswith('"'):
        out = []
        i = 1
        while i < len(raw):
            ch = raw[i]
            if ch == "\\" and i + 1 < len(raw) and raw[i + 1] in _DQ_ESCAPES:
                out.append(raw[i + 1])
                i += 2
                continue
            if ch == '"':
                rest = raw[i + 1:].strip()
                if rest and not rest.startswith("#"):
                    return None
                return "".join(out)
            out.append(ch)
            i += 1
        return None
    return re.split(r"\s+#", raw, maxsplit=1)[0].strip()


def parse_line(line: str) -> Optional[tuple[str, str]]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    m = _LINE_RE.match(line)
    if not m:
        return None
    value = parse_value(m.group(2))
    if value is None:
        return None
    return m.group(1), value


def parse_text(text: str) -> dict:
    result = {}
    for line in text.splitlines():
        parsed = parse_line(line)
        if parsed:
            result[parsed[0]] = parsed[1]
    return result


def load(path) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    return parse_text(p.read_text(encoding="utf-8"))


def validate(key: str, value) -> str:
    if not KEY_RE.match(key or ""):
        raise ValueError(f"invalid .env key {key!r}")
    value = "" if value is None else str(value)
    if any(c in value for c in _FORBIDDEN):
        raise ValueError(f"{key}: value must not contain line breaks or NUL characters")
    return value


def format_value(value: str) -> str:
    if value == "" or _BARE_SAFE_RE.match(value):
        return value
    if "'" not in value:
        return f"'{value}'"
    escaped = "".join("\\" + c if c in _DQ_ESCAPES else c for c in value)
    return f'"{escaped}"'


def format_line(key: str, value) -> str:
    value = validate(key, value)
    return f"{key}={format_value(value)}"


def render(lines_in: list[str], updates: dict) -> list[str]:
    for k, v in updates.items():
        validate(k, v)
    out, written = [], set()
    for line in lines_in:
        m = _LINE_RE.match(line.strip())
        if m and m.group(1) in updates:
            k = m.group(1)
            if k in written:
                continue
            out.append(format_line(k, updates[k]))
            written.add(k)
        else:
            out.append(line.rstrip("\r\n"))
    for k, v in updates.items():
        if k not in written:
            out.append(format_line(k, v))
    return out


def write_atomic(path, text: str, mode: int = 0o600) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    owner = None
    if p.exists():
        st = p.stat()
        owner = (st.st_uid, st.st_gid)
    elif os.geteuid() == 0:
        st = p.parent.stat()
        owner = (st.st_uid, st.st_gid)
    fd, tmp = tempfile.mkstemp(prefix=f".{p.name}.", suffix=".tmp", dir=str(p.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        if owner and os.geteuid() == 0:
            os.chown(tmp, *owner)
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def update(path, updates: dict, mode: int = 0o600) -> None:
    p = Path(path)
    existing = p.read_text(encoding="utf-8").splitlines() if p.exists() else []
    write_atomic(p, "\n".join(render(existing, updates)) + "\n", mode=mode)


def write_filtered(path, env: dict, keys, mode: int = 0o600) -> None:
    lines = [format_line(k, env[k]) for k in keys if k in env]
    write_atomic(path, "\n".join(lines) + "\n", mode=mode)


def ensure_secret(path, key: str, nbytes: int = 32) -> str:
    import secrets as _secrets
    env = load(path)
    value = env.get(key, "")
    if not value:
        value = _secrets.token_hex(nbytes)
        update(path, {key: value})
    return value


def _cli(argv: list[str]) -> int:
    """python3 -m wazuh_api.envfile get KEY [FILE]
    python3 -m wazuh_api.envfile set KEY [FILE]   (value is read from stdin,
                                                   so it never shows in ps)
    python3 -m wazuh_api.envfile ensure-secret KEY [FILE]  (generates if unset;
                                                   prints nothing)"""
    if len(argv) >= 2 and argv[0] == "ensure-secret":
        ensure_secret(argv[2] if len(argv) > 2 else ".env", argv[1])
        return 0
    if len(argv) >= 2 and argv[0] in ("get", "set"):
        key = argv[1]
        path = argv[2] if len(argv) > 2 else ".env"
        if argv[0] == "get":
            env = load(path)
            if key not in env:
                return 1
            sys.stdout.write(env[key] + "\n")
            return 0
        value = sys.stdin.read()
        if value.endswith("\n"):
            value = value[:-1]
        try:
            update(path, {key: value})
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        return 0
    print(_cli.__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
