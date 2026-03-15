"""
c5browser.py — Interactive C5-DEC Doorstop item browser for specifications.

Reads all Doorstop item files from docs/specs/ subdirectories, auto-discovering
document types and their relations from .doorstop.yml files, and generates a
standalone Bootstrap + DataTables HTML page with one sortable/filterable table
per document type.  Both Markdown-frontmatter (.md) and pure-YAML (.yml) item
formats are supported.

Configuration is loaded from c5browser_config.yaml (alongside this script).
All tuneable constants — numeric fields, defect badges/labels, and the static
doc-type fallback list — live there so users never need to edit this file.

Usage:
    poetry run python c5browser.py                        # default output
    poetry run python c5browser.py --output path/to/out.html
    poetry run python c5browser.py --specs-dir path/to/specs/
    poetry run python c5browser.py --config path/to/c5browser_config.yaml
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import yaml as _yaml
    _YAML = True
except ImportError:
    _YAML = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = SCRIPT_DIR / "c5browser_config.yaml"

BOOTSTRAP_CSS = "https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"
BOOTSTRAP_JS = "https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"
JQUERY_JS = "https://code.jquery.com/jquery-3.7.0.min.js"
DT_CSS = "https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css"
DT_JS = "https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"
DT_BS5_JS = "https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js"

# _NAMED_PATTERN matches items like MRS-ADBox, SRS-SONAR — non-numeric UIDs
_NAMED_PATTERN = re.compile(r"^[A-Z]+-[A-Za-z]", re.ASCII)

# Fields that should be sorted/rendered as numbers in the browser table
# (used as built-in fallback when no config file is available)
_DEFAULT_NUMERIC_FIELDS = {
    "urgency", "importance", "difficulty", "risk", "complexity",
    "passed-steps", "failed-steps", "not-executed-steps",
    "passed_steps", "failed_steps", "not_executed_steps",
}

# Document type → (subdirectory, ordered list of (column_key, display_label, sortable_type))
# Kept as a static fallback; at runtime the list is replaced by discover_doc_types() or config.
# sortable_type: "str" | "num" (numeric string columns are coerced to int for sorting)
_DEFAULT_DOC_TYPES = [
    ("MRS",  "mrs",  [
        ("uid",         "UID",          "str"),
        ("title",       "Title",        "str"),
        ("type",        "Type",         "str"),
        ("urgency",     "Urgency",      "num"),
        ("importance",  "Importance",   "num"),
        ("release",     "Release",      "str"),
        ("vm",          "VM",           "str"),
        ("active",      "Active",       "str"),
        ("_parents",    "Parent links", "str"),
    ]),
    ("HARC", "harc", [
        ("uid",         "UID",          "str"),
        ("title",       "Title",        "str"),
        ("active",      "Active",       "str"),
        ("_parents",    "Parent links", "str"),
    ]),
    ("SRS",  "srs",  [
        ("uid",         "UID",          "str"),
        ("title",       "Title",        "str"),
        ("urgency",     "Urgency",      "num"),
        ("importance",  "Importance",   "num"),
        ("difficulty",  "Difficulty",   "num"),
        ("risk",        "Risk",         "num"),
        ("status",      "Status",       "str"),
        ("release",     "Release",      "str"),
        ("version",     "Version",      "str"),
        ("active",      "Active",       "str"),
        ("_parents",    "Parent links", "str"),
    ]),
    ("LARC", "larc", [
        ("uid",         "UID",          "str"),
        ("title",       "Title",        "str"),
        ("release",     "Release",      "str"),
        ("version",     "Version",      "str"),
        ("active",      "Active",       "str"),
        ("_parents",    "Parent links", "str"),
    ]),
    ("SWD",  "swd",  [
        ("uid",         "UID",          "str"),
        ("title",       "Title",        "str"),
        ("version",     "Version",      "str"),
        ("active",      "Active",       "str"),
        ("_parents",    "Parent links", "str"),
    ]),
    ("TCS",  "tcs",  [
        ("uid",                 "UID",                  "str"),
        ("title",               "Title",                "str"),
        ("complexity",          "Complexity",           "num"),
        ("execution_type",      "Exec type",            "str"),
        ("verification_method", "Verif. method",        "str"),
        ("authors",             "Authors",              "str"),
        ("platform",            "Platform",             "str"),
        ("release",             "Release",              "str"),
        ("version",             "Version",              "str"),
        ("active",              "Active",               "str"),
        ("_parents",            "Parent links",         "str"),
    ]),
    ("TRP",  "trp",  [
        ("uid",         "UID",          "str"),
        ("title",       "Title",        "str"),
        ("defect-category",     "Defect",           "str"),
        ("passed-steps",        "Passed",           "num"),
        ("failed-steps",        "Failed",           "num"),
        ("not-executed-steps",  "Not exec.",        "num"),
        ("tester",              "Tester",           "str"),
        ("test-date",           "Test date",        "str"),
        ("release",             "Release",          "str"),
        ("active",              "Active",           "str"),
        ("_parents",            "Parent links",     "str"),
    ]),
]

# Defect level → CSS class for badge colouring
_DEFAULT_DEFECT_BADGE_CSS = {
    "?c5-defect-0": "bg-success",
    "?c5-defect-1": "bg-success",
    "?c5-defect-2": "bg-warning text-dark",
    "?c5-defect-3": "bg-danger",
    "?c5-defect-4": "bg-danger",
}
_DEFAULT_DEFECT_LABELS = {
    "?c5-defect-0": "0 — flawless",
    "?c5-defect-1": "1 — insignificant",
    "?c5-defect-2": "2 — minor",
    "?c5-defect-3": "3 — major",
    "?c5-defect-4": "4 — critical",
}

# ---------------------------------------------------------------------------
# Configuration loading
# ---------------------------------------------------------------------------

def load_config(config_path: Path) -> dict:
    """
    Load c5browser_config.yaml and return a normalised config dict with keys:
      numeric_fields   : set[str]
      defect_badge_css : dict[str, str]
      defect_labels    : dict[str, str]
      doc_types        : list of (prefix, subdir, [(key, label, type), ...])

    Falls back to built-in _DEFAULT_* values for any missing section, or
    entirely when pyyaml is unavailable or the file is absent.
    """
    defaults = {
        "numeric_fields": _DEFAULT_NUMERIC_FIELDS,
        "defect_badge_css": _DEFAULT_DEFECT_BADGE_CSS,
        "defect_labels": _DEFAULT_DEFECT_LABELS,
        "doc_types": _DEFAULT_DOC_TYPES,
    }

    if not _YAML:
        print(
            "WARNING: pyyaml not available — cannot read config file; "
            "using built-in defaults.",
            file=sys.stderr,
        )
        return defaults

    if not config_path.exists():
        print(
            f"INFO: config file not found at {config_path}; using built-in defaults.",
            file=sys.stderr,
        )
        return defaults

    try:
        raw = _yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        print(
            f"WARNING: could not parse config file {config_path}: {exc}; "
            "using built-in defaults.",
            file=sys.stderr,
        )
        return defaults

    numeric_fields = set(raw.get("numeric_fields") or []) or _DEFAULT_NUMERIC_FIELDS
    defect_badge_css = raw.get("defect_badge_css") or _DEFAULT_DEFECT_BADGE_CSS
    defect_labels = raw.get("defect_labels") or _DEFAULT_DEFECT_LABELS
    raw_doc_types = raw.get("doc_types")
    doc_types = (
        _parse_doc_types_from_config(raw_doc_types)
        if raw_doc_types
        else _DEFAULT_DOC_TYPES
    )

    return {
        "numeric_fields": numeric_fields,
        "defect_badge_css": defect_badge_css,
        "defect_labels": defect_labels,
        "doc_types": doc_types,
    }


def _parse_doc_types_from_config(raw: list) -> list:
    """
    Convert the doc_types list from the YAML config into the
    (prefix, subdir, [(key, label, type), ...]) tuple format used internally.
    """
    result = []
    for entry in raw:
        prefix = str(entry.get("prefix", "")).strip()
        subdir = str(entry.get("subdir", prefix.lower())).strip()
        cols = []
        for col in entry.get("columns", []):
            key = str(col.get("key", "")).strip()
            label = str(col.get("label", key)).strip()
            ctype = str(col.get("type", "str")).strip()
            if key:
                cols.append((key, label, ctype))
        if prefix:
            result.append((prefix, subdir, cols))
    return result


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _uid_sort_key(uid: str):
    parts = uid.rsplit("-", 1)
    if len(parts) == 2:
        try:
            return (parts[0], int(parts[1]))
        except ValueError:
            return (parts[0], parts[1])
    return (uid, "")


def parse_item(path: Path) -> dict:
    """
    Parse a single Doorstop item file (.md Markdown frontmatter or .yml pure YAML).

    Returns a dict containing:
      - all item fields (str values, stripped)
      - 'uid'      : stem of the file (e.g. 'SRS-001')
      - 'title'    : H1 heading (Markdown items) or 'header' field (YAML items), or ''
      - '_parents' : comma-separated list of parent UIDs extracted from 'links:'
      - '_named'   : True when the UID is a named/group item (e.g. MRS-ADBox)
      - '_path'    : absolute path to the source file
    """
    uid = path.stem
    content = path.read_text(encoding="utf-8")

    if path.suffix == ".yml":
        item = _parse_yaml_item(uid, content)
    else:
        item = _parse_md_item(uid, content)

    item["_named"] = bool(_NAMED_PATTERN.match(uid))
    item["_path"] = str(path)
    return item


def _parse_md_item(uid: str, content: str) -> dict:
    """Parse a Markdown-format Doorstop item (YAML frontmatter + body)."""
    fm: dict = {}
    body = content

    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            raw_fm = parts[1]
            body = parts[2]
            if _YAML:
                fm = _yaml.safe_load(raw_fm) or {}
            else:
                str_fm: dict = {}
                _parse_yaml_block(raw_fm, str_fm)
                fm = str_fm

    # Extract H1 title from body
    title = ""
    for line in body.splitlines():
        m = re.match(r"^#\s+(.+)", line)
        if m:
            title = m.group(1).strip()
            break

    # Extract parent UIDs from links — pyyaml gives a list of dicts
    parents: list[str] = []
    links_val = fm.get("links", [])
    if isinstance(links_val, list):
        for entry in links_val:
            if isinstance(entry, dict):
                parents.extend(entry.keys())
            elif isinstance(entry, str):
                m2 = re.match(r"([A-Z]+-[A-Za-z0-9]+)", entry)
                if m2:
                    parents.append(m2.group(1))
    elif isinstance(links_val, str):
        for m2 in re.finditer(r"-\s+([A-Z]+-[A-Za-z0-9]+)", links_val):
            parents.append(m2.group(1))

    # Flatten scalar fields to str for display
    item: dict = {}
    for k, v in fm.items():
        if k in ("links", "text", "ref", "reviewed"):
            continue
        item[k] = str(v).strip() if v is not None else ""

    item["uid"] = uid
    item["title"] = title
    item["_parents"] = ", ".join(parents)
    return item


def _parse_yaml_item(uid: str, content: str) -> dict:
    """Parse a pure-YAML-format Doorstop item."""
    raw: dict = {}
    if _YAML:
        raw = _yaml.safe_load(content) or {}
    else:
        # Minimal fallback: parse scalar key: value lines only
        for line in content.splitlines():
            if ":" in line and not line.startswith(" ") and not line.startswith("-"):
                k, _, v = line.partition(":")
                raw[k.strip()] = v.strip().strip("'\"")

    # Flatten everything to str for display
    item: dict[str, str] = {}
    for k, v in raw.items():
        if k in ("links", "text", "ref", "reviewed"):
            continue  # handled separately below
        item[k] = str(v).strip() if v is not None else ""

    # Title from 'header' field, falling back to first line of 'text'
    title = str(raw.get("header", "")).strip()
    if not title:
        text_val = str(raw.get("text", "")).strip()
        title = text_val.splitlines()[0].lstrip("# ").strip() if text_val else ""

    # Extract parent UIDs from links list [{"PREFIX-NNN": "hash"}, ...]
    parents: list[str] = []
    links_val = raw.get("links", [])
    if isinstance(links_val, list):
        for entry in links_val:
            if isinstance(entry, dict):
                parents.extend(entry.keys())
            elif isinstance(entry, str):
                m = re.match(r"([A-Z]+-[A-Za-z0-9]+)", entry)
                if m:
                    parents.append(m.group(1))
    elif isinstance(links_val, str):
        for m2 in re.finditer(r"-\s+([A-Z]+-[A-Za-z0-9]+)", links_val):
            parents.append(m2.group(1))

    item["uid"] = uid
    item["title"] = title
    item["_parents"] = ", ".join(parents)
    return item


def _parse_yaml_block(raw: str, out: dict) -> None:
    """
    Minimal YAML parser: handles scalar key: value pairs and multi-line lists
    (the '- item' format used for links).  Does not handle nested mappings.
    Values are lightly cleaned — outer quotes stripped, newlines replaced with space.
    """
    current_key: str | None = None
    list_buffer: list[str] = []

    for line in raw.splitlines():
        # List continuation for multi-line values (links), indented with spaces
        if current_key and line.startswith("  ") and line.lstrip().startswith("-"):
            list_buffer.append(line.strip())
            continue

        # Key: value — flush previous accumulation inline (avoids closure rebinding bug)
        if ":" in line and not line.startswith(" "):
            if current_key and list_buffer:
                out[current_key] = " ".join(list_buffer).strip()
            k, _, v = line.partition(":")
            current_key = k.strip()
            val = v.strip().strip("'\"")
            list_buffer = [val] if val else []
        elif line.startswith("- ") and current_key:
            list_buffer.append(line.strip())

    # Flush the last key
    if current_key and list_buffer:
        out[current_key] = " ".join(list_buffer).strip()


def discover_doc_types(specs_dir: Path, numeric_fields: set) -> list:
    """
    Auto-discover document types by reading every .doorstop.yml found directly
    under *specs_dir* (one level deep).  Returns a DOC_TYPES-compatible list
    of ``(prefix, subdir, columns)`` tuples, topologically sorted
    (parent documents before their children).

    Column definitions are derived from ``attributes.publish`` (preferred) or
    ``attributes.defaults`` in each document's .doorstop.yml, with ``uid``,
    ``title``, ``active``, and ``_parents`` always included.

    Parameters
    ----------
    specs_dir : Path
        Root directory containing Doorstop subdirectories.
    numeric_fields : set
        Field names that should be treated as numeric (loaded from config).
    """
    if not _YAML:
        print(
            "WARNING: pyyaml not available — cannot auto-discover doc types; "
            "falling back to config/built-in doc_types.",
            file=sys.stderr,
        )
        return []

    def _to_label(key: str) -> str:
        s = key.replace("_", " ").replace("-", " ")
        return s[0].upper() + s[1:] if s else s

    docs: dict[str, dict] = {}  # prefix -> info dict

    for yml_file in sorted(specs_dir.glob("*/.doorstop.yml")):
        subdir = yml_file.parent.name
        try:
            data = _yaml.safe_load(yml_file.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            print(f"  Warning: could not read {yml_file}: {exc}", file=sys.stderr)
            continue

        settings = data.get("settings", {})
        prefix = settings.get("prefix")
        parent = settings.get("parent")
        if not prefix:
            continue

        attrs = data.get("attributes", {})
        publish_list: list[str] = [
            k for k in (attrs.get("publish") or []) if isinstance(k, str)
        ]
        defaults_keys: list[str] = [
            k for k in (attrs.get("defaults") or {}).keys()
            if k not in ("text", "header", "references")
        ]

        # Use publish list when available; fall back to defaults keys
        col_keys = publish_list or defaults_keys

        docs[prefix] = {
            "subdir": subdir,
            "parent": parent,
            "col_keys": col_keys,
        }

    if not docs:
        return []

    # Topological sort: parents before children
    ordered: list[str] = []
    visiting: set[str] = set()

    def _visit(pfx: str) -> None:
        if pfx in visiting or pfx not in docs:
            return
        visiting.add(pfx)
        par = docs[pfx].get("parent")
        if par:
            _visit(par)
        ordered.append(pfx)

    for pfx in sorted(docs.keys()):
        _visit(pfx)

    # Build DOC_TYPES-compatible tuples
    result = []
    for pfx in ordered:
        info = docs[pfx]
        cols: list[tuple] = [("uid", "UID", "str"), ("title", "Title", "str")]
        for key in info["col_keys"]:
            stype = "num" if key in numeric_fields else "str"
            cols.append((key, _to_label(key), stype))
        # Ensure active and parent links appear at the end
        if not any(k == "active" for k, _, _ in cols):
            cols.append(("active", "Active", "str"))
        cols.append(("_parents", "Parent links", "str"))
        result.append((pfx, info["subdir"], cols))

    return result


def load_document(specs_dir: Path, subdir: str, prefix: str) -> list[dict]:
    """
    Load all .md and .yml items from specs_dir/subdir/ (skipping .doorstop.yml).
    Returns items sorted by level (numeric), named items last within their tier.
    """
    folder = specs_dir / subdir
    if not folder.is_dir():
        return []

    items = []
    for item_path in sorted(folder.glob("*.md")) + sorted(
        p for p in folder.glob("*.yml") if p.name != ".doorstop.yml"
    ):
        try:
            item = parse_item(item_path)
            items.append(item)
        except Exception as exc:
            print(f"  Warning: could not parse {item_path}: {exc}", file=sys.stderr)

    # Sort by level (float), named items sort last
    def _sort_key(it):
        try:
            lvl = float(it.get("level", "999"))
        except (ValueError, TypeError):
            lvl = 999.0
        return (1 if it["_named"] else 0, lvl)

    items.sort(key=_sort_key)
    return items


# ---------------------------------------------------------------------------
# HTML cell renderers
# ---------------------------------------------------------------------------

def _esc(s: str) -> str:
    """Minimal HTML escaping."""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _cell_uid(value: str, named: bool) -> str:
    cls = "text-muted fst-italic" if named else "fw-bold font-monospace uid-cell"
    return f'<code class="{cls}">{_esc(value)}</code>'


def _cell_active(value: str) -> str:
    if str(value).lower() == "false":
        return '<span class="badge bg-secondary">inactive</span>'
    return '<span class="badge bg-success">active</span>'


def _cell_numeric(value: str) -> str:
    """Render numeric fields with a coloured pip — higher number = more intense."""
    try:
        n = int(str(value).strip("'\""))
    except (ValueError, TypeError):
        return f'<span class="text-muted">—</span>'
    colours = {1: "#198754", 2: "#5cb85c", 3: "#ffc107", 4: "#fd7e14", 5: "#dc3545"}
    col = colours.get(n, "#6c757d")
    return f'<span style="color:{col};font-weight:600">{n}</span>'


def _cell_defect(value: str, defect_badge_css: dict, defect_labels: dict) -> str:
    css = defect_badge_css.get(value, "bg-secondary")
    label = defect_labels.get(value, _esc(value))
    return f'<span class="badge {css}">{label}</span>'


def _cell_parents(value: str) -> str:
    if not value:
        return '<span class="text-muted">—</span>'
    badges = []
    for uid in [v.strip() for v in value.split(",") if v.strip()]:
        badges.append(f'<code class="badge bg-light text-dark border">{_esc(uid)}</code>')
    return " ".join(badges)


def _cell_default(value: str) -> str:
    s = str(value).strip("'\"").strip()
    if not s or s in ("null", "None", "''", '""'):
        return '<span class="text-muted">—</span>'
    return _esc(s)


def _render_cell(
    key: str,
    value: str,
    named: bool,
    defect_badge_css: dict,
    defect_labels: dict,
) -> str:
    if key == "uid":
        return _cell_uid(value, named)
    if key == "active":
        return _cell_active(value)
    if key == "_parents":
        return _cell_parents(value)
    if key == "defect-category":
        return _cell_defect(value, defect_badge_css, defect_labels)
    if key in ("urgency", "importance", "difficulty", "risk", "complexity",
               "passed-steps", "failed-steps", "not-executed-steps"):
        return _cell_numeric(value)
    return _cell_default(value)


# ---------------------------------------------------------------------------
# HTML generation
# ---------------------------------------------------------------------------

def _build_tab_nav(doc_types: list, items_by_prefix: dict) -> str:
    parts = ['<ul class="nav nav-tabs" id="docTabs" role="tablist">']
    for i, (prefix, _, _cols) in enumerate(doc_types):
        count = len(items_by_prefix.get(prefix, []))
        active_cls = " active" if i == 0 else ""
        selected = "true" if i == 0 else "false"
        badge_css = "bg-primary" if count else "bg-secondary"
        parts.append(
            f'  <li class="nav-item" role="presentation">'
            f'<button class="nav-link{active_cls}" id="tab-{prefix}" '
            f'data-bs-toggle="tab" data-bs-target="#pane-{prefix}" '
            f'type="button" role="tab" aria-controls="pane-{prefix}" '
            f'aria-selected="{selected}">'
            f'{prefix} <span class="badge {badge_css} ms-1">{count}</span>'
            f'</button></li>'
        )
    parts.append("</ul>")
    return "\n".join(parts)


def _build_table(
    prefix: str,
    cols: list,
    items: list,
    defect_badge_css: dict,
    defect_labels: dict,
) -> str:
    table_id = f"dt-{prefix}"
    # thead
    ths = "".join(f"<th>{_esc(label)}</th>" for _, label, _ in cols)
    thead = f"<thead><tr>{ths}</tr></thead>"

    # tfoot — one input per column for per-column filtering
    tfoot_cells = []
    for key, label, _ in cols:
        if key == "active":
            tfoot_cells.append(
                f'<th>'
                f'<select class="col-filter form-select form-select-sm">'
                f'<option value="">All</option>'
                f'<option value="active">active</option>'
                f'<option value="inactive">inactive</option>'
                f'</select>'
                f'</th>'
            )
        else:
            tfoot_cells.append(
                f'<th><input type="text" class="col-filter form-control form-control-sm" '
                f'placeholder="{_esc(label)}…" style="min-width:55px"/></th>'
            )
    tfoot = f"<tfoot><tr>{''.join(tfoot_cells)}</tr></tfoot>"

    # tbody
    rows = []
    for item in items:
        named = item.get("_named", False)
        inactive = str(item.get("active", "true")).lower() == "false"
        row_cls = ""
        if inactive:
            row_cls = ' class="table-secondary text-decoration-line-through"'
        elif named:
            row_cls = ' class="table-light text-muted"'

        cells = []
        for key, _label, stype in cols:
            raw = item.get(key, "")
            cell_html = _render_cell(key, str(raw), named, defect_badge_css, defect_labels)
            if stype == "num":
                # Provide a machine-readable sort value so DataTables can sort
                # numerically even though the cell displays styled HTML.
                try:
                    order_val = int(str(raw).strip("'\""))
                except (ValueError, TypeError):
                    order_val = -1
                cells.append(f'<td data-order="{order_val}">{cell_html}</td>')
            else:
                cells.append(f"<td>{cell_html}</td>")
        rows.append(f"<tr{row_cls}>{''.join(cells)}</tr>")

    tbody = f"<tbody>{''.join(rows)}</tbody>"
    return (
        f'<table id="{table_id}" class="table table-bordered table-hover table-sm w-100">'
        f"{thead}{tbody}{tfoot}</table>"
    )


def _build_dt_init(doc_types: list) -> str:
    """Generate the DataTables init JS for every table."""
    inits = []
    for prefix, _, cols in doc_types:
        table_id = f"dt-{prefix}"
        # Column definitions: disable ordering on the parent-links column
        col_defs = []
        for i, (key, _label, stype) in enumerate(cols):
            if key == "_parents":
                col_defs.append(f'{{ targets: {i}, orderable: false }}')
            elif stype == "num":
                # Custom sort on numeric-as-string values
                col_defs.append(
                    f'{{ targets: {i}, type: "num" }}'
                )
        col_defs_js = "[" + ", ".join(col_defs) + "]"
        inits.append(f"""
      $('#{table_id}').DataTable({{
        pageLength: 25,
        lengthMenu: [10, 25, 50, 100, -1],
        responsive: false,
        columnDefs: {col_defs_js},
        language: {{ search: "Filter all columns:" }},
        initComplete: function () {{
          var api = this.api();
          api.columns().every(function (colIdx) {{
            var col = this;
            var $ctrl = $('tfoot tr th:eq(' + colIdx + ') .col-filter', $('#{table_id}'));
            if ($ctrl.is('select')) {{
              $ctrl.on('change', function () {{
                var val = $.fn.dataTable.util.escapeRegex($(this).val());
                col.search(val ? '^' + val + '$' : '', true, false).draw();
              }});
            }} else {{
              $ctrl.on('keyup change clear', function () {{
                if (col.search() !== this.value) {{
                  col.search(this.value).draw();
                }}
              }});
            }}
          }});
        }}
      }});""")
    return "\n".join(inits)


def build_html(
    items_by_prefix: dict,
    doc_types: list,
    defect_badge_css: dict,
    defect_labels: dict,
) -> str:
    import datetime
    today = datetime.date.today().isoformat()

    tab_nav = _build_tab_nav(doc_types, items_by_prefix)

    # Build tab panes
    panes = []
    for i, (prefix, _, cols) in enumerate(doc_types):
        items = items_by_prefix.get(prefix, [])
        active_cls = " show active" if i == 0 else ""
        table_html = _build_table(prefix, cols, items, defect_badge_css, defect_labels)
        panes.append(
            f'<div class="tab-pane fade{active_cls}" id="pane-{prefix}" '
            f'role="tabpanel" aria-labelledby="tab-{prefix}">'
            f'<div class="pt-3">{table_html}</div>'
            f'</div>'
        )
    panes_html = "\n".join(panes)

    dt_init_js = _build_dt_init(doc_types)

    total_items = sum(len(v) for v in items_by_prefix.values())

    return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Specification Browser</title>
  <link rel="stylesheet" href="{BOOTSTRAP_CSS}">
  <link rel="stylesheet" href="{DT_CSS}">
  <style>
    body {{
      font-family: 'Segoe UI', sans-serif;
      padding: 1.5rem;
      background: #f8f9fa;
    }}
    h1 {{ font-size: 1.6rem; margin-bottom: 0.15rem; }}
    .subtitle {{ color: #6c757d; font-size: .9rem; margin-bottom: 1.25rem; }}
    .uid-cell {{ font-size: .85rem; letter-spacing: .02em; }}
    table.dataTable td {{ vertical-align: middle; font-size: .85rem; }}
    table.dataTable th {{ font-size: .82rem; background: #f1f3f5; }}
    table.dataTable tfoot th {{
      background: #fff;
      padding: .3rem .4rem;
    }}
    .dataTables_wrapper .dataTables_filter input {{
      border: 1px solid #ced4da;
      border-radius: .375rem;
      padding: .25rem .5rem;
    }}
    footer {{
      color: #aaa;
      font-size: .78rem;
      margin-top: 2rem;
      border-top: 1px solid #dee2e6;
      padding-top: .75rem;
    }}
    .nav-tabs .nav-link {{ font-size: .85rem; padding: .4rem .75rem; }}
    .badge.bg-light {{ border: 1px solid #dee2e6; }}
    .text-decoration-line-through td {{ opacity: .6; }}
  </style>
</head>
<body>
  <h1>Specification Browser</h1>
  <p class="subtitle">
    {total_items} items across {len(doc_types)} document types
    &mdash; generated {today}
  </p>

  <!-- Tab navigation -->
  {tab_nav}

  <!-- Tab content -->
  <div class="tab-content" id="docTabsContent">
    {panes_html}
  </div>

  <footer>
    Generated by c5browser.py &mdash; C5-DEC CAD Doorstop specification toolchain.<br>
    Columns are sortable (click header). Use the <em>Filter all columns</em> box for a global search,
    or the per-column inputs in the table footer to filter individual columns.
    Named/group items (e.g.&nbsp;<code>MRS-ADBox</code>) are shown in muted style.
    Inactive items are struck through.
  </footer>

  <script src="{JQUERY_JS}"></script>
  <script src="{DT_JS}"></script>
  <script src="{DT_BS5_JS}"></script>
  <script src="{BOOTSTRAP_JS}"></script>
  <script>
    $(document).ready(function () {{
      // Initialise all DataTables
      {dt_init_js}

      // When switching tabs, adjust column widths so DataTables renders correctly
      $('button[data-bs-toggle="tab"]').on('shown.bs.tab', function (e) {{
        var targetPane = $(e.target).data('bs-target');
        $(targetPane).find('table.dataTable').DataTable().columns.adjust();
      }});
    }});
  </script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate an interactive HTML browser for all Doorstop spec items"
    )
    parser.add_argument(
        "--specs-dir",
        default=str(SCRIPT_DIR.parent),
        help="Root directory containing the Doorstop subdirectories (default: parent of this script)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output HTML file path (default: docs/publish/items_browser.html relative to specs-dir)",
    )
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help=f"Path to the YAML configuration file (default: {DEFAULT_CONFIG_PATH})",
    )
    args = parser.parse_args()

    specs_dir = Path(args.specs_dir).resolve()
    if not specs_dir.is_dir():
        print(f"ERROR: specs-dir not found: {specs_dir}", file=sys.stderr)
        sys.exit(1)

    if args.output:
        out_path = Path(args.output)
    else:
        out_path = SCRIPT_DIR.parent / "docs" / "publish" / "items_browser.html"

    # Load configuration (numeric fields, defect badges, doc_types fallback)
    cfg = load_config(Path(args.config))
    numeric_fields = cfg["numeric_fields"]
    defect_badge_css = cfg["defect_badge_css"]
    defect_labels = cfg["defect_labels"]
    config_doc_types = cfg["doc_types"]

    # Auto-discover document types from .doorstop.yml files; fall back to the
    # doc_types from the config file (or built-in defaults) when discovery
    # produces no results.
    active_doc_types = discover_doc_types(specs_dir, numeric_fields)
    if active_doc_types:
        print(f"Discovered {len(active_doc_types)} document type(s) from .doorstop.yml files.")
    else:
        print("Using doc_types from config file (or built-in defaults).")
        active_doc_types = config_doc_types

    print("Loading Doorstop items...")
    items_by_prefix: dict[str, list] = {}
    for prefix, subdir, _cols in active_doc_types:
        items = load_document(specs_dir, subdir, prefix)
        items_by_prefix[prefix] = items
        print(f"  {prefix:<6} {len(items):>4} items  ({specs_dir / subdir})")

    print(f"\nBuilding HTML browser...")
    html = build_html(items_by_prefix, active_doc_types, defect_badge_css, defect_labels)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    print(f"Written to: {out_path}")


if __name__ == "__main__":
    main()
