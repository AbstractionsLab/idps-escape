"""
c5traceability.py — Configurable traceability matrix statistics for Doorstop projects.

All document types, parent–child relations, and coverage checks are defined in a
YAML configuration file (default: c5traceability.yaml alongside this script).
The tool can also auto-discover the document tree from .doorstop.yml files.

Usage:
    python c5traceability.py                        # console output, default config
    python c5traceability.py --html                 # console + HTML report
    python c5traceability.py --config my.yaml       # custom config file
    python c5traceability.py --discover             # print config derived from .doorstop.yml
    python c5traceability.py --discover --discover-write  # write discovered config, then run
    python c5traceability.py --csv path/to/traceability.csv --html --output report.html
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

try:
    import yaml as _yaml
    _YAML = True
except ImportError:
    _YAML = False

# ---------------------------------------------------------------------------
# Rich — optional.  Fall back to plain text if not installed.
# ---------------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    from rich.panel import Panel

    _RICH = True
    console = Console()
except ImportError:
    _RICH = False
    console = None  # type: ignore

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent

_NAMED_PATTERN = re.compile(r"^[A-Z]+-[A-Za-z]", re.ASCII)

DEFECT_KEYWORDS = {
    "?c5-defect-0": 0,
    "?c5-defect-1": 1,
    "?c5-defect-2": 2,
    "?c5-defect-3": 3,
    "?c5-defect-4": 4,
}

_DEFECT_COLORS_RICH = {0: "green", 1: "dark_sea_green4", 2: "dark_orange", 3: "red", 4: "bright_red"}
_DEFECT_LABELS = {
    0: "0 — flawless",
    1: "1 — insignificant defect",
    2: "2 — minor defect",
    3: "3 — major defect",
    4: "4 — critical defect",
}

BOOTSTRAP_CDN = "https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def is_named(uid: str) -> bool:
    """Return True for named (non-numeric) group items such as MRS-ADBox."""
    return bool(_NAMED_PATTERN.match(uid))


def _uid_sort_key(uid: str):
    parts = uid.rsplit("-", 1)
    if len(parts) == 2:
        try:
            return (parts[0], int(parts[1]))
        except ValueError:
            return (parts[0], parts[1])
    return (uid, "")


def pct(covered: int, total: int) -> float:
    return 100.0 * covered / total if total else 0.0


def _print(msg: str = ""):
    if _RICH:
        console.print(msg)
    else:
        print(msg)


def _section(title: str):
    if _RICH:
        console.rule(f"[bold cyan]{title}[/bold cyan]")
    else:
        print(f"\n{'=' * 70}")
        print(f"  {title}")
        print("=" * 70)


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "document_order": [],
    "checks": [],
    "defect_sources": [],
}


def load_config(config_path: Path) -> dict:
    """Load and validate the YAML config file."""
    if not _YAML:
        print("ERROR: pyyaml is required for config loading.  Run: pip install pyyaml", file=sys.stderr)
        sys.exit(1)
    if not config_path.exists():
        print(f"ERROR: config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)
    with open(config_path, encoding="utf-8") as fh:
        data = _yaml.safe_load(fh) or {}
    cfg = {**DEFAULT_CONFIG, **data}
    # Normalise each check
    for i, check in enumerate(cfg["checks"]):
        if "subject" not in check or "linked" not in check:
            print(f"ERROR: check #{i + 1} in config is missing 'subject' or 'linked'", file=sys.stderr)
            sys.exit(1)
        if isinstance(check["linked"], str):
            check["linked"] = [check["linked"]]
        check.setdefault("id", f"check_{i + 1}")
        check.setdefault("title", f"{check['subject']} → {', '.join(check['linked'])} coverage")
        check.setdefault("uncovered_label", "uncovered")
    return cfg


# ---------------------------------------------------------------------------
# Auto-discovery from .doorstop.yml files
# ---------------------------------------------------------------------------


def discover_config_from_doorstop(specs_dir: Path) -> dict:
    """
    Walk *specs_dir* for .doorstop.yml files and build a config dict by reading
    the 'prefix' and 'parent' fields from each document's settings block.

    The generated checks cover every parent→child edge in the tree.
    Defect sources are left empty (the user can add them manually).
    """
    if not _YAML:
        print("ERROR: pyyaml is required for --discover.  Run: pip install pyyaml", file=sys.stderr)
        sys.exit(1)

    documents: dict[str, str | None] = {}  # prefix → parent prefix (or None for root)

    for yml_file in sorted(specs_dir.rglob(".doorstop.yml")):
        with open(yml_file, encoding="utf-8") as fh:
            data = _yaml.safe_load(fh) or {}
        settings = data.get("settings", {})
        prefix = settings.get("prefix")
        parent = settings.get("parent")
        if prefix:
            documents[prefix] = parent

    if not documents:
        print(f"WARNING: no .doorstop.yml files found under {specs_dir}", file=sys.stderr)

    # Build a coverage check for every child→parent edge
    checks = []
    for prefix, parent in sorted(documents.items()):
        if parent:
            checks.append(
                {
                    "id": f"{parent.lower()}_{prefix.lower()}",
                    "subject": parent,
                    "linked": [prefix],
                    "title": f"{parent} → {prefix} coverage",
                    "uncovered_label": f"no {prefix}",
                }
            )

    # Document order: roots first, then children (topological-ish)
    roots = [p for p, par in documents.items() if par is None]
    others = [p for p in sorted(documents.keys()) if p not in roots]
    doc_order = roots + others

    return {
        "document_order": doc_order,
        "checks": checks,
        "defect_sources": [],
        "_discovered": True,
    }


def config_to_yaml_str(cfg: dict) -> str:
    """Serialise a config dict back to a YAML string."""
    if not _YAML:
        return str(cfg)
    # Remove internal keys
    clean = {k: v for k, v in cfg.items() if not k.startswith("_")}
    return _yaml.dump(clean, default_flow_style=False, sort_keys=False, allow_unicode=True)


# ---------------------------------------------------------------------------
# CSV parsing
# ---------------------------------------------------------------------------


def load_traceability(csv_path: Path, include_named: bool = False):
    """Return (columns dict, rows list).  Named group items excluded unless include_named."""
    columns: dict[str, set] = defaultdict(set)
    rows: list[dict] = []

    with open(csv_path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for raw_row in reader:
            row = {k.strip(): v.strip() for k, v in raw_row.items() if k}
            if not any(row.values()):
                continue
            rows.append(row)
            for col, val in row.items():
                if val and (include_named or not is_named(val)):
                    columns[col].add(val)

    return columns, rows


# ---------------------------------------------------------------------------
# Generic coverage computation
# ---------------------------------------------------------------------------


def compute_coverage(
    rows: list[dict],
    subject_col: str,
    linked_cols: list[str],
    include_named: bool = False,
) -> dict[str, dict[str, set]]:
    """
    For each value in *subject_col*, collect values from each of *linked_cols*
    that appear in the same CSV row.

    Returns:
        subject_uid → {linked_col: set_of_values}

    An item is "covered" when at least one value exists across all linked_col sets.
    """
    mapping: dict[str, dict[str, set]] = {}

    def _empty_row() -> dict[str, set]:
        return {col: set() for col in linked_cols}

    for row in rows:
        subject_val = row.get(subject_col, "")
        if not subject_val or (not include_named and is_named(subject_val)):
            continue
        if subject_val not in mapping:
            mapping[subject_val] = _empty_row()
        for col in linked_cols:
            linked_val = row.get(col, "")
            if linked_val and (include_named or not is_named(linked_val)):
                mapping[subject_val][col].add(linked_val)

    return mapping


def _is_covered(item: dict[str, set]) -> bool:
    """True if any linked column has at least one value."""
    return any(item.values())


def _all_linked_sorted(item: dict[str, set]) -> list[str]:
    """Flat sorted list of all linked UIDs across all columns."""
    result = []
    for col_vals in item.values():
        result.extend(col_vals)
    return sorted(result, key=_uid_sort_key)


# ---------------------------------------------------------------------------
# Defect scanning (unchanged logic, config-driven document list)
# ---------------------------------------------------------------------------


def _parse_frontmatter(content: str) -> tuple[dict, str]:
    fm: dict[str, str] = {}
    body = content
    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            for line in parts[1].splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    fm[k.strip()] = v.strip()
            body = parts[2]
    return fm, body


def scan_defects(specs_dir: Path, defect_sources: list[dict]):
    """
    Scan configured defect-source documents for ?c5-defect-X keywords.

    defect_sources items:
        prefix             — subdirectory name (lowercase is tried first, then as-is)
        frontmatter_field  — if present, read this FM field instead of body scan
        guide_strip_heading — strip from this heading onward before body scan
    """
    defect_counts: dict[int, int] = defaultdict(int)
    severe_items: list[tuple[str, int]] = []

    for source in defect_sources:
        prefix = source.get("prefix", "")
        fm_field = source.get("frontmatter_field")
        strip_heading = source.get("guide_strip_heading")

        # Try lowercase prefix as directory name first (doorstop convention),
        # then the prefix as-is.
        for subdir_name in (prefix.lower(), prefix):
            folder = specs_dir / subdir_name
            if folder.is_dir():
                break
        else:
            continue  # directory not found, skip

        for md_file in sorted(folder.glob("*.md")):
            uid = md_file.stem
            if is_named(uid):
                continue
            content = md_file.read_text(encoding="utf-8")
            fm, body = _parse_frontmatter(content)
            if fm.get("active", "true").lower() == "false":
                continue

            found_levels: list[int] = []

            if fm_field:
                dc = fm.get(fm_field, "")
                for keyword, level in DEFECT_KEYWORDS.items():
                    if keyword in dc:
                        found_levels.append(level)
            else:
                if strip_heading:
                    body = body.split(strip_heading)[0]
                for keyword, level in DEFECT_KEYWORDS.items():
                    if keyword in body:
                        found_levels.append(level)

            if found_levels:
                max_level = max(found_levels)
                defect_counts[max_level] += 1
                if max_level >= 3:
                    severe_items.append((uid, max_level))

    return defect_counts, severe_items


# ---------------------------------------------------------------------------
# Console output — summary totals
# ---------------------------------------------------------------------------


def print_summary_totals(columns: dict, document_order: list[str], section_num: int):
    _section(f"{section_num}. Summary — unique items per document type")
    # Fall back to all columns present in the CSV if order not configured
    order = document_order or sorted(columns.keys())
    if _RICH:
        tbl = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
        tbl.add_column("Document type", style="bold")
        tbl.add_column("Unique items", justify="right")
        for col in order:
            count = len(columns.get(col, set()))
            tbl.add_row(col, str(count))
        console.print(tbl)
    else:
        print(f"{'Document type':<20} {'Unique items':>12}")
        print("-" * 34)
        for col in order:
            count = len(columns.get(col, set()))
            print(f"{col:<20} {count:>12}")


# ---------------------------------------------------------------------------
# Console output — generic coverage section
# ---------------------------------------------------------------------------


def print_coverage_section(
    mapping: dict[str, dict[str, set]],
    check: dict,
    section_num: int,
):
    """Generic console printer for any coverage check."""
    _section(f"{section_num}. {check['title']}")
    subject_col = check["subject"]
    linked_cols = check["linked"]
    uncovered_label = check["uncovered_label"]
    multi = len(linked_cols) > 1

    all_subjects = sorted(mapping.keys(), key=_uid_sort_key)
    covered_items = [s for s in all_subjects if _is_covered(mapping[s])]
    uncovered_items = [s for s in all_subjects if not _is_covered(mapping[s])]
    total = len(all_subjects)
    covered = len(covered_items)

    if _RICH:
        tbl = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
        tbl.add_column(subject_col, style="bold")
        if multi:
            for col in linked_cols:
                tbl.add_column(col)
        else:
            tbl.add_column(f"Linked {linked_cols[0]}s")
        tbl.add_column("Status")

        for uid in all_subjects:
            row_data = mapping[uid]
            is_cov = _is_covered(row_data)
            status = "[green]✓ covered[/green]" if is_cov else f"[yellow]⚠ {uncovered_label}[/yellow]"
            if multi:
                cols_display = [", ".join(sorted(row_data[c], key=_uid_sort_key)) or "—" for c in linked_cols]
                tbl.add_row(uid, *cols_display, status)
            else:
                linked_display = ", ".join(_all_linked_sorted(row_data)) or "—"
                tbl.add_row(uid, linked_display, status)

        console.print(tbl)
        pct_val = pct(covered, total)
        color = "green" if pct_val >= 80 else "yellow" if pct_val >= 50 else "red"
        console.print(
            f"Coverage: [{color}]{covered}/{total} ({pct_val:.1f}%)[/{color}]  "
            f"— {len(uncovered_items)} {subject_col} item(s) are {uncovered_label}"
        )
    else:
        col_w = 12
        link_w = 40
        if multi:
            header = f"{'  '.join(f'{c:<{col_w}}' for c in linked_cols)}"
        else:
            header = f"{'Linked ' + linked_cols[0]:<{link_w}}"
        print(f"{subject_col:<{col_w}} {header}  Status")
        print("-" * 80)
        for uid in all_subjects:
            row_data = mapping[uid]
            is_cov = _is_covered(row_data)
            status = "ok" if is_cov else uncovered_label.upper()
            if multi:
                cols_display = "  ".join(
                    f"{', '.join(sorted(row_data[c], key=_uid_sort_key)) or '—':<{col_w}}" for c in linked_cols
                )
            else:
                cols_display = f"{', '.join(_all_linked_sorted(row_data)) or '—':<{link_w}}"
            print(f"{uid:<{col_w}} {cols_display}  {status}")
        print(f"\nCoverage: {covered}/{total} ({pct(covered, total):.1f}%)")
        print(f"{len(uncovered_items)} {subject_col} item(s) are {uncovered_label}.")


# ---------------------------------------------------------------------------
# Console output — defects and health score
# ---------------------------------------------------------------------------


def print_defect_summary(defect_counts: dict, severe_items: list, section_num: int):
    _section(f"{section_num}. Defect severity summary (scan of defect-source documents)")
    total_reports = sum(defect_counts.values())
    if total_reports == 0:
        _print("  No defect-source files found or no defect keywords detected.")
        return

    if _RICH:
        tbl = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
        tbl.add_column("Level", style="bold")
        tbl.add_column("Label")
        tbl.add_column("Reports", justify="right")
        tbl.add_column("Pct", justify="right")
        for level in range(5):
            count = defect_counts.get(level, 0)
            color = _DEFECT_COLORS_RICH[level]
            tbl.add_row(
                f"[{color}]{level}[/{color}]",
                f"[{color}]{_DEFECT_LABELS[level]}[/{color}]",
                str(count),
                f"{pct(count, total_reports):.1f}%",
            )
        console.print(tbl)
        if severe_items:
            console.print("\n[bold red]Items with major or critical defects (level ≥ 3):[/bold red]")
            for uid, level in sorted(severe_items, key=lambda x: (-x[1], x[0])):
                color = _DEFECT_COLORS_RICH[level]
                console.print(f"  [{color}]● {uid}  ({_DEFECT_LABELS[level]})[/{color}]")
        else:
            console.print("[green]No major or critical defects found.[/green]")
    else:
        print(f"{'Level':<8} {'Label':<35} {'Reports':>8} {'Pct':>7}")
        print("-" * 62)
        for level in range(5):
            count = defect_counts.get(level, 0)
            print(f"{level:<8} {_DEFECT_LABELS[level]:<35} {count:>8} {pct(count, total_reports):>6.1f}%")
        if severe_items:
            print("\nItems with major or critical defects (level >= 3):")
            for uid, level in sorted(severe_items, key=lambda x: (-x[1], x[0])):
                print(f"  * {uid}  ({_DEFECT_LABELS[level]})")
        else:
            print("No major or critical defects found.")


def print_health_score(metrics: list[tuple[str, int, int]], section_num: int):
    _section(f"{section_num}. Overall health score")
    total_covered = sum(c for _, c, _ in metrics)
    total_items = sum(t for _, _, t in metrics)
    overall = pct(total_covered, total_items)

    if _RICH:
        tbl = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
        tbl.add_column("Metric", style="bold")
        tbl.add_column("Covered", justify="right")
        tbl.add_column("Total", justify="right")
        tbl.add_column("Coverage", justify="right")
        for label, covered, total in metrics:
            p = pct(covered, total)
            color = "green" if p >= 80 else "yellow" if p >= 50 else "red"
            tbl.add_row(label, str(covered), str(total), f"[{color}]{p:.1f}%[/{color}]")
        color = "green" if overall >= 80 else "yellow" if overall >= 50 else "red"
        tbl.add_row(
            "[bold]OVERALL[/bold]",
            f"[bold]{total_covered}[/bold]",
            f"[bold]{total_items}[/bold]",
            f"[bold {color}]{overall:.1f}%[/bold {color}]",
        )
        console.print(tbl)
        bar_len = 40
        filled = int(bar_len * overall / 100)
        color = "green" if overall >= 80 else "yellow" if overall >= 50 else "red"
        bar = "█" * filled + "░" * (bar_len - filled)
        console.print(f"\n[{color}]{bar}[/{color}]  [{color}]{overall:.1f}%[/{color}]")
    else:
        print(f"{'Metric':<45} {'Covered':>8} {'Total':>7} {'Coverage':>10}")
        print("-" * 74)
        for label, covered, total in metrics:
            print(f"{label:<45} {covered:>8} {total:>7} {pct(covered, total):>9.1f}%")
        print("-" * 74)
        print(f"{'OVERALL':<45} {total_covered:>8} {total_items:>7} {overall:>9.1f}%")
        bar_len = 40
        filled = int(bar_len * overall / 100)
        bar = "#" * filled + "-" * (bar_len - filled)
        print(f"\n[{bar}]  {overall:.1f}%")


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

_HTML_HEADER = (
    """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Traceability Statistics</title>
  <link rel="stylesheet" href="{bootstrap_cdn}">
  <style>
    body {{ font-family: 'Segoe UI', sans-serif; padding: 2rem; }}
    h1 {{ margin-bottom: 0.25rem; }}
    .subtitle {{ color: #6c757d; margin-bottom: 2rem; }}
    section {{ margin-bottom: 3rem; }}
    .badge-ok {{ background-color: #198754; color: #fff; padding: .2em .5em; border-radius: .25rem; }}
    .badge-warn {{ background-color: #ffc107; color: #212529; padding: .2em .5em; border-radius: .25rem; }}
    .badge-crit {{ background-color: #dc3545; color: #fff; padding: .2em .5em; border-radius: .25rem; }}
    .progress {{ height: 24px; }}
    .tbl-uid {{ font-family: monospace; font-size: .85rem; }}
    footer {{ color: #aaa; font-size: .8rem; margin-top: 3rem; border-top: 1px solid #eee; padding-top: 1rem; }}
  </style>
</head>
<body>
  <h1>Traceability Statistics</h1>
  <p class="subtitle">Generated on {date}</p>
""".format(
        bootstrap_cdn=BOOTSTRAP_CDN,
        date=__import__("datetime").date.today().isoformat(),
    )
)

_HTML_FOOTER = (
    "  <footer>Generated by c5traceability.py — C5-DEC CAD Doorstop traceability toolchain</footer>\n"
    "</body>\n</html>\n"
)


def _badge(covered: int, total: int) -> str:
    p = pct(covered, total)
    cls = "badge-ok" if p >= 80 else "badge-warn" if p >= 50 else "badge-crit"
    return f'<span class="{cls}">{covered}/{total} ({p:.1f}%)</span>'


def _progress_bar(covered: int, total: int) -> str:
    p = pct(covered, total)
    cls = "bg-success" if p >= 80 else "bg-warning" if p >= 50 else "bg-danger"
    return (
        f'<div class="progress mb-2">'
        f'<div class="progress-bar {cls}" role="progressbar" style="width:{p:.1f}%">'
        f"{p:.1f}%</div></div>"
    )


def _build_nav(total_sections: int, has_defects: bool, section_titles: dict | None = None) -> str:
    section_titles = section_titles or {}
    items = ['<li class="nav-item"><a class="nav-link" href="#s1">1. Summary</a></li>']
    for i in range(2, total_sections + 1):
        label = section_titles.get(i, f"{i}.")
        items.append(f'<li class="nav-item"><a class="nav-link" href="#s{i}">{label}</a></li>')
    return (
        '\n  <nav class="mb-4">\n    <ul class="nav nav-pills flex-wrap gap-2">\n      '
        + "\n      ".join(items)
        + "\n    </ul>\n  </nav>\n"
    )


def build_html_summary(columns: dict, document_order: list[str], section_num: int) -> str:
    order = document_order or sorted(columns.keys())
    parts = [f'<section id="s{section_num}"><h2>{section_num}. Summary — unique items per document type</h2>']
    parts.append('<table class="table table-bordered table-sm table-hover w-auto">')
    parts.append('<thead><tr><th>Document type</th><th class="text-end">Unique items</th></tr></thead><tbody>')
    for col in order:
        count = len(columns.get(col, set()))
        parts.append(f"<tr><td class='tbl-uid'><b>{col}</b></td><td class='text-end'>{count}</td></tr>")
    parts.append("</tbody></table></section>")
    return "\n".join(parts)


def build_html_coverage_section(
    mapping: dict[str, dict[str, set]],
    check: dict,
    section_num: int,
) -> str:
    subject_col = check["subject"]
    linked_cols = check["linked"]
    uncovered_label = check["uncovered_label"]
    multi = len(linked_cols) > 1
    title = check["title"]

    all_subjects = sorted(mapping.keys(), key=_uid_sort_key)
    uncovered_items = [s for s in all_subjects if not _is_covered(mapping[s])]
    total = len(all_subjects)
    covered = total - len(uncovered_items)

    parts = [
        f'<section id="s{section_num}"><h2>{section_num}. {title}</h2>',
        f"<p>{_badge(covered, total)} &nbsp; {len(uncovered_items)} {subject_col} item(s) are {uncovered_label}</p>",
        _progress_bar(covered, total),
        '<table class="table table-bordered table-sm table-hover">',
        "<thead><tr>",
        f"<th>{subject_col}</th>",
    ]
    if multi:
        for col in linked_cols:
            parts.append(f"<th>{col}</th>")
    else:
        parts.append(f"<th>Linked {linked_cols[0]}s</th>")
    parts.append("<th>Status</th></tr></thead><tbody>")

    for uid in all_subjects:
        row_data = mapping[uid]
        is_cov = _is_covered(row_data)
        status = '<span class="badge-ok">✓ covered</span>' if is_cov else f'<span class="badge-warn">⚠ {uncovered_label}</span>'
        row_cls = "" if is_cov else ' class="table-warning"'
        parts.append(f"<tr{row_cls}><td class='tbl-uid'>{uid}</td>")
        if multi:
            for col in linked_cols:
                vals = ", ".join(sorted(row_data[col], key=_uid_sort_key)) or "—"
                parts.append(f"<td class='tbl-uid'>{vals}</td>")
        else:
            vals = ", ".join(_all_linked_sorted(row_data)) or "—"
            parts.append(f"<td class='tbl-uid'>{vals}</td>")
        parts.append(f"<td>{status}</td></tr>")

    parts.append("</tbody></table></section>")
    return "\n".join(parts)


def build_html_defect_section(defect_counts: dict, severe_items: list, section_num: int) -> str:
    total_reports = sum(defect_counts.values())
    parts = [f'<section id="s{section_num}"><h2>{section_num}. Defect severity summary</h2>']
    if total_reports == 0:
        parts.append("<p class='text-muted'>No defect-source files found or no defect keywords detected.</p>")
    else:
        _ROW_CSS = {0: "", 1: "", 2: "table-warning", 3: "table-danger", 4: "table-danger fw-bold"}
        parts.append('<table class="table table-bordered table-sm table-hover w-auto">')
        parts.append('<thead><tr><th>Level</th><th>Label</th><th class="text-end">Reports</th><th class="text-end">%</th></tr></thead><tbody>')
        for level in range(5):
            count = defect_counts.get(level, 0)
            css = _ROW_CSS[level]
            row_cls = f' class="{css}"' if css else ""
            p = pct(count, total_reports)
            parts.append(f"<tr{row_cls}><td><b>{level}</b></td><td>{_DEFECT_LABELS[level]}</td><td class='text-end'>{count}</td><td class='text-end'>{p:.1f}%</td></tr>")
        parts.append("</tbody></table>")
        if severe_items:
            parts.append('<h5 class="text-danger">Items with major or critical defects (level ≥ 3):</h5><ul class="text-danger">')
            for uid, level in sorted(severe_items, key=lambda x: (-x[1], x[0])):
                parts.append(f"<li><code>{uid}</code> — {_DEFECT_LABELS[level]}</li>")
            parts.append("</ul>")
        else:
            parts.append('<p class="text-success">✓ No major or critical defects found.</p>')
    parts.append("</section>")
    return "\n".join(parts)


def build_html_health_section(metrics: list[tuple[str, int, int]], section_num: int) -> str:
    total_covered = sum(c for _, c, _ in metrics)
    total_items = sum(t for _, _, t in metrics)
    overall = pct(total_covered, total_items)

    parts = [
        f'<section id="s{section_num}"><h2>{section_num}. Overall health score</h2>',
        _progress_bar(total_covered, total_items),
        '<table class="table table-bordered table-sm table-hover">',
        '<thead><tr><th>Metric</th><th class="text-end">Covered</th><th class="text-end">Total</th><th class="text-end">Coverage</th></tr></thead><tbody>',
    ]
    for label, covered, total in metrics:
        p = pct(covered, total)
        css = "table-success" if p >= 80 else "table-warning" if p >= 50 else "table-danger"
        parts.append(f'<tr class="{css}"><td>{label}</td><td class="text-end">{covered}</td><td class="text-end">{total}</td><td class="text-end">{p:.1f}%</td></tr>')
    css_overall = "table-success" if overall >= 80 else "table-warning" if overall >= 50 else "table-danger"
    parts.append(f'<tr class="{css_overall} fw-bold"><td>OVERALL</td><td class="text-end">{total_covered}</td><td class="text-end">{total_items}</td><td class="text-end">{overall:.1f}%</td></tr>')
    parts.append("</tbody></table></section>")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Configurable traceability statistics from a Doorstop traceability.csv"
    )
    parser.add_argument(
        "--config",
        default=str(SCRIPT_DIR / "c5traceability_config.yaml"),
        help="Path to the YAML config file (default: c5traceability_config.yaml alongside this script)",
    )
    parser.add_argument(
        "--csv",
        default=str(SCRIPT_DIR.parent.parent / "traceability" / "traceability.csv"),
        help="Path to traceability.csv",
    )
    parser.add_argument(
        "--html",
        action="store_true",
        help="Generate an HTML report in addition to console output",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Path for the HTML report (default: docs/publish/traceability_stats.html relative to specs-dir)",
    )
    parser.add_argument(
        "--include-named",
        action="store_true",
        help="Include named items (e.g. MRS-ADBox) in coverage statistics",
    )
    parser.add_argument(
        "--specs-dir",
        default=str(SCRIPT_DIR.parent),
        help="Root specs directory containing .doorstop.yml sub-folders (default: parent of this script)",
    )
    parser.add_argument(
        "--discover",
        action="store_true",
        help="Auto-build config from .doorstop.yml files and print the discovered YAML",
    )
    parser.add_argument(
        "--discover-write",
        action="store_true",
        help="Together with --discover: write the discovered config to --config path, then run analysis",
    )
    args = parser.parse_args()

    specs_dir = Path(args.specs_dir)
    include_named = args.include_named

    # --- Config ---
    if args.discover:
        cfg = discover_config_from_doorstop(specs_dir)
        discovered_yaml = config_to_yaml_str(cfg)
        print("# Discovered config from .doorstop.yml files")
        print(discovered_yaml)
        if args.discover_write:
            config_path = Path(args.config)
            config_path.write_text(discovered_yaml, encoding="utf-8")
            _print(f"\nConfig written to: {config_path}")
        else:
            # Print only; do not run analysis unless --discover-write was given
            return
    else:
        config_path = Path(args.config)
        if not config_path.exists():
            # No config file — auto-discover document tree from .doorstop.yml files
            msg = f"Config not found at {config_path}; auto-discovering from .doorstop.yml files in {specs_dir}"
            if _RICH:
                console.print(f"[dim]{msg}[/dim]")
            else:
                print(msg)
            cfg = discover_config_from_doorstop(specs_dir)
        else:
            cfg = load_config(config_path)

    # --- CSV ---
    csv_path = Path(args.csv)
    if not csv_path.exists():
        print(f"ERROR: traceability.csv not found at: {csv_path}", file=sys.stderr)
        sys.exit(1)

    columns, rows = load_traceability(csv_path, include_named=include_named)

    # --- Compute coverage for every check ---
    check_results: list[dict[str, dict[str, set]]] = []
    for check in cfg["checks"]:
        result = compute_coverage(rows, check["subject"], check["linked"], include_named)
        check_results.append(result)

    # --- Defects ---
    defect_counts, severe_items = scan_defects(specs_dir, cfg.get("defect_sources", []))

    # --- Health metrics ---
    metrics: list[tuple[str, int, int]] = []
    for check, result in zip(cfg["checks"], check_results):
        total = len(result)
        covered = sum(1 for item in result.values() if _is_covered(item))
        metrics.append((check["title"], covered, total))

    # Section numbering: 1=summary, 2..N=checks, N+1=defects, N+2=health
    n_checks = len(cfg["checks"])
    section_defects = n_checks + 2
    section_health = n_checks + 3

    # --- Console output ---
    if _RICH:
        console.print(
            Panel(
                "[bold]Traceability Statistics[/bold]\n"
                f"[dim]Source: {csv_path}[/dim]\n"
                f"[dim]Config: {args.config}[/dim]",
                style="cyan",
            )
        )
    else:
        print("=" * 70)
        print("  Traceability Statistics")
        print(f"  Source: {csv_path}")
        print(f"  Config: {args.config}")
        print("=" * 70)

    print_summary_totals(columns, cfg["document_order"], section_num=1)

    for i, (check, result) in enumerate(zip(cfg["checks"], check_results), start=2):
        print_coverage_section(result, check, section_num=i)

    print_defect_summary(defect_counts, severe_items, section_num=section_defects)
    print_health_score(metrics, section_num=section_health)

    # --- HTML ---
    if args.html:
        html_path = Path(args.output) if args.output else SCRIPT_DIR.parent / "docs" / "publish" / "traceability_stats.html"
        html_path.parent.mkdir(parents=True, exist_ok=True)

        total_sections = section_health
        section_titles: dict[int, str] = {}
        for i, check in enumerate(cfg["checks"], start=2):
            section_titles[i] = f"{i}. {check['title']}"
        section_titles[section_defects] = f"{section_defects}. Defect severity summary"
        section_titles[section_health] = f"{section_health}. Overall health score"
        parts = [
            _HTML_HEADER,
            _build_nav(total_sections, has_defects=bool(cfg.get("defect_sources")), section_titles=section_titles),
            build_html_summary(columns, cfg["document_order"], section_num=1),
        ]
        for i, (check, result) in enumerate(zip(cfg["checks"], check_results), start=2):
            parts.append(build_html_coverage_section(result, check, section_num=i))
        parts.append(build_html_defect_section(defect_counts, severe_items, section_num=section_defects))
        parts.append(build_html_health_section(metrics, section_num=section_health))
        parts.append(_HTML_FOOTER)

        html_path.write_text("\n".join(parts), encoding="utf-8")
        if _RICH:
            console.print(f"\n[bold green]HTML report written to:[/bold green] {html_path}")
        else:
            print(f"\nHTML report written to: {html_path}")


if __name__ == "__main__":
    main()
