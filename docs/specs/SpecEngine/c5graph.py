"""
c5graph.py — Interactive Cytoscape.js graph for Doorstop specification traceability.

Reads all active Doorstop item files from docs/specs/ subdirectories, auto-discovering
document types and their relations from .doorstop.yml files, and generates a single
self-contained HTML file (specs-graph.html) with an interactive, hierarchical
expand/collapse node graph.

Graph conventions:
  - Each active Doorstop item becomes a node identified by its UID.
  - Each entry in an item's `links:` field defines a directed edge from the child item
    to its parent item (upward traceability, consistent with Doorstop convention).
  - Green node  = item has at least one upward link (covered).
  - Yellow node = item has no upward links (uncovered / root).
  - Initial view shows only top-level MRS nodes and their direct children.
  - Click a node to expand its direct children; click again to collapse the subtree.

Usage:
    poetry run python c5graph.py                          # default output location
    poetry run python c5graph.py --output path/to/out.html
    poetry run python c5graph.py --specs-dir path/to/specs/
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from pathlib import Path
from urllib.request import urlopen
from urllib.error import URLError

try:
    import yaml as _yaml
    _YAML = True
except ImportError:
    _YAML = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent

# CDN URLs — fetched at generation time and inlined in the HTML output.
_CYTOSCAPE_URL = (
    "https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"
)
_DAGRE_URL = (
    "https://cdnjs.cloudflare.com/ajax/libs/dagre/0.8.5/dagre.min.js"
)
_CY_DAGRE_URL = (
    "https://cdn.jsdelivr.net/npm/cytoscape-dagre@2.5.0/cytoscape-dagre.min.js"
)

# Non-numeric UID pattern (e.g. MRS-ADBox, SRS-SONAR)
_NAMED_PATTERN = re.compile(r"^[A-Z]+-[A-Za-z]", re.ASCII)

# ---------------------------------------------------------------------------
# Item parsing  (shared patterns with c5browser.py)
# ---------------------------------------------------------------------------


def parse_item(path: Path) -> dict:
    """Parse a Doorstop item (.md with YAML frontmatter, or pure .yml)."""
    uid = path.stem
    content = path.read_text(encoding="utf-8")

    if path.suffix == ".yml":
        item = _parse_yaml_item(uid, content)
    else:
        item = _parse_md_item(uid, content)

    item["_path"] = str(path)
    return item


def _parse_md_item(uid: str, content: str) -> dict:
    """Parse a Markdown-format Doorstop item (YAML frontmatter + Markdown body)."""
    fm: dict = {}
    body = content

    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            _parse_yaml_block(parts[1], fm)
            body = parts[2]

    # H1 heading as the display title
    title = ""
    for line in body.splitlines():
        m = re.match(r"^#\s+(.+)", line)
        if m:
            title = m.group(1).strip()
            break

    # Parent UIDs from links field
    parents: list[str] = []
    links_raw = fm.get("links", "")
    if links_raw and links_raw not in ("[]", "''", '""', ""):
        for m2 in re.finditer(r"-\s+([A-Z]+-[A-Za-z0-9]+)", links_raw):
            parents.append(m2.group(1))

    item = dict(fm)
    item["uid"] = uid
    item["title"] = title
    item["_parents"] = parents
    return item


def _parse_yaml_item(uid: str, content: str) -> dict:
    """Parse a pure-YAML-format Doorstop item."""
    raw: dict = {}
    if _YAML:
        raw = _yaml.safe_load(content) or {}
    else:
        for line in content.splitlines():
            if ":" in line and not line.startswith((" ", "-")):
                k, _, v = line.partition(":")
                raw[k.strip()] = v.strip().strip("'\"")

    title = str(raw.get("header", "")).strip()
    if not title:
        text_val = str(raw.get("text", "")).strip()
        title = text_val.splitlines()[0].lstrip("# ").strip() if text_val else ""

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

    item: dict = {k: str(v) for k, v in raw.items() if k not in ("text", "links", "reviewed")}
    item["uid"] = uid
    item["title"] = title
    item["_parents"] = parents
    return item


def _parse_yaml_block(raw: str, out: dict) -> None:
    """Minimal YAML parser for Doorstop frontmatter scalar and list fields."""
    current_key: str | None = None
    list_buffer: list[str] = []

    def _flush():
        if current_key is not None and list_buffer:
            out[current_key] = " ".join(list_buffer).strip()

    for line in raw.splitlines():
        # List items (both indented and root-level) for the current key.
        # Must be checked BEFORE key: value to avoid mis-parsing "- UID: hash".
        stripped = line.lstrip()
        if stripped.startswith("- ") and current_key is not None:
            list_buffer.append(stripped)
            continue
        if ":" in line and not line.startswith(" ") and not line.startswith("-"):
            _flush()
            list_buffer = []
            k, _, v = line.partition(":")
            current_key = k.strip()
            val = v.strip().strip("'\"")
            if val:
                list_buffer = [val]

    _flush()


# ---------------------------------------------------------------------------
# Document discovery
# ---------------------------------------------------------------------------


def discover_doc_types(specs_dir: Path) -> list[tuple[str, str]]:
    """
    Auto-discover document prefixes + subdirectories by reading .doorstop.yml files.
    Returns list of (prefix, subdir) tuples in topological order (parents first).
    """
    if not _YAML:
        print(
            "WARNING: pyyaml not available — using filesystem order for discovery.",
            file=sys.stderr,
        )
        results = []
        for d in sorted(specs_dir.iterdir()):
            if d.is_dir() and (d / ".doorstop.yml").exists():
                results.append((d.name.upper(), d.name))
        return results

    docs: dict[str, dict] = {}

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

        docs[prefix] = {"subdir": subdir, "parent": parent}

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

    return [(pfx, docs[pfx]["subdir"]) for pfx in ordered]


def load_all_items(specs_dir: Path) -> list[dict]:
    """
    Load all active Doorstop items from every discovered document directory.
    Returns a flat list; inactive items (active: false) are excluded.
    """
    doc_types = discover_doc_types(specs_dir)
    all_items: list[dict] = []

    for prefix, subdir in doc_types:
        folder = specs_dir / subdir
        if not folder.is_dir():
            continue

        for item_path in sorted(folder.glob("*.md")) + sorted(
            p for p in folder.glob("*.yml") if p.name != ".doorstop.yml"
        ):
            try:
                item = parse_item(item_path)
            except Exception as exc:
                print(f"  Warning: could not parse {item_path}: {exc}", file=sys.stderr)
                continue

            # Skip inactive items
            if str(item.get("active", "true")).lower() == "false":
                continue

            item["_prefix"] = prefix
            all_items.append(item)

    return all_items


# ---------------------------------------------------------------------------
# Graph data builder
# ---------------------------------------------------------------------------


def build_graph_data(items: list[dict]) -> tuple[list[dict], list[dict]]:
    """
    Build Cytoscape node and edge element lists from the parsed item list.

    Node data fields:
      id       — UID (e.g. 'SRS-049')
      label    — H1 title truncated to 60 chars (full title in tooltip)
      fullLabel— untruncated H1 title
      prefix   — document prefix (e.g. 'SRS')
      covered  — True when the item has at least one upward link

    Edges go child → parent (upward traceability).
    """
    uid_set = {item["uid"] for item in items}

    nodes: list[dict] = []
    edges: list[dict] = []

    for item in items:
        uid = item["uid"]
        full_label = item.get("title") or uid
        label = full_label if len(full_label) <= 60 else full_label[:57] + "…"
        parents: list[str] = item.get("_parents") or []

        nodes.append({
            "data": {
                "id": uid,
                "label": label,
                "fullLabel": full_label,
                "prefix": item.get("_prefix", uid.split("-")[0]),
                "covered": bool(parents),
            }
        })

        for parent_uid in parents:
            if parent_uid in uid_set:
                edge_id = f"{uid}__{parent_uid}"
                edges.append({
                    "data": {
                        "id": edge_id,
                        "source": uid,
                        "target": parent_uid,
                    }
                })

    return nodes, edges


# ---------------------------------------------------------------------------
# JS/CSS asset fetching
# ---------------------------------------------------------------------------


def _fetch_asset(url: str) -> str:
    """Fetch a URL and return its text content, or raise URLError."""
    with urlopen(url, timeout=20) as resp:
        return resp.read().decode("utf-8")


def fetch_assets() -> tuple[str, str, str]:
    """
    Fetch Cytoscape.js, dagre, and cytoscape-dagre from CDN.
    Returns (cytoscape_js, dagre_js, cy_dagre_js).
    Raises SystemExit with instructions if any fetch fails.
    """
    urls = [
        ("Cytoscape.js", _CYTOSCAPE_URL),
        ("dagre",        _DAGRE_URL),
        ("cytoscape-dagre", _CY_DAGRE_URL),
    ]
    results = []
    for name, url in urls:
        try:
            print(f"  Fetching {name} from {url} …", end=" ", flush=True)
            js = _fetch_asset(url)
            print(f"OK ({len(js):,} bytes)")
            results.append(js)
        except URLError as exc:
            print(f"FAILED: {exc}", file=sys.stderr)
            print(
                "\nCould not download JavaScript assets required for offline operation.\n"
                "Ensure internet access when generating specs-graph.html, or manually\n"
                "download and place the following files alongside c5graph.py:\n"
                f"  cytoscape.min.js  — {_CYTOSCAPE_URL}\n"
                f"  dagre.min.js      — {_DAGRE_URL}\n"
                f"  cytoscape-dagre.min.js — {_CY_DAGRE_URL}\n",
                file=sys.stderr,
            )
            sys.exit(1)

    return results[0], results[1], results[2]


def load_local_assets(script_dir: Path) -> tuple[str, str, str] | None:
    """
    Check for pre-downloaded asset files alongside the script.
    Returns (cytoscape_js, dagre_js, cy_dagre_js) or None.
    """
    names = ["cytoscape.min.js", "dagre.min.js", "cytoscape-dagre.min.js"]
    paths = [script_dir / n for n in names]
    if all(p.exists() for p in paths):
        return tuple(p.read_text(encoding="utf-8") for p in paths)
    return None


# ---------------------------------------------------------------------------
# HTML generation
# ---------------------------------------------------------------------------

# Paths to the dedicated CSS / JS asset files, relative to this script.
_CSS_FILE = SCRIPT_DIR / "assets" / "css" / "c5graph.css"
_JS_FILE  = SCRIPT_DIR / "assets" / "js"  / "c5graph.js"


def _load_static_assets() -> tuple[str, str]:
    """
    Read the CSS and JS source files from the assets/ sub-directories.
    Returns (css_text, js_template_text).
    The JS text still contains the __NODES_JSON__ / __EDGES_JSON__ sentinels
    that build_html() will substitute with the actual graph data.
    """
    if not _CSS_FILE.exists():
        raise FileNotFoundError(
            f"CSS asset not found: {_CSS_FILE}\n"
            "Expected: SpecEngine/assets/css/c5graph.css"
        )
    if not _JS_FILE.exists():
        raise FileNotFoundError(
            f"JS asset not found: {_JS_FILE}\n"
            "Expected: SpecEngine/assets/js/c5graph.js"
        )
    return (
        _CSS_FILE.read_text(encoding="utf-8"),
        _JS_FILE.read_text(encoding="utf-8"),
    )

# JS source has been moved to: assets/js/c5graph.js
# build_html() reads that file at runtime and substitutes two sentinels:
#   __NODES_JSON__  →  Cytoscape node elements JSON array
#   __EDGES_JSON__  →  Cytoscape edge elements JSON array


def build_html(
    nodes: list[dict],
    edges: list[dict],
    cytoscape_js: str,
    dagre_js: str,
    cy_dagre_js: str,
    css: str,
    page_js_tpl: str,
) -> str:
    """
    Assemble the final self-contained HTML string.

    Parameters
    ----------
    nodes / edges     : Cytoscape element dicts produced by build_graph_data().
    cytoscape_js      : Full text of cytoscape.min.js (fetched from CDN or local).
    dagre_js          : Full text of dagre.min.js.
    cy_dagre_js       : Full text of cytoscape-dagre.min.js.
    css               : Content of assets/css/c5graph.css.
    page_js_tpl       : Content of assets/js/c5graph.js (sentinels not yet replaced).
    """
    today = datetime.date.today().isoformat()
    nodes_json = json.dumps(nodes, indent=None, separators=(",", ":"))
    edges_json = json.dumps(edges, indent=None, separators=(",", ":"))

    page_js = (
        page_js_tpl
        .replace("__NODES_JSON__", nodes_json)
        .replace("__EDGES_JSON__", edges_json)
    )

    total_nodes = len(nodes)
    covered = sum(1 for n in nodes if n["data"]["covered"])
    uncovered = total_nodes - covered

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>C5-DEC Specs Graph — {today}</title>
<style>
{css}
</style>
</head>
<body>
<div id="header">
  <h1>C5-DEC Specification Graph</h1>
  <div class="meta">Generated {today} &mdash; {total_nodes} nodes
    (<span style="color:#27ae60">{covered} covered</span> /
     <span style="color:#f1c40f">{uncovered} uncovered</span>)
  </div>
  <div id="controls">
    <button id="btn-expand-all">Expand all</button>
    <button id="btn-reset">Reset view</button>
    <button id="btn-fit">Fit</button>
    <button id="btn-png">Save PNG</button>
    <input id="search-box" type="text" placeholder="Search UID or title…"/>
  </div>
  <div id="legend">
    <span><span class="leg-dot leg-green"></span>covered (has link)</span>
    <span><span class="leg-dot leg-yellow"></span>uncovered (no link)</span>
    <span style="font-size:0.72rem;color:#888">Click node to expand/collapse children</span>
  </div>
</div>
<div id="cy-wrapper">
  <div id="cy"></div>
  <div id="tooltip"></div>
</div>
<script>
/* cytoscape.js */
{cytoscape_js}
</script>
<script>
/* dagre */
{dagre_js}
</script>
<script>
/* cytoscape-dagre */
{cy_dagre_js}
</script>
<script>
{page_js}
</script>
</body>
</html>
"""
    return html


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Generate a self-contained Cytoscape.js traceability graph "
                    "for all Doorstop specifications.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Path for the output HTML file (default: <specs-dir>/../traceability/specs-graph.html).",
    )
    parser.add_argument(
        "--specs-dir", "-s",
        default=None,
        help="Root directory containing Doorstop documents (default: auto-detected).",
    )
    args = parser.parse_args()

    # Resolve specs directory
    if args.specs_dir:
        specs_dir = Path(args.specs_dir).resolve()
    else:
        # Walk up from the script directory looking for a 'specs' folder
        candidate = SCRIPT_DIR.parent
        if (candidate / "srs").is_dir() or (candidate / "mrs").is_dir():
            specs_dir = candidate
        else:
            specs_dir = Path.cwd()

    # Resolve output path
    if args.output:
        output_path = Path(args.output).resolve()
    else:
        # Default: docs/specs/docs/publish/specs-graph.html
        publish_dir = specs_dir / "docs" / "publish"
        if publish_dir.is_dir():
            output_path = publish_dir / "specs-graph.html"
        else:
            # Fallback: traceability dir, then parent
            traceability_dir = specs_dir.parent / "traceability"
            if traceability_dir.is_dir():
                output_path = traceability_dir / "specs-graph.html"
            else:
                output_path = specs_dir.parent / "specs-graph.html"

    print(f"C5-DEC Spec Graph Generator")
    print(f"  Specs directory : {specs_dir}")
    print(f"  Output          : {output_path}")

    # Load items
    print("Loading items …")
    items = load_all_items(specs_dir)
    print(f"  Loaded {len(items)} active items.")

    if not items:
        print("No active items found — nothing to render.", file=sys.stderr)
        sys.exit(1)

    # Build graph data
    nodes, edges = build_graph_data(items)
    covered = sum(1 for n in nodes if n["data"]["covered"])
    print(f"  Graph: {len(nodes)} nodes ({covered} covered), {len(edges)} edges.")

    # Load CSS / JS source assets from SpecEngine/assets/
    css, page_js_tpl = _load_static_assets()

    # Fetch / load CDN JS libraries (Cytoscape, dagre, cytoscape-dagre)
    local = load_local_assets(SCRIPT_DIR)
    if local:
        print("Using locally cached JS assets.")
        cytoscape_js, dagre_js, cy_dagre_js = local
    else:
        print("Fetching JS assets from CDN …")
        cytoscape_js, dagre_js, cy_dagre_js = fetch_assets()

    # Generate HTML
    print("Generating HTML …")
    html = build_html(nodes, edges, cytoscape_js, dagre_js, cy_dagre_js, css, page_js_tpl)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    size_kb = output_path.stat().st_size // 1024
    print(f"  Written {size_kb:,} KB → {output_path}")


if __name__ == "__main__":
    main()
