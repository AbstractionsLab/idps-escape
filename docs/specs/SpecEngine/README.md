# SpecEngine

A collection of Python utilities for managing, publishing, and analysing C5-DEC Doorstop specification trees. The scripts are designed to work together as a post-processing toolchain on top of the Doorstop requirements management tool.

---

## Scripts

### `c5traceability.py`

Computes traceability coverage statistics from a Doorstop-generated `traceability.csv` file and renders the results to the console and/or to a self-contained Bootstrap HTML report (`traceability_stats.html`).

**How it works:**

1. **Config loading** — reads a YAML config file (`c5traceability_config.yaml` by default) that declares:
   - `document_order` — the list of document prefixes shown in the summary table.
   - `checks` — a list of coverage checks, each specifying a `subject` document column and one or more `linked` document columns. An item is considered *covered* when at least one linked column contains a value in the same CSV row.
   - `defect_sources` — documents whose `.md` files are scanned for `?c5-defect-X` keywords (levels 0–4).
2. **Auto-discover mode** — if `--discover` is passed, the script walks the specs directory looking for `.doorstop.yml` files to infer the document tree automatically, building a config without requiring a hand-written YAML file.
3. **CSV parsing** — reads the Doorstop traceability CSV, grouping values by column. Named/group items (e.g. `MRS-ADBox`) are excluded by default.
4. **Coverage computation** — for every check, each unique subject UID is looked up and all linked UIDs in the same rows are collected. Covered = at least one linked value found.
5. **Defect scanning** — scans the body text (or a configured YAML frontmatter field) of each `.md` file in each defect-source document for `?c5-defect-0` … `?c5-defect-4` keywords. Items with level ≥ 3 are reported separately.
6. **Health score** — aggregates all coverage percentages across all checks into a single overall score.
7. **Output** — results are printed to the console (with optional `rich` formatting) and, when `--html` is given, written to an HTML file with a Bootstrap table layout, progress bars, and a navigation pill row.

**Optional dependency:** `rich` (for formatted console output); falls back to plain text if not installed.

**Usage:**

```bash
# Console output with default config
python c5traceability.py

# Console + HTML report
python c5traceability.py --html

# Custom config file
python c5traceability.py --config my_config.yaml

# Print auto-discovered config (does not run analysis)
python c5traceability.py --discover

# Write auto-discovered config to file, then run analysis
python c5traceability.py --discover --discover-write

# Custom CSV source and HTML output path
python c5traceability.py --csv path/to/traceability.csv --html --output report.html
```

---

### `c5browser.py`

Generates a standalone HTML specification browser (`items_browser.html`) containing one sortable, filterable table per Doorstop document type. The page uses Bootstrap 5 and DataTables and requires no server — it can be opened directly in a browser.

**How it works:**

1. **Document discovery** — reads every `.doorstop.yml` file found under the specs directory to determine document prefixes, subdirectories, and parent relationships. The list is topologically sorted (parents before children). Falls back to a static `DOC_TYPES` list if discovery finds nothing.
2. **Item parsing** — loads every `.md` (Markdown-frontmatter format) and `.yml` (pure YAML format) file from each document directory. For `.md` files the YAML frontmatter is extracted with a lightweight parser; for `.yml` files `pyyaml` is used directly. The `title` is taken from the first H1 heading (Markdown) or the `header` / first `text` line (YAML). Parent UIDs are extracted from the `links:` field.
3. **Column mapping** — each document type has a predefined list of `(field_key, display_label, sort_type)` columns. Numeric fields (urgency, importance, risk, etc.) are cast to integers for correct DataTables sorting. Unknown document types (discovered but not in the column map) receive a minimal default set of columns.
4. **Defect badge rendering** — `?c5-defect-X` keywords found in item frontmatter fields are replaced with colour-coded Bootstrap badges.
5. **HTML generation** — a single, self-contained HTML string is assembled with all CDN links (Bootstrap, jQuery, DataTables), one `<section>` per document type, and a sticky navigation bar to jump between them.

**Usage:**

```bash
# Default output (docs/publish/items_browser.html)
poetry run python c5browser.py

# Custom output path
poetry run python c5browser.py --output path/to/out.html

# Custom specs directory
poetry run python c5browser.py --specs-dir path/to/specs/
```

---

### `c5fingerprint.py`

Computes and stores dependency content fingerprints in Doorstop items, enabling dependency-aware impact analysis when referenced source files change.

**Role in the pipeline:**

Each Doorstop item may carry a `references:` list pointing to source files (e.g. a TCS item referencing the implementation files it covers). `c5fingerprint.py` hashes the content of those files and stores the result as `references_content_fingerprint` in the item's YAML frontmatter. When a referenced file changes, the stored fingerprint becomes *stale*, alerting reviewers that the item may need to be revisited. This creates a lightweight traceability link between specification items and their dependent source artifacts.

**How it works:**

1. **Document discovery** — walks the specs directory for `.doorstop.yml` files to identify all Doorstop documents and their item files (same discovery pattern as other SpecEngine scripts).
2. **Reference extraction** — for each item, parses the `references:` frontmatter list and collects every entry that carries a `path` key. URL-only or path-less entries are skipped.
3. **Per-file hashing** — each referenced path is resolved relative to the repository root and hashed with SHA-256 (truncated to 16 hex characters). Files that are missing or inaccessible are recorded as `"missing"` and excluded from the combined hash, so a missing file does not mask changes in files that are present.
4. **Combined hash** — a single combined digest is computed over the sorted `"path:hash"` pairs of all present files.
5. **Staleness check** — the newly computed fingerprint is compared against the stored `references_content_fingerprint` value. Items where any file hash has changed are flagged as `[STALE]`.
6. **In-place update** — unless `--dry-run` or `--check` is set, stale items are updated in place with the new fingerprint.
7. **Attribute registration** — for every document that contains at least one item with references, the `references_content_fingerprint: {}` default is injected into the document's `.doorstop.yml` `attributes.defaults` block (idempotent).

**Stored fingerprint format** (written into each item's YAML frontmatter):

```yaml
references_content_fingerprint:
  combined: 4a7b9c1d2e3f4a5b
  files:
    c5dec/core/cpssa/__init__.py: 9c0d1e2f3a4b5c6d
    c5dec/core/cpssa/cpssa.py: 1a2b3c4d5e6f7a8b
```

**Usage:**

```bash
# Standard invocation (from docs/specs/ via publish.sh)
poetry run python ./SpecEngine/c5fingerprint.py

# Dry-run – compute only, no writes (exit 0)
poetry run python ./SpecEngine/c5fingerprint.py --dry-run

# Check mode – exit 1 if stale items found (CI gate)
poetry run python ./SpecEngine/c5fingerprint.py --check

# Verbose – show per-file hash details per item
poetry run python ./SpecEngine/c5fingerprint.py --verbose

# Non-default paths
poetry run python ./SpecEngine/c5fingerprint.py \
    --specs-dir /path/to/docs/specs \
    --repo-root /path/to/repo/root
```

**Flags:**

| Flag | Effect |
|------|--------|
| `--dry-run` | Compute fingerprints but write nothing. Exits with 0. |
| `--check` | Implies `--dry-run`. Exits with 1 if any stale items are found. Suitable as a CI gate. |
| `--verbose` | Print per-item and per-file hash details alongside the `[OK]` / `[STALE]` status. |
| `--specs-dir PATH` | Override the specs root (default: parent of this script's directory). |
| `--repo-root PATH` | Override the repository root used to resolve reference paths. |

---

### `c5graph.py`

Generates a self-contained, interactive HTML graph (`specs-graph.html`) visualising the Doorstop item dependency tree using Cytoscape.js with the Dagre hierarchical layout.

**How it works:**

1. **Item loading** — same discovery and parsing pipeline as `c5browser.py`: reads `.doorstop.yml` files for document structure, then loads all active `.md` / `.yml` items. Items with `active: false` are excluded.
2. **Graph data building** — each item becomes a Cytoscape node. Each entry in an item's `links:` field creates a directed edge from the child item to the parent. Node colour indicates coverage:
   - Green — item has at least one upward link (covered).
   - Yellow — item has no upward links (root / uncovered).
3. **CDN inlining** — the Cytoscape.js, Dagre, and cytoscape-dagre libraries are fetched at generation time from their CDN URLs and embedded directly in the HTML output so the file is fully self-contained. If a CDN fetch fails, the script falls back to empty strings (the graph will not render without the libraries).
4. **Initial view** — on load only the top-level MRS nodes and their direct children are visible. Clicking a node expands its subtree; clicking again collapses it.
5. **Sidebar** — a collapsible sidebar lists all nodes with a filter input. Clicking a node in the sidebar centres and highlights it in the graph.

**Usage:**

```bash
# Default output (docs/publish/specs-graph.html)
poetry run python c5graph.py

# Custom output path
poetry run python c5graph.py --output path/to/out.html

# Custom specs directory
poetry run python c5graph.py --specs-dir path/to/specs/
```

---

### `c5publish.py`

Publishes the full Doorstop specification tree to HTML using the `doorstop` library, then post-processes the output to improve styling, linkify item IDs, and inject links to the SpecEngine tooling reports.

**How it works:**

1. **Doorstop publishing** — calls `doorstop.publisher.publish(tree, path, ".html")` to render every document in the tree to an HTML file in `docs/publish/`.
2. **CC database exclusion** — when `--include-cc-db` is *not* given (the default), all `.doorstop.yml` files under the CC database directory are temporarily renamed to `disabled_doorstop.yml` before building the Doorstop tree, so Common Criteria reference items are excluded from the published output. They are renamed back after publishing completes.
3. **HTML post-processing** — the generated `index.html` is patched to:
   - Replace the default `<head>` block with local Bootstrap CSS references.
   - Add `table-striped table-condensed` classes to all `<table>` elements.
   - Inject a navigation section at the top of `<body>` with links to the browser, traceability statistics, and graph reports.
4. **CSS patch** — appends a responsive column-width fix to the Doorstop sidebar CSS.
5. **Linkification** — scans every published HTML file for bare Doorstop item IDs (e.g. `SRS-001`) and replaces them with relative hyperlinks (`<a href="SRS.html#SRS-001">SRS-001</a>`), skipping IDs already inside anchor tags.
6. **Linkify-only mode** — `--linkify-only` skips publishing entirely and re-runs only the linkification pass, useful after the other SpecEngine tools have generated their report files.

**Usage:**

```bash
# Publish without CC database (default)
python c5publish.py

# Publish including CC database items
python c5publish.py --include-cc-db

# Re-linkify an already-published folder without re-publishing
python c5publish.py --linkify-only

# Re-linkify a non-default folder
python c5publish.py --linkify-only --publish-folder /path/to/publish/
```

---

### `c5-keyword.py`

A two-way keyword substitution utility that replaces `?c5-defect-X` shorthand keywords in Markdown files with coloured HTML `<span>` elements, or reverts them back.

**How it works:**

The script maintains a `keyword_map` dictionary that associates each keyword (`?c5-defect-0` … `?c5-defect-4`) with an HTML tag name, a CSS colour, and a human-readable label. The two operations are:

- **`replace`** — iterates over every `.md` file in a given folder. For each file, every occurrence of a `?c5-defect-X` keyword is replaced with a `<span style="color:COLOR">LABEL</span>` element, making the defect level visible when the Markdown is rendered to HTML.
- **`undo`** — the reverse pass: scans for the generated `<span>` elements and substitutes the original `?c5-defect-X` keywords back in.

The colour coding is:

| Keyword | Colour | Label |
|---------|--------|-------|
| `?c5-defect-0` | green | `0 = flawless` |
| `?c5-defect-1` | SeaGreen | `1 = insignificant defect` |
| `?c5-defect-2` | orange | `2 = minor defect` |
| `?c5-defect-3` | DarkOrange | `3 = major defect` |
| `?c5-defect-4` | red | `4 = critical defect` |

**Usage:**

```bash
# Replace keywords in all .md files in a folder
python c5-keyword.py <folder_path> replace

# Undo replacements in all .md files in a folder
python c5-keyword.py <folder_path> undo
```

---

### `doorstop_yml_to_md.py`

A one-time migration script that converts Doorstop item files from the legacy pure-YAML (`.yml`) format to the Markdown-with-YAML-frontmatter (`.md`) format used by the C5-DEC project.

**How it works:**

For each `.yml` item file found in the target folders:

1. The file is loaded as a YAML mapping.
2. The `header` field is extracted and written as a `# Title` H1 heading at the top of the Markdown body.
3. The `text` field is appended to the Markdown body.
4. Any other field whose value contains embedded newlines (i.e. multi-paragraph prose) is moved to the Markdown body as a `## field_name` section.
5. All remaining scalar and list fields (including structural fields like `links`, `active`, `level`, `reviewed`) are written into the YAML frontmatter block, sorted alphabetically.
6. The resulting `.md` file is written alongside the original `.yml`, which is then deleted.
7. The document's `.doorstop.yml` configuration file is updated to set `itemformat: markdown`.

Items that already have a corresponding `.md` file are skipped. Files that do not parse as YAML mappings are flagged as invalid.

`--dry-run` prints what would happen without writing any files.

**Default target folders** (relative to the repo root):
`docs/specs/arc`, `docs/specs/mrs`, `docs/specs/srs`, `docs/specs/swd`, `docs/specs/tcs`, `docs/specs/trp`

**Usage:**

```bash
# Convert all default folders
python doorstop_yml_to_md.py

# Preview without writing
python doorstop_yml_to_md.py --dry-run

# Convert specific folders only
python doorstop_yml_to_md.py docs/specs/srs docs/specs/mrs
```

---

### `prune_bad_links.py`

Removes Doorstop `links:` entries that violate the Doorstop constraint that items may only link to items in their direct *parent* document.

**How it works:**

1. **Discovery** — walks the specs directory for `.doorstop.yml` files. Each one is read to extract the document `prefix` and `parent` prefix, building a full map of the document tree.
2. **Item scanning** — for each document, every item file (`.md` and `.yml`) is read. The YAML frontmatter is parsed to extract the `links:` list.
3. **Bad link detection** — a link is bad in three cases:
   - The item is in a root document (no parent) and has any link at all.
   - The link points to an item in the same document (self-link).
   - The link target's prefix does not match the document's declared parent prefix.
4. **Removal** — bad link lines are removed from the file's raw text using targeted regular expressions. If removing all links leaves an empty `links:` block, it is normalised to `links: []`.
5. **Dry-run mode** — `--dry-run` reports what would be changed without modifying any file.

**Usage:**

```bash
# Preview what would be removed (from the project root)
python docs/specs/SpecEngine/prune_bad_links.py --dry-run

# Apply removals
python docs/specs/SpecEngine/prune_bad_links.py

# Target a non-default specs directory
python docs/specs/SpecEngine/prune_bad_links.py --specs-dir /path/to/specs
```

---

## Configuration files

### `c5traceability_config.yaml`

The active configuration used by `c5traceability.py` for the current project. Contains the `document_order` list, the `checks` array defining which cross-document coverage relationships to evaluate, and the `defect_sources` list.

### `c5traceability_config_example.yaml`

A heavily commented reference configuration showing all available options for `c5traceability_config.yaml`, including examples of multi-source checks, defect source configuration with `frontmatter_field` and `guide_strip_heading`, and inline documentation for every field.

---

## Assets

| Path | Purpose |
|------|---------|
| `assets/css/c5graph.css` | Stylesheet for the graph page generated by `c5graph.py` |
| `assets/js/c5graph.js` | JavaScript for the interactive graph generated by `c5graph.py` |

---

## Typical workflow

```bash
# 1. Publish the Doorstop specification tree to HTML
python docs/specs/SpecEngine/c5publish.py

# 2. Generate the interactive specification browser
poetry run python docs/specs/SpecEngine/c5browser.py

# 3. Generate the traceability statistics report
python docs/specs/SpecEngine/c5traceability.py --html

# 4. Generate the interactive traceability graph
poetry run python docs/specs/SpecEngine/c5graph.py

# 5. Re-linkify all HTML files now that the tooling reports exist
python docs/specs/SpecEngine/c5publish.py --linkify-only
```

All HTML outputs land in `docs/publish/` and are linked from the `index.html` sidebar injected by `c5publish.py`.

---

## Dependencies

| Package | Required by | Notes |
|---------|-------------|-------|
| `doorstop` | `c5publish.py` | Core Doorstop library |
| `pyyaml` | all scripts | YAML parsing; most scripts include a minimal fallback parser |
| `rich` | `c5traceability.py` | Optional; improves console output formatting |
