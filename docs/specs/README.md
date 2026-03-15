# Technical specifications aimed at traceability

This folder holds the authoritative, traceable specifications for IDPS-ESCAPE managed with Doorstop following the [C5-DEC](https://github.com/AbstractionsLab/c5dec) methodology and its enhancements to Doorstop via extra custom code and templates. Use it for defining what the system must do and why, not how to operate it.

## What lives here

| Path | Document type | Role in hierarchy |
|------|--------------|-------------------|
| `mrs/` | Mission Requirements Specifications | Root of the tree |
| `srs/` | Software/System Requirements Specifications | Child of MRS |
| `harc/` | High-level architecture | Child of MRS |
| `larc/` | Low-level architecture | Child of SRS |
| `swd/` | Software design | Child of LARC |
| `tst/` | Test cases | Child of SRS |
| `trp/` | Test execution reports | Child of TST |
| `SpecEngine/` | Python tooling scripts for publishing, analysis, and graph generation | See [SpecEngine](#specengine-tooling) |
| `docs/publish/` | Generated HTML output | Produced by `publish.sh` |

### Custom tooling scripts

All scripts live under `SpecEngine/`. The top-level `publish.sh` orchestrates the full pipeline by calling them in sequence.

| Script | Purpose |
|--------|---------|
| `publish.sh` | Orchestrates the full publish pipeline (keyword replacement → Mermaid rendering → HTML generation → traceability stats → graph) |
| `SpecEngine/c5publish.py` | Invokes the Doorstop HTML publisher, applies Bootstrap CSS patches, linkifies item IDs, and injects navigation links to tooling reports |
| `SpecEngine/c5-keyword.py` | Preprocessor/postprocessor that replaces `?c5-defect-X` shorthand keywords with styled HTML spans in TRP files before publishing, then restores originals |
| `SpecEngine/c5mermaid.py` | Renders fenced Mermaid code blocks in item `.md` files to SVG/PNG via the Mermaid CLI and replaces them with image references (idempotent) |
| `SpecEngine/c5traceability.py` | Analyses the Doorstop traceability CSV and reports coverage statistics (see [below](#traceability-statistics)) |
| `SpecEngine/c5browser.py` | Generates an interactive HTML browser (`items_browser.html`) with sortable/filterable DataTables for every document type (see [below](#specification-browser)) |
| `SpecEngine/c5graph.py` | Generates an interactive Cytoscape.js dependency graph (`specs-graph.html`) of the full item tree (see [below](#traceability-graph)) |
| `SpecEngine/prune_bad_links.py` | Removes Doorstop `links:` entries that violate the parent-document constraint |
| `SpecEngine/doorstop_yml_to_md.py` | One-time migration script that converts legacy pure-YAML item files (`.yml`) to Markdown-with-YAML-frontmatter (`.md`) |

## Doorstop hierarchy

```
MRS ──┬──> SRS ──┬──> LARC ──> SWD
      │          └──> TST  ──> TRP
      └──> HARC
```

Links are **upward-only** (child → parent). Adding downward links causes `RecursionError` during publishing.

## Conventions

- **Numbering**: three digits per prefix (e.g., `SRS-001`) as set in each `.doorstop.yml`.
- **Format**: markdown items with YAML frontmatter followed by a markdown body.
- **Assets**: place supporting files per document under its `assets/` subfolder (e.g., `harc/assets/`, `tst/assets/`).
- **Diagrams**: prefer PlantUML in assets; avoid Mermaid in specs.
- **Review hashes**: Doorstop fingerprints change when text or reviewed attributes update — re-review after edits with `poetry run doorstop review <uid>`.
- **Named items**: items like `MRS-ADBox` and `SRS-SONAR` are group-summary placeholders used for organisational purposes; they are excluded from numeric coverage statistics by default.

## Working with items

```bash
# Validate the tree
poetry run doorstop

# Add a new item (auto UID)
poetry run doorstop add srs

# Link child to parent (upward-only)
poetry run doorstop link TST-001 SRS-046

# Review an item after editing it
poetry run doorstop review SRS-001
```

## Publishing

```bash
cd docs/specs
./publish.sh
```

`publish.sh` runs the full pipeline:
1. `SpecEngine/c5-keyword.py` — replaces `?c5-defect-X` keywords in TRP files
2. `SpecEngine/c5mermaid.py` — renders Mermaid diagrams in spec items to SVG and replaces fenced blocks with image references
3. `SpecEngine/c5publish.py` — generates Bootstrap-styled HTML into `docs/publish/` with navigation links
4. `SpecEngine/c5-keyword.py` — restores original TRP files
5. `SpecEngine/c5mermaid.py undo` — restores readable ` ```mermaid ` blocks
6. `SpecEngine/c5traceability.py --html` — prints coverage statistics to the console and writes `docs/publish/traceability_stats.html`
7. `SpecEngine/c5browser.py` — generates the interactive item browser at `docs/publish/items_browser.html`
8. `SpecEngine/c5publish.py --linkify-only` — re-linkifies all HTML files now that tooling reports exist
9. `SpecEngine/c5graph.py` — generates the interactive traceability graph at `docs/publish/specs-graph.html`

## Traceability statistics

`SpecEngine/c5traceability.py` reads the Doorstop-generated `traceability.csv` (placed in `docs/publish/` after publishing) and produces eight sections of coverage analysis. Behaviour is driven by `SpecEngine/c5traceability_config.yaml`; a fully documented example is in `SpecEngine/c5traceability_config_example.yaml`.

| Section | What it checks |
|---------|---------------|
| 1. Summary totals | Unique item count per document type |
| 2. SRS test coverage | SRS items with no TST link — untested/unimplemented requirements |
| 3. SRS design coverage | SRS items with no LARC or SWD link — no design documentation |
| 4. MRS specification coverage | MRS items with no SRS child — mission needs not yet specified |
| 5. HARC implementation coverage | HARC items not linked to any SRS — architecture decisions without requirements |
| 6. TST execution coverage | TST items with no TRP report — test cases never executed |
| 7. Defect severity summary | Scans TRP files for `?c5-defect-X` and summarizes severity distribution; flags major/critical items (level ≥ 3) |
| 8. Overall health score | Aggregate coverage percentage across all five metrics with a progress bar |

Output is colour-coded in the terminal using `rich` (falls back to plain text if unavailable). The HTML report uses Bootstrap and is placed at `docs/publish/traceability_stats.html`.

```bash
cd docs/specs

# Console output with default config
poetry run python SpecEngine/c5traceability.py --config SpecEngine/c5traceability_config.yaml

# Console + HTML report
poetry run python SpecEngine/c5traceability.py --config SpecEngine/c5traceability_config.yaml --html

# Print auto-discovered config (does not run analysis)
poetry run python SpecEngine/c5traceability.py --discover

# Custom CSV path and output location
poetry run python SpecEngine/c5traceability.py --csv docs/publish/traceability.csv --html --output docs/publish/stats.html

# Include named/group items (e.g. MRS-ADBox) in statistics
poetry run python SpecEngine/c5traceability.py --include-named
```

## Specification browser

`SpecEngine/c5browser.py` scans all Doorstop subdirectories, parses each item's YAML frontmatter and H1 heading, and produces a standalone Bootstrap + DataTables HTML page at `docs/publish/items_browser.html`.

Features:
- **One tab per document type** — MRS, HARC, SRS, LARC, SWD, TST, TRP
- **Sortable columns** — click any header to sort ascending/descending
- **Per-tab filter** — DataTables search box filters rows by any visible column (e.g. type "RADAR" to show only RADAR items)
- **Numeric fields colour-coded** — urgency, importance, risk etc. are rendered with severity colours (green → red)
- **Defect badges** on TRP rows show severity level at a glance
- Named/group items (e.g. `MRS-ADBox`) are shown muted; `active: false` items are struck through

```bash
cd docs/specs

# Default output: docs/publish/items_browser.html
poetry run python SpecEngine/c5browser.py

# Custom output path
poetry run python SpecEngine/c5browser.py --output docs/publish/browser.html

# Custom specs directory
poetry run python SpecEngine/c5browser.py --specs-dir /path/to/specs
```

## Traceability graph

`SpecEngine/c5graph.py` generates a self-contained, interactive HTML graph (`docs/publish/specs-graph.html`) visualising the full Doorstop item dependency tree using Cytoscape.js with a Dagre hierarchical layout.

- **Green nodes** — items with at least one upward link (covered).
- **Yellow nodes** — items with no upward links (root / uncovered).
- **Expand/collapse** — initial view shows only MRS nodes and their direct children; click a node to expand or collapse its subtree.
- **Sidebar** — collapsible list with a filter input; clicking a node centres and highlights it in the graph.
- **Self-contained** — CDN libraries are inlined at generation time; the file can be opened directly without a server.

```bash
cd docs/specs

# Default output: docs/publish/specs-graph.html
poetry run python SpecEngine/c5graph.py

# Custom output path
poetry run python SpecEngine/c5graph.py --output docs/publish/graph.html

# Custom specs directory
poetry run python SpecEngine/c5graph.py --specs-dir /path/to/specs
```

## When to use which document

| Document | Use for |
|----------|---------|
| MRS | Mission and business needs; value and urgency |
| SRS | Software requirements and acceptance criteria |
| HARC | High-level architecture constraints and decisions |
| LARC | Detailed architecture and component design |
| SWD | Software design details and diagrams |
| TST | Test case specifications |
| TRP | Executed test reports with defect categorization |

For detailed rules and examples, see the per-folder `.doorstop.yml` defaults, and `SpecEngine/README.md`.