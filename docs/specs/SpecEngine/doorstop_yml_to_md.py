#!/usr/bin/env python3
"""
Doorstop YAML-to-Markdown migration script.

Converts Doorstop item files from pure YAML (.yml) to Markdown with YAML
frontmatter (.md), matching the format used in already-converted document
sets (TCS, TRP).

Conversion rules
----------------
* ``header`` field  → ``# Title`` as the first line of the Markdown body
                       (omitted when the value is empty/blank).
* ``text`` field    → Markdown body content (after the heading).
* Any other field whose *stripped* string value contains an embedded newline
  (i.e. is genuinely multi-paragraph prose) → appended to the body as a
  ``## field_name`` section (field removed from frontmatter).
* All remaining scalar / list fields → YAML frontmatter (alphabetically sorted,
  matching the style of TCS-001.md).
* Each ``.doorstop.yml`` is updated to ``itemformat: markdown``.

Usage
-----
    python scripts/doorstop_yml_to_md.py [folder ...]

If no folders are given the script defaults to the core spec
folders:
    docs/specs/arc  docs/specs/mrs  docs/specs/srs  docs/specs/swd
    docs/specs/tcs  docs/specs/trp

Options
-------
    --dry-run    Print what would be done without writing any files.
"""

import argparse
import re
import sys
from pathlib import Path

import yaml

# ---------------------------------------------------------------------------
# Default target folders (relative to the repo root – resolved at runtime)
# ---------------------------------------------------------------------------
DEFAULT_FOLDERS = [
    "docs/specs/arc",
    "docs/specs/mrs",
    "docs/specs/srs",
    "docs/specs/swd",
    "docs/specs/tcs",
    "docs/specs/trp",
]

# Fields that are ALWAYS kept in the YAML frontmatter regardless of their
# value type, because they are structural / link / identity fields and not
# prose content.
STRUCTURAL_KEYS = {
    "active",
    "derived",
    "level",
    "links",
    "normative",
    "ref",
    "reviewed",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_prose_multiline(value: object) -> bool:
    """Return True when *value* is a string with multiple lines of content.

    A YAML literal-block scalar that contains exactly one line of prose (plus
    the mandatory trailing newline) is treated as a plain scalar and kept in
    the frontmatter.  Only values that, once stripped, still contain an
    embedded ``\\n`` are moved to the Markdown body.
    """
    if not isinstance(value, str):
        return False
    return "\n" in value.strip()


def _normalize_scalars(value: object) -> object:
    """Recursively strip trailing whitespace from string scalars.

    YAML literal-block scalars (``|``) always carry a trailing newline when
    loaded.  This step normalises those trailing newlines so that
    ``yaml.dump`` emits clean plain scalars rather than quoted/block ones.
    """
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        return {k: _normalize_scalars(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize_scalars(item) for item in value]
    return value


def _frontmatter_yaml(data: dict) -> str:
    """Serialise *data* to a YAML string suitable for frontmatter.

    Keys are sorted alphabetically (matching the TCS/TRP convention).
    ``width=9999`` prevents PyYAML from wrapping long single-line values.
    """
    return yaml.dump(
        _normalize_scalars(data),
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=True,
        width=9999,
    )


# ---------------------------------------------------------------------------
# Per-file conversion
# ---------------------------------------------------------------------------

def convert_item(yml_path: Path, dry_run: bool = False) -> str:
    """Convert a single ``.yml`` Doorstop item to ``.md`` format.

    Returns one of: ``"converted"``, ``"skipped"`` (already exists), or
    ``"invalid"`` (not a YAML mapping).
    """
    md_path = yml_path.with_suffix(".md")

    if md_path.exists():
        return "skipped"

    raw = yml_path.read_text(encoding="utf-8")
    data: object = yaml.safe_load(raw)

    if not isinstance(data, dict):
        return "invalid"

    # --- extract header and text (always go to body) ----------------------
    header: str = (data.pop("header", None) or "").strip()
    text: str = (data.pop("text", None) or "").strip()

    # --- extract other prose multiline fields (in original key order) -----
    # We iterate over a snapshot of the keys so we can pop while iterating.
    prose_extras = []  # type: list
    for key in list(data.keys()):
        if key not in STRUCTURAL_KEYS and _is_prose_multiline(data[key]):
            prose_extras.append((key, data.pop(key).strip()))

    # --- build Markdown body ----------------------------------------------
    body_parts = []  # type: list
    if header:
        body_parts.append(f"# {header}")
    if text:
        body_parts.append(text)
    for field, content in prose_extras:
        body_parts.append(f"## {field}\n\n{content}")

    body = "\n\n".join(body_parts)

    # --- compose final file content ---------------------------------------
    fm = _frontmatter_yaml(data)
    if body:
        md_content = f"---\n{fm}---\n\n{body}\n"
    else:
        md_content = f"---\n{fm}---\n"

    if not dry_run:
        md_path.write_text(md_content, encoding="utf-8")
        yml_path.unlink()

    return "converted"


# ---------------------------------------------------------------------------
# .doorstop.yml update
# ---------------------------------------------------------------------------

def update_doorstop_config(config_path: Path, dry_run: bool = False) -> bool:
    """Set ``itemformat: markdown`` in a ``.doorstop.yml`` file.

    Returns True when the file was (or would be) modified.
    """
    text = config_path.read_text(encoding="utf-8")
    original = text

    if re.search(r"itemformat\s*:", text):
        # Replace existing value
        text = re.sub(r"(itemformat\s*:\s*)\S+", r"\1markdown", text)
    else:
        # Insert after the ``sep: ...`` line inside the settings block.
        # Falls back to inserting after the ``digits: ...`` line.
        for pattern in (r"(  sep\s*:.*\n)", r"(  digits\s*:.*\n)"):
            new_text, n = re.subn(pattern, r"\1  itemformat: markdown\n", text, count=1)
            if n:
                text = new_text
                break

    if text == original:
        return False

    if not dry_run:
        config_path.write_text(text, encoding="utf-8")

    return True


# ---------------------------------------------------------------------------
# Folder-level processing
# ---------------------------------------------------------------------------

def process_folder(folder: Path, dry_run: bool = False) -> dict:
    """Process all ``.yml`` item files in *folder*.

    Returns a summary dict with counts.
    """
    counts = {"converted": 0, "skipped": 0, "invalid": 0}

    yml_files = sorted(
        p for p in folder.iterdir()
        if p.suffix == ".yml" and p.name != ".doorstop.yml"
    )

    for yml_path in yml_files:
        result = convert_item(yml_path, dry_run=dry_run)
        counts[result] += 1
        label = {"converted": "CONVERT", "skipped": "SKIP   ", "invalid": "INVALID"}[result]
        print(f"  [{label}] {yml_path.name}")

    # Update .doorstop.yml
    config_path = folder / ".doorstop.yml"
    if config_path.exists():
        changed = update_doorstop_config(config_path, dry_run=dry_run)
        tag = "UPDATE " if changed else "NOCHANGE"
        print(f"  [{tag}] .doorstop.yml")
    else:
        print(f"  [MISSING] .doorstop.yml not found")

    return counts


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert Doorstop YAML items to Markdown frontmatter format."
    )
    parser.add_argument(
        "folders",
        nargs="*",
        help="Folders to process (default: the seven YAML-format spec folders).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned actions without writing any files.",
    )
    args = parser.parse_args()

    # Resolve folders relative to the script's parent's parent (repo root)
    repo_root = Path(__file__).resolve().parent.parent
    if args.folders:
        folders = [Path(f).resolve() for f in args.folders]
    else:
        folders = [repo_root / rel for rel in DEFAULT_FOLDERS]

    if args.dry_run:
        print("DRY-RUN mode – no files will be written.\n")

    total = {"converted": 0, "skipped": 0, "invalid": 0}

    for folder in folders:
        if not folder.is_dir():
            print(f"[WARNING] Not a directory, skipping: {folder}")
            continue
        print(f"\n{'(dry-run) ' if args.dry_run else ''}Processing: {folder}")
        counts = process_folder(folder, dry_run=args.dry_run)
        for k, v in counts.items():
            total[k] += v

    print("\n" + "=" * 50)
    print(f"Summary: {total['converted']} converted, "
          f"{total['skipped']} skipped (already .md), "
          f"{total['invalid']} invalid.")
    if args.dry_run:
        print("(dry-run: no files were written)")


if __name__ == "__main__":
    main()
