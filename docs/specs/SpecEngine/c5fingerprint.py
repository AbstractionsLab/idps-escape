#!/usr/bin/env python3
"""c5fingerprint.py – Compute and store dependency content fingerprints in Doorstop items.

For each Doorstop item that has a ``references:`` list containing file paths,
this script hashes the content of every referenced file and stores both a
per-file breakdown and a combined hash as ``references_content_fingerprint``
in the item's YAML frontmatter.

When a fingerprint differs from the stored value, the item is flagged as
*stale* — a warning is printed and (unless ``--dry-run`` / ``--check``) the
stored fingerprint is updated in-place.

This enables dependency-aware impact analysis: when a source file referenced
by a TCS item (or any other Doorstop document item) changes, the item will
show a stale fingerprint, alerting reviewers that the specification may need
to be revisited.

Usage::

    # Standard invocation (from docs/specs/ via publish.sh):
    poetry run python ./SpecEngine/c5fingerprint.py

    # Dry-run – compute only, no writes (exit 0):
    poetry run python ./SpecEngine/c5fingerprint.py --dry-run

    # Check mode – exit 1 if stale items found (CI gate):
    poetry run python ./SpecEngine/c5fingerprint.py --check

    # Verbose – show per-file hash details per item:
    poetry run python ./SpecEngine/c5fingerprint.py --verbose

    # Non-default paths:
    poetry run python ./SpecEngine/c5fingerprint.py \\
        --specs-dir /path/to/docs/specs \\
        --repo-root /path/to/repo/root

Stored fingerprint format in each item's YAML frontmatter::

    references_content_fingerprint:
      combined: 4a7b9c1d2e3f4a5b
      files:
        c5dec/core/cpssa/__init__.py: 9c0d1e2f3a4b5c6d
        c5dec/core/cpssa/cpssa.py: 1a2b3c4d5e6f7a8b

Files that are missing or inaccessible at the time of the run are recorded
as the sentinel value ``"missing"`` in the per-file dict and are excluded
from the combined hash computation.

Notes
-----
* Only ``references:`` entries that carry a ``path`` key are fingerprinted.
  URL-only entries or entries without a ``path`` are silently skipped.
* The field ``references_content_fingerprint`` is intentionally **not** added
  to ``attributes.reviewed`` in ``.doorstop.yml``, because it is a computed
  annotation rather than authored content.  Updating it does not cascade to
  require re-reviewing the item itself.
* The ``--check`` flag (exit code 1 on stale) is suitable as a CI gate that
  reminds reviewers to visit impacted items after source file changes.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required.  Install it with: pip install pyyaml")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: YAML field name written to each item's frontmatter.
FINGERPRINT_FIELD = "references_content_fingerprint"

#: Number of hex characters used for per-file and combined digests.
#: 16 hex chars = 64-bit prefix of SHA-256, sufficient for collision resistance
#: across a typical repository's reference set.
HASH_LENGTH = 16

#: Sentinel value stored for files that are missing or inaccessible.
MISSING_SENTINEL = "missing"


# ---------------------------------------------------------------------------
# Frontmatter helpers  (pattern from prune_bad_links.py)
# ---------------------------------------------------------------------------

# Matches the YAML frontmatter block between the first pair of --- delimiters.
_FM_RE = re.compile(r"\A---[ \t]*\r?\n(.*?)\r?\n---[ \t]*\r?\n", re.DOTALL)


def _extract_frontmatter(content: str) -> tuple[dict | None, str]:
    """Return ``(parsed_dict, body)`` from *content*, or ``(None, content)``."""
    m = _FM_RE.match(content)
    if not m:
        return None, content
    raw = m.group(1)
    try:
        parsed = yaml.safe_load(raw)
    except yaml.YAMLError:
        return None, content
    if not isinstance(parsed, dict):
        return None, content
    # body is everything after the closing '---\n' (may start with a blank line)
    body = content[m.end():]
    return parsed, body


def _serialize_frontmatter(meta: dict) -> str:
    """Serialise *meta* to a YAML string for frontmatter.

    Keys are sorted alphabetically (matching the SpecEngine convention used by
    ``doorstop_yml_to_md.py``).  ``width=9999`` suppresses line-wrapping.
    """
    return yaml.dump(
        meta,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=True,
        width=9999,
    )


def _write_item(filepath: str, meta: dict, body: str) -> None:
    """Write *meta* as YAML frontmatter plus *body* back to *filepath*."""
    fm_yaml = _serialize_frontmatter(meta)
    # body already contains the blank-line separator (if any) that appeared
    # between the closing '---' and the Markdown heading in the original file.
    new_content = f"---\n{fm_yaml}---\n{body}"
    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write(new_content)


# ---------------------------------------------------------------------------
# Document discovery  (pattern from prune_bad_links.py)
# ---------------------------------------------------------------------------

def _find_doorstop_docs(specs_root: str) -> list[dict]:
    """Return one dict per Doorstop document found under *specs_root*.

    Each dict carries ``prefix`` (e.g. ``"TCS"``) and ``path`` (absolute
    directory path of the document folder).
    """
    docs: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(specs_root):
        dirnames.sort()
        if ".doorstop.yml" not in filenames:
            continue
        cfg_path = os.path.join(dirpath, ".doorstop.yml")
        try:
            with open(cfg_path, "r", encoding="utf-8") as fh:
                cfg = yaml.safe_load(fh) or {}
        except (OSError, yaml.YAMLError) as exc:
            print(f"  WARNING: could not read {cfg_path}: {exc}", file=sys.stderr)
            continue
        settings = cfg.get("settings", {}) or {}
        prefix = settings.get("prefix", "")
        if not prefix:
            print(
                f"  WARNING: no 'prefix' in {cfg_path}, skipping.",
                file=sys.stderr,
            )
            continue
        docs.append({"prefix": prefix, "path": dirpath})
    return docs


def _list_item_files(doc_path: str) -> list[str]:
    """Return sorted paths to item files (``.md`` / non-hidden ``.yml``) in *doc_path*."""
    items: list[str] = []
    try:
        entries = os.listdir(doc_path)
    except OSError:
        return items
    for fname in sorted(entries):
        if fname == ".doorstop.yml":
            continue
        if fname.startswith("."):
            continue
        if fname.endswith(".md") or fname.endswith(".yml"):
            fpath = os.path.join(doc_path, fname)
            if os.path.isfile(fpath):
                items.append(fpath)
    return items


# ---------------------------------------------------------------------------
# Hashing helpers  (pattern from c5mermaid.py::_content_hash)
# ---------------------------------------------------------------------------

def _file_hash(filepath: str) -> str:
    """Return a *HASH_LENGTH*-character hex SHA-256 digest of *filepath* bytes."""
    h = hashlib.sha256()
    with open(filepath, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:HASH_LENGTH]


def _combined_hash(file_hashes: dict[str, str]) -> str:
    """Return a *HASH_LENGTH*-character combined hash for *file_hashes*.

    The combined value is SHA-256 over the sorted ``"path:hash"`` pairs.
    Files recorded as ``MISSING_SENTINEL`` are excluded from the computation
    so that a missing reference does not mask changes in files that are present.
    """
    h = hashlib.sha256()
    for path in sorted(file_hashes):
        value = file_hashes[path]
        if value == MISSING_SENTINEL:
            continue
        h.update(f"{path}:{value}".encode("utf-8"))
    return h.hexdigest()[:HASH_LENGTH]


# ---------------------------------------------------------------------------
# References extraction
# ---------------------------------------------------------------------------

def _extract_file_references(meta: dict) -> list[str]:
    """Return the list of file paths from the item's ``references:`` list.

    Only entries that carry a ``path`` key are included.  Entries without a
    ``path`` (e.g. URL-only references) are silently skipped.  The ``type``
    field is not checked — any path-bearing entry is treated as a file
    reference regardless of the declared type.
    """
    references = meta.get("references") or []
    if not isinstance(references, list):
        return []
    paths: list[str] = []
    for entry in references:
        if not isinstance(entry, dict):
            continue
        path = entry.get("path")
        if path and isinstance(path, str):
            paths.append(path)
    return paths


# ---------------------------------------------------------------------------
# Fingerprint computation
# ---------------------------------------------------------------------------

def compute_fingerprint(file_paths: list[str], repo_root: str) -> dict:
    """Compute per-file SHA-256 hashes and a combined hash for *file_paths*.

    Each path in *file_paths* is resolved relative to *repo_root*.  Files that
    are missing or cannot be read are stored as ``MISSING_SENTINEL`` in the
    per-file dict and excluded from the combined hash.

    Returns a dict::

        {
            "combined": "<16-char hex>",
            "files": {
                "path/to/file.py": "<16-char hex>",
                "path/to/missing.py": "missing",
            }
        }
    """
    file_hashes: dict[str, str] = {}
    for rel_path in file_paths:
        abs_path = os.path.join(repo_root, rel_path)
        if os.path.isfile(abs_path):
            try:
                file_hashes[rel_path] = _file_hash(abs_path)
            except OSError:
                file_hashes[rel_path] = MISSING_SENTINEL
        else:
            file_hashes[rel_path] = MISSING_SENTINEL
    combined = _combined_hash(file_hashes)
    return {"combined": combined, "files": file_hashes}


# ---------------------------------------------------------------------------
# Fingerprint comparison
# ---------------------------------------------------------------------------

def _fingerprints_equal(stored: object, computed: dict) -> bool:
    """Return True when *stored* matches *computed* in both sub-fields."""
    if not isinstance(stored, dict):
        return False
    if stored.get("combined") != computed.get("combined"):
        return False
    if stored.get("files") != computed.get("files"):
        return False
    return True


# ---------------------------------------------------------------------------
# .doorstop.yml attribute registration
# ---------------------------------------------------------------------------

def _register_attribute(doc_path: str, dry_run: bool) -> bool:
    """Ensure ``references_content_fingerprint: {}`` appears in
    ``attributes.defaults`` of the ``.doorstop.yml`` file in *doc_path*.

    Uses PyYAML round-trip to safely add the attribute without disturbing the
    rest of the document structure.  Returns ``True`` when the file was (or
    would be) modified.
    """
    cfg_file = os.path.join(doc_path, ".doorstop.yml")
    try:
        with open(cfg_file, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return False

    # Fast check – field already declared somewhere in the file.
    if FINGERPRINT_FIELD in text:
        return False

    try:
        cfg = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        print(
            f"  WARNING: could not parse {cfg_file}: {exc}; "
            "skipping attribute registration.",
            file=sys.stderr,
        )
        return False

    # Inject into attributes.defaults, creating intermediate keys if needed.
    if "attributes" not in cfg or cfg["attributes"] is None:
        cfg["attributes"] = {}
    attrs = cfg["attributes"]
    if "defaults" not in attrs or attrs["defaults"] is None:
        attrs["defaults"] = {}
    attrs["defaults"][FINGERPRINT_FIELD] = {}

    if not dry_run:
        new_text = yaml.dump(
            cfg,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
        )
        with open(cfg_file, "w", encoding="utf-8") as fh:
            fh.write(new_text)
    return True


# ---------------------------------------------------------------------------
# Per-document processing
# ---------------------------------------------------------------------------

def process_document(
    doc: dict,
    repo_root: str,
    *,
    dry_run: bool = False,
    verbose: bool = False,
) -> tuple[int, int]:
    """Process all items in *doc*, updating stale fingerprints.

    Returns ``(stale_count, items_with_refs_count)``.
    """
    doc_path = doc["path"]
    prefix = doc["prefix"]
    stale = 0
    processed = 0

    for fpath in _list_item_files(doc_path):
        fname = os.path.basename(fpath)
        try:
            with open(fpath, "r", encoding="utf-8") as fh:
                content = fh.read()
        except OSError as exc:
            print(f"  WARNING: cannot read {fpath}: {exc}", file=sys.stderr)
            continue

        meta, body = _extract_frontmatter(content)
        if meta is None:
            continue

        file_refs = _extract_file_references(meta)
        if not file_refs:
            continue  # nothing to fingerprint in this item

        processed += 1
        uid = os.path.splitext(fname)[0]
        new_fp = compute_fingerprint(file_refs, repo_root)
        stored_fp = meta.get(FINGERPRINT_FIELD)

        # Warn once per missing referenced file.
        for rel_path, digest in new_fp["files"].items():
            if digest == MISSING_SENTINEL:
                print(
                    f"  WARNING: [{prefix}] {uid}: referenced file not found:"
                    f" {rel_path}",
                    file=sys.stderr,
                )

        if _fingerprints_equal(stored_fp, new_fp):
            if verbose:
                print(f"  [OK   ] {uid}: fingerprint current")
            continue

        # Determine which specific files changed (for verbose output).
        stale += 1
        if isinstance(stored_fp, dict) and "files" in stored_fp:
            changed = [
                p for p in new_fp["files"]
                if new_fp["files"][p] != stored_fp["files"].get(p)
            ]
        else:
            changed = list(new_fp["files"].keys())

        detail = (f": {', '.join(changed)}" if verbose else "")
        print(f"  [STALE] {uid}: {len(changed)} file(s) changed{detail}")

        if not dry_run:
            meta[FINGERPRINT_FIELD] = new_fp
            _write_item(fpath, meta, body)

    return stale, processed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    # Default paths derived from this script's location:
    #   docs/specs/SpecEngine/c5fingerprint.py
    #     -> specs root: docs/specs/        (1 level up)
    #     -> repo root:  <project root>     (3 levels up)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_specs = os.path.normpath(os.path.join(script_dir, ".."))
    default_repo = os.path.normpath(os.path.join(script_dir, "..", "..", ".."))

    parser = argparse.ArgumentParser(
        description=(
            "Compute and store dependency content fingerprints in Doorstop items.\n\n"
            "Items that carry a 'references:' list with file paths have per-file\n"
            "SHA-256 hashes and a combined hash stored under the field\n"
            f"'{FINGERPRINT_FIELD}'.  Items whose fingerprint has changed\n"
            "since the last run are flagged as [STALE] in the output.\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--specs-dir",
        default=default_specs,
        metavar="PATH",
        help=f"Root of the Doorstop specs tree to scan (default: {default_specs})",
    )
    parser.add_argument(
        "--repo-root",
        default=default_repo,
        metavar="PATH",
        help=(
            f"Repository root for resolving reference paths (default: {default_repo})"
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute fingerprints but do not write any files.  Exits with 0.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Compute fingerprints but do not write any files.  "
            "Exits with 1 if any stale items are found (CI gate)."
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print per-item and per-file fingerprint details.",
    )
    args = parser.parse_args()

    # --check implies --dry-run
    if args.check:
        args.dry_run = True

    specs_root = os.path.abspath(args.specs_dir)
    repo_root = os.path.abspath(args.repo_root)

    if not os.path.isdir(specs_root):
        sys.exit(f"ERROR: specs directory not found: {specs_root}")
    if not os.path.isdir(repo_root):
        sys.exit(f"ERROR: repo root not found: {repo_root}")

    if args.dry_run:
        mode_label = "CHECK" if args.check else "DRY RUN"
        print(f"=== {mode_label} – no files will be modified ===\n")

    docs = _find_doorstop_docs(specs_root)
    if not docs:
        sys.exit(f"No Doorstop documents found under: {specs_root}")

    total_stale = 0
    total_processed = 0
    docs_with_refs: list[str] = []

    for doc in sorted(docs, key=lambda d: d["prefix"]):
        prefix = doc["prefix"]
        stale, processed = process_document(
            doc,
            repo_root,
            dry_run=args.dry_run,
            verbose=args.verbose,
        )
        if processed:
            docs_with_refs.append(doc["path"])
        total_stale += stale
        total_processed += processed

        if args.verbose and processed:
            print(
                f"  [{prefix}] {processed} item(s) with references,"
                f" {stale} stale\n"
            )

    # Register the attribute default in .doorstop.yml for every document that
    # contains at least one item with a references: field.
    for doc_path in sorted(docs_with_refs):
        registered = _register_attribute(doc_path, dry_run=args.dry_run)
        if registered:
            cfg_rel = os.path.relpath(
                os.path.join(doc_path, ".doorstop.yml"), repo_root
            )
            action = "Would register" if args.dry_run else "Registered"
            print(
                f"  [INFO] {action} '{FINGERPRINT_FIELD}' attribute"
                f" in {cfg_rel}"
            )

    # Summary line
    mode_suffix = " (dry run)" if args.dry_run else ""
    print(
        f"\nFingerprint scan complete{mode_suffix}: "
        f"{total_processed} item(s) with references, "
        f"{total_stale} stale."
    )

    if args.check and total_stale > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
