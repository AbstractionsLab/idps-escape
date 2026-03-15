#!/usr/bin/env python3
"""
prune_bad_links.py – Remove Doorstop links that violate the parent-document constraint.

For each Doorstop document (any folder containing a .doorstop.yml file), every
item file (.md or .yml, excluding .doorstop.yml itself) is checked.  A link is
considered *bad* when:

  • The link target prefix does not match the document's declared parent prefix.
    Example: an SRS item that links to an ARC item is bad because SRS's parent
    is MRS, not ARC.
  • The document is a root document (no parent declared) and the item has any
    links at all.

Options
-------
    --specs-dir PATH   Root of the specs tree to scan.
                       Default: the ``specs/`` folder one level above this
                       script's directory (i.e. docs/specs relative to the
                       project root when the script lives in docs/specs/SpecEngine/).
    --dry-run          Report what would change without writing anything.
    -h / --help        Show this help message.

Examples
--------
    # Preview from the project root:
    python docs/specs/SpecEngine/prune_bad_links.py --dry-run

    # Apply changes:
    python docs/specs/SpecEngine/prune_bad_links.py

    # Scan a non-default specs tree:
    python docs/specs/SpecEngine/prune_bad_links.py --specs-dir /path/to/specs
"""

from __future__ import annotations

import argparse
import os
import re
import sys

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required.  Install it with: pip install pyyaml")


# ---------------------------------------------------------------------------
# Discovery helpers
# ---------------------------------------------------------------------------

def find_doorstop_docs(specs_root: str) -> list[dict]:
    """Walk *specs_root* and return one dict per Doorstop document found.

    A folder qualifies as a Doorstop document when it directly contains a
    ``.doorstop.yml`` file (subdirectories are walked separately).

    Returned keys per dict:
        prefix  – document prefix (e.g. ``"SRS"``)
        parent  – parent prefix string or ``None`` for root documents
        path    – absolute path to the document folder
    """
    docs: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(specs_root):
        # Sort dirnames in-place so os.walk visits them in a stable order.
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
        parent = settings.get("parent", None)
        if not prefix:
            print(
                f"  WARNING: no 'prefix' in {cfg_path}, skipping.",
                file=sys.stderr,
            )
            continue
        docs.append({"prefix": prefix, "parent": parent, "path": dirpath})
    return docs


def list_item_files(doc_path: str) -> list[str]:
    """Return sorted paths to item files (.md / non-hidden .yml) in *doc_path*.

    Only the top-level directory is considered (Doorstop items live directly
    inside their document folder, not in subdirectories).
    """
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
# Frontmatter parsing
# ---------------------------------------------------------------------------

# Matches the YAML frontmatter block (content between the first pair of ---).
_FM_RE = re.compile(r"\A---[ \t]*\r?\n(.*?)\r?\n---[ \t]*\r?\n", re.DOTALL)


def extract_frontmatter(content: str) -> tuple[dict | None, str | None]:
    """Return ``(parsed_dict, raw_yaml_str)`` or ``(None, None)`` if absent."""
    m = _FM_RE.match(content)
    if not m:
        return None, None
    raw = m.group(1)
    try:
        parsed = yaml.safe_load(raw)
    except yaml.YAMLError:
        return None, None
    if not isinstance(parsed, dict):
        return None, None
    return parsed, raw


def uid_to_prefix(uid: str) -> str:
    """Extract the document prefix from a Doorstop UID.

    Doorstop UIDs have the form ``PREFIX-NNN`` or ``PREFIX-TAG`` where PREFIX
    is uppercase letters only and the suffix comes after the *last* hyphen.

    >>> uid_to_prefix("MRS-001")
    'MRS'
    >>> uid_to_prefix("SRS-CCT")
    'SRS'
    >>> uid_to_prefix("TRA-CDB")
    'TRA'
    """
    parts = uid.rsplit("-", 1)
    return parts[0] if len(parts) == 2 else uid


def parse_link_uids(links_value) -> list[str]:
    """Return the list of parent UIDs from the raw parsed value of ``links:``.

    Doorstop stores links in three equivalent forms::

        links: []                          # no links
        links:
        - MRS-001: <fingerprint>           # reviewed link
        - MRS-002: null                    # link, fingerprint not yet set
        - MRS-003                          # link, fingerprint omitted
    """
    if not links_value:
        return []
    uids: list[str] = []
    for entry in links_value:
        if isinstance(entry, str):
            uids.append(entry.strip())
        elif isinstance(entry, dict):
            for key in entry:
                uids.append(str(key).strip())
    return uids


# ---------------------------------------------------------------------------
# In-place link removal
# ---------------------------------------------------------------------------

def _link_line_re(uid: str) -> re.Pattern:
    """Return a regex that matches the raw link line for *uid* in frontmatter.

    Handles all three link forms (fingerprinted, null, omitted) with optional
    leading whitespace.
    """
    return re.compile(
        r"^[ \t]*-[ \t]+"
        + re.escape(uid)
        + r"(?:[ \t]*:[ \t]*.*)?"   # optional ': <fingerprint>' or ': null'
        + r"[ \t]*\r?\n",
        re.MULTILINE,
    )


_EMPTY_LINKS_BLOCK_RE = re.compile(
    r"^(links:)[ \t]*\r?\n(?![ \t]*-)",  # 'links:' not followed by a list item
    re.MULTILINE,
)


def remove_links_from_content(content: str, bad_uids: list[str]) -> str:
    """Remove the link lines for each UID in *bad_uids* from *content*.

    After removal, if the ``links:`` block becomes empty (no child ``- …``
    lines remain), it is normalised to ``links: []`` to keep valid Doorstop
    YAML.
    """
    for uid in bad_uids:
        pat = _link_line_re(uid)
        content, n = pat.subn("", content)
        if n == 0:
            # Fallback: try matching without a trailing newline (end of file).
            pat2 = re.compile(
                r"^[ \t]*-[ \t]+" + re.escape(uid) + r"(?:[ \t]*:[ \t]*.*)?\s*$",
                re.MULTILINE,
            )
            content = pat2.sub("", content)

    # Normalise an empty links block to 'links: []'.
    content = _EMPTY_LINKS_BLOCK_RE.sub(r"\1 []\n", content)
    return content


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    default_specs = os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", )
    )

    parser = argparse.ArgumentParser(
        description=(
            "Prune Doorstop item links that point to non-parent documents.\n"
            "Each Doorstop document has exactly one parent; items may only\n"
            "link to items in that parent document."
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
        "--dry-run",
        action="store_true",
        help="Report what would be changed without modifying any files.",
    )
    args = parser.parse_args()

    specs_root = os.path.abspath(args.specs_dir)
    if not os.path.isdir(specs_root):
        sys.exit(f"ERROR: specs directory not found: {specs_root}")

    if args.dry_run:
        print("=== DRY RUN – no files will be modified ===\n")

    docs = find_doorstop_docs(specs_root)
    if not docs:
        sys.exit(f"No Doorstop documents found under: {specs_root}")

    # Build a set of all known prefixes so we can warn about unknown ones.
    known_prefixes = {d["prefix"] for d in docs}

    total_links_removed = 0
    total_files_affected = 0

    for doc in sorted(docs, key=lambda d: d["prefix"]):
        prefix: str = doc["prefix"]
        parent_prefix: str | None = doc["parent"]
        doc_path: str = doc["path"]

        item_files = list_item_files(doc_path)
        doc_header_printed = False

        for fpath in item_files:
            fname = os.path.basename(fpath)
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    content = fh.read()
            except OSError as exc:
                print(f"  WARNING: cannot read {fpath}: {exc}", file=sys.stderr)
                continue

            fm, _raw = extract_frontmatter(content)
            if fm is None:
                continue  # no YAML frontmatter

            links_raw = fm.get("links")
            if not links_raw:
                continue  # empty or absent links

            link_uids = parse_link_uids(links_raw)
            if not link_uids:
                continue

            bad_uids: list[str] = []
            for uid in link_uids:
                lprefix = uid_to_prefix(uid)
                if parent_prefix is None:
                    # Root document – must have no links at all.
                    reason = "root document cannot have links"
                    bad_uids.append(uid)
                elif lprefix == prefix:
                    reason = "self-link (item links to its own document)"
                    bad_uids.append(uid)
                elif lprefix != parent_prefix:
                    if lprefix not in known_prefixes:
                        reason = f"unknown document prefix '{lprefix}'"
                    else:
                        reason = (
                            f"'{lprefix}' is not the parent document "
                            f"('{prefix}' parent is '{parent_prefix}')"
                        )
                    bad_uids.append(uid)

            if not bad_uids:
                continue

            # Print document section header once.
            if not doc_header_printed:
                parent_label = parent_prefix if parent_prefix else "none (root)"
                print(f"[{prefix}]  parent: {parent_label}")
                doc_header_printed = True

            rel = os.path.relpath(fpath, specs_root)
            for uid in bad_uids:
                lprefix = uid_to_prefix(uid)
                if parent_prefix is None:
                    reason = "root document cannot have links"
                elif lprefix == prefix:
                    reason = "self-link"
                elif lprefix not in known_prefixes:
                    reason = f"unknown document prefix '{lprefix}'"
                else:
                    reason = (
                        f"target prefix '{lprefix}' ≠ parent '{parent_prefix}'"
                    )
                verb = "Would remove" if args.dry_run else "Removing"
                print(f"  {verb}: {uid}  in {rel}  [{reason}]")

            total_links_removed += len(bad_uids)
            total_files_affected += 1

            if not args.dry_run:
                new_content = remove_links_from_content(content, bad_uids)
                try:
                    with open(fpath, "w", encoding="utf-8") as fh:
                        fh.write(new_content)
                except OSError as exc:
                    print(
                        f"  ERROR: could not write {fpath}: {exc}",
                        file=sys.stderr,
                    )

    print()
    if total_links_removed == 0:
        print("No bad links found.  Nothing to do.")
        return

    if args.dry_run:
        print(
            f"Dry run complete: {total_links_removed} bad link(s) across "
            f"{total_files_affected} file(s) would be removed."
        )
    else:
        print(
            f"Done: removed {total_links_removed} bad link(s) from "
            f"{total_files_affected} file(s)."
        )


if __name__ == "__main__":
    main()
