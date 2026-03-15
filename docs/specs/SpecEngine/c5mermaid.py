"""Pre-process Doorstop Markdown items to render Mermaid diagrams.

Scans all Doorstop ``.md`` item files under a specs folder for fenced
````` ```mermaid ````` code blocks, renders each one to SVG (or PNG) via
the Mermaid CLI (``mmdc``), stores the result in the item's ``assets/``
directory, and replaces the fenced block with an HTML comment preserving
the original source plus a Markdown image reference.

The transformation is **one-way and idempotent** — already-converted blocks
(detected by the ``<!-- c5-mermaid-source:<base64> -->`` sentinel) are skipped
on subsequent runs, and identical diagram content produces the same filename
thanks to a content hash.  The mermaid source is stored as a base64 payload
inside the single-line HTML comment so that arrow syntax (``-->``) and
``%%`` comment lines in the diagram cannot prematurely close the comment.

Usage::

    # From docs/specs/:
    python ./SpecEngine/c5mermaid.py .

    # Dry-run (report what would change without writing):
    python ./SpecEngine/c5mermaid.py . --dry-run

    # Use PNG instead of SVG:
    python ./SpecEngine/c5mermaid.py . --format png

    # Undo: restore encoded sentinels back to readable ```mermaid blocks:
    python ./SpecEngine/c5mermaid.py . undo

Display size attributes 'width' and 'height' can be specified on the line
immediately after the closing fence of a mermaid block using a kramdown-style
attribute list.

    ```mermaid
    sequenceDiagram
    ...
    ```
    {width="50%"}

    ```mermaid
    ...
    ```
    {height="2cm"}

    ```mermaid
    ...
    ```
    {width="800px" height="600px"}

Both ``{width="50%"}`` and ``{: width="50%"}`` are accepted (kramdown prefix
``: `` is optional).


Requires:
    npm install -g @mermaid-js/mermaid-cli
"""

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import List, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ASSETS_DIRNAME = "assets"

#: Sub-path (relative to specs_folder) where published assets live.
PUBLISH_ASSETS_SUBPATH = os.path.join("docs", "publish", "assets")

#: Default output format for rendered diagrams.
DEFAULT_FORMAT = "svg"

#: Mermaid CLI binary name (expected on PATH).
MMDC_CMD = "mmdc"

#: Sentinel that marks an already-converted mermaid block.
_SENTINEL = "c5-mermaid-source"

#: System Chromium paths to probe (used when Puppeteer's bundled Chrome
#: cannot run, e.g. in ARM containers or CI environments).
_CHROMIUM_CANDIDATES = [
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/google-chrome",
]

# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------

# Fenced ```mermaid ... ``` block in Markdown body text.
# Captures optional leading whitespace (indent), the diagram source, and an
# optional attribute block on the line immediately after the closing fence,
# e.g.::
#
#   ```mermaid
#   sequenceDiagram
#   ...
#   ```
#   {width="50%"}
#
# The ``attrs`` group is ``None`` when no attribute line is present.
_MERMAID_BLOCK_RE = re.compile(
    r"(?P<indent>[ \t]*)```mermaid[ \t]*\n(?P<code>.*?)```(?:[ \t]*\n(?P<attrs>\{[^}\n]*\}))?",
    re.DOTALL,
)

# Already-converted block: sentinel HTML comment (base64 payload) + image ref.
# Format: <!-- c5-mermaid-source:<base64> -->\n![...](...)  (optional {: ...})
# Single-line comment avoids '-->' sequences inside mermaid source
# (e.g. arrows or %% comments) from prematurely closing the HTML comment.
# Wrapped in a capturing group so re.split() preserves matched tokens.
_CONVERTED_RE = re.compile(
    r"(<!-- " + re.escape(_SENTINEL) + r":[A-Za-z0-9+/=]+ -->\n"
    r"!\[.*?\]\(.*?\)(?:\{:[^}]*\})?)",
    re.DOTALL,
)

# For undo: captures indent, base64 payload, and image reference line
# (including any optional kramdown IAL suffix such as ``{: width="50%"}``)
_UNDO_RE = re.compile(
    r"(?P<indent>[ \t]*)<!-- " + re.escape(_SENTINEL)
    + r":(?P<payload>[A-Za-z0-9+/=]+) -->\n"
    r"[ \t]*(?P<imgref>!\[.*?\]\(.*?\)(?:\{:[^}]*\})?)",
)

# YAML frontmatter delimiters (Doorstop Markdown items start with ---).
_FRONTMATTER_RE = re.compile(r"\A(---\n.*?\n---\n)", re.DOTALL)

# Kramdown-style IAL attribute block on a mermaid fence line, e.g.
# ``{width="50%"}`` or ``{: height="2cm" width="800px"}``.
# The leading ``: `` is optional (both ``{foo}`` and ``{: foo}`` are accepted).
_FENCE_ATTRS_RE = re.compile(r"\{:?\s*(?P<attrs>[^}]+)\}")

# Detects a CSS unit suffix on a dimension value (e.g. "3cm", "2.5em", "800px").
# Values that are plain integers ("800") or percentages ("50%") do NOT match
# and are kept as plain HTML attributes.  Anything matching this regex must be
# emitted as a CSS ``style`` property instead.
_CSS_UNIT_RE = re.compile(r"\d[a-zA-Z]")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def check_mmdc_available() -> bool:
    """Return True if the Mermaid CLI (``mmdc``) is on PATH."""
    return shutil.which(MMDC_CMD) is not None


def _find_system_chromium() -> Optional[str]:
    """Return the path of a system-installed Chromium/Chrome, or None."""
    for candidate in _CHROMIUM_CANDIDATES:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _create_puppeteer_config(tmpdir: str) -> Optional[str]:
    """Write a Puppeteer JSON config with ``--no-sandbox`` for containers.

    Also sets ``executablePath`` to a system Chromium when the bundled
    Chrome cannot run (common in ARM containers or CI images).

    Args:
        tmpdir: Directory to write the config file into.

    Returns:
        Absolute path to the config file, or None if none is needed.
    """
    config = {}  # type: dict
    chromium = _find_system_chromium()
    if chromium:
        config["executablePath"] = chromium
    # Always add --no-sandbox inside containers / CI.
    config["args"] = ["--no-sandbox", "--disable-gpu"]
    if not config:
        return None
    path = os.path.join(tmpdir, "puppeteer-config.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(config, fh)
    return path


def _content_hash(code: str) -> str:
    """Return a 12-char hex hash of the diagram source for deterministic filenames."""
    return hashlib.sha256(code.strip().encode("utf-8")).hexdigest()[:12]


def _parse_fence_attrs(attrs_raw: Optional[str]) -> Optional[str]:
    """Extract display attributes from a post-fence attribute line.

    Accepts the ``{...}`` or ``{: ...}`` string captured from the line
    immediately after the closing fence of a mermaid block, or ``None`` when
    no such line is present.

    Args:
        attrs_raw: Full attribute block string (e.g. ``{width="50%"}`` or
            ``{: height="2cm"}``), or ``None``.

    Returns:
        The stripped attribute content (e.g. ``width="50%"``), or ``None``
        if *attrs_raw* is absent or contains no ``{...}`` block.
    """
    if not attrs_raw:
        return None
    m = _FENCE_ATTRS_RE.search(attrs_raw)
    if not m:
        return None
    return m.group("attrs").strip()


def _attrs_to_ial(attrs: str) -> str:
    """Convert parsed fence attrs to a kramdown IAL attribute string.

    For ``width`` and ``height`` values that contain CSS units (e.g. ``3cm``,
    ``2.5em``, ``800px``), plain HTML attributes are not valid and browsers
    ignore them.  Such values are converted to a CSS ``style`` property.
    Plain integers (``800``) and percentages (``50%``) are kept as-is since
    browsers accept them as HTML attributes.

    All other key/value pairs are passed through verbatim.

    Args:
        attrs: Attribute string as returned by ``_parse_fence_attrs``, e.g.
            ``width="50%"`` or ``width="3cm" height="2cm"``.

    Returns:
        A normalized attribute string suitable for use inside a kramdown IAL
        ``{: ...}`` suffix, e.g. ``width="50%"`` or
        ``style="width: 3cm; height: 2cm;"``.
    """
    pairs = re.findall(r'(\w+)="([^"]*)"', attrs)
    html_attrs = []  # type: List[str]
    style_parts = []  # type: List[str]
    for key, value in pairs:
        if key in ("width", "height") and _CSS_UNIT_RE.search(value):
            style_parts.append(f"{key}: {value};")
        else:
            html_attrs.append(f'{key}="{value}"')
    result = html_attrs[:]
    if style_parts:
        result.append(f'style="{" ".join(style_parts)}"')
    return " ".join(result)


def _render_mermaid(
    mermaid_code: str,
    output_path: str,
    output_format: str = DEFAULT_FORMAT,
) -> bool:
    """Render *mermaid_code* to an image file via ``mmdc``.

    Args:
        mermaid_code: Mermaid diagram source.
        output_path: Absolute path for the output image.
        output_format: ``"svg"`` or ``"png"``.

    Returns:
        ``True`` on success, ``False`` otherwise.
    """
    # Write source to a temp file next to the intended output so mmdc can
    # resolve relative paths the same way.
    out_dir = os.path.dirname(output_path)
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".mmd", dir=out_dir)
    puppeteer_cfg = _create_puppeteer_config(out_dir)
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
            fh.write(mermaid_code.strip() + "\n")

        cmd = [
            MMDC_CMD,
            "--input", tmp_path,
            "--output", output_path,
            "--outputFormat", output_format,
            "--quiet",
        ]
        if puppeteer_cfg:
            cmd.extend(["--puppeteerConfigFile", puppeteer_cfg])
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            print(
                f"  WARNING: mmdc failed for {os.path.basename(output_path)}: "
                f"{result.stderr.strip()}"
            )
            return False
        return os.path.isfile(output_path)
    except FileNotFoundError:
        print(
            f"  ERROR: '{MMDC_CMD}' not found. "
            "Install with: npm install -g @mermaid-js/mermaid-cli"
        )
        return False
    except subprocess.TimeoutExpired:
        print(f"  ERROR: mmdc timed out rendering {output_path}")
        return False
    finally:
        if os.path.isfile(tmp_path):
            os.remove(tmp_path)
        if puppeteer_cfg and os.path.isfile(puppeteer_cfg):
            os.remove(puppeteer_cfg)


def _copy_to_publish_assets(
    src_path: str,
    publish_assets_dir: str,
    img_filename: str,
) -> None:
    """Copy a rendered image to the publish assets directory.

    Args:
        src_path: Absolute path of the rendered image.
        publish_assets_dir: Absolute path of the publish assets directory.
        img_filename: Filename (basename) of the image.
    """
    os.makedirs(publish_assets_dir, exist_ok=True)
    dst_path = os.path.join(publish_assets_dir, img_filename)
    shutil.copy2(src_path, dst_path)


def _find_item_files(specs_folder: str) -> List[str]:
    """Collect all Doorstop Markdown item files under *specs_folder*.

    Args:
        specs_folder: Root specs directory (e.g. ``docs/specs``).

    Returns:
        Sorted list of absolute paths to ``.md`` item files.
    """
    items = []  # type: List[str]
    for root, dirs, files in os.walk(specs_folder):
        # Skip hidden dirs, assets dirs, SpecEngine, and publish output.
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".")
            and d != ASSETS_DIRNAME
            and d not in ("SpecEngine", "publish", "docs")
        ]
        for fname in sorted(files):
            # Doorstop items: PREFIX-NNN.md  or  PREFIX-NAME.md
            if fname.endswith(".md") and re.match(r"^[A-Z]", fname):
                items.append(os.path.join(root, fname))
    return items


# ---------------------------------------------------------------------------
# Core per-file processing
# ---------------------------------------------------------------------------


def render_mermaid_in_file(
    item_path: str,
    output_format: str = DEFAULT_FORMAT,
    dry_run: bool = False,
    publish_assets_dir: Optional[str] = None,
) -> int:
    """Render Mermaid blocks in a single Doorstop item file.

    Args:
        item_path: Absolute path to the ``.md`` item file.
        output_format: ``"svg"`` or ``"png"``.
        dry_run: If ``True``, report but do not write anything.
        publish_assets_dir: Optional absolute path to the publish assets
            directory.  When provided, a copy of each rendered image is
            placed there in addition to the item's own ``assets/`` folder.

    Returns:
        Number of diagrams rendered (or that *would be* rendered in dry-run).
    """
    with open(item_path, "r", encoding="utf-8") as fh:
        content = fh.read()

    # Quick bail-out: nothing to do if no mermaid blocks exist and no
    # converted blocks need re-checking.
    if "```mermaid" not in content:
        return 0

    item_dir = os.path.dirname(item_path)
    item_basename = os.path.splitext(os.path.basename(item_path))[0]  # e.g. SWD-003
    assets_dir = os.path.join(item_dir, ASSETS_DIRNAME)

    # Separate frontmatter from body so the regex only operates on
    # the Markdown body (after the closing ---).
    fm_match = _FRONTMATTER_RE.match(content)
    if fm_match:
        frontmatter = fm_match.group(1)
        body = content[fm_match.end():]
    else:
        frontmatter = ""
        body = content

    rendered_count = 0
    diagram_index = [0]  # mutable counter for the closure

    def _replace(m: re.Match) -> str:
        nonlocal rendered_count
        diagram_index[0] += 1
        idx = diagram_index[0]

        indent = m.group("indent")
        mermaid_code = m.group("code")
        display_attrs = _parse_fence_attrs(m.group("attrs"))
        chash = _content_hash(mermaid_code)
        # e.g. "SWD-003" → "swd-003", giving "swd-003-<hash>.svg" (! diff from c5: only 'swd' is used)
        img_filename = f"{item_basename.lower()}-{chash}.{output_format}"
        img_path = os.path.join(assets_dir, img_filename)
        rel_path = f"{ASSETS_DIRNAME}/{img_filename}"

        # Encode payload as JSON so that display attrs survive undo.
        # V1 format (raw mermaid code, not JSON) is handled gracefully on undo.
        payload_obj = {"code": mermaid_code}
        if display_attrs is not None:
            payload_obj["attrs"] = display_attrs
        encoded = base64.b64encode(
            json.dumps(payload_obj).encode("utf-8")
        ).decode("ascii")
        img_ref = f"{indent}![{item_basename} diagram {idx}]({rel_path})"
        if display_attrs:
            img_ref += "{: " + _attrs_to_ial(display_attrs) + "}"
        comment_block = (
            f"{indent}<!-- {_SENTINEL}:{encoded} -->\n"
            f"{img_ref}"
        )

        if dry_run:
            print(f"  [dry-run] Would render: {img_filename}")
            rendered_count += 1
            return comment_block

        # Cache hit — image already exists with identical content hash.
        if os.path.isfile(img_path):
            print(f"  Cached: {img_filename}")
            if publish_assets_dir:
                _copy_to_publish_assets(img_path, publish_assets_dir, img_filename)
            rendered_count += 1
            return comment_block

        # Render the diagram.
        os.makedirs(assets_dir, exist_ok=True)
        if _render_mermaid(mermaid_code, img_path, output_format):
            print(f"  Rendered: {img_filename}")
            if publish_assets_dir:
                _copy_to_publish_assets(img_path, publish_assets_dir, img_filename)
            rendered_count += 1
            return comment_block

        # Rendering failed — leave the original block intact.
        return m.group(0)

    # Tokenize the body: split on already-converted sentinel blocks so the
    # mermaid regex only operates on segments that have NOT been processed
    # in a prior run.  Converted blocks have the form:
    #   <!-- c5-mermaid-source:<base64> -->\n![...](...)
    # Because _CONVERTED_RE uses a capturing group, re.split() preserves
    # the matched separators in the result list (at odd indices).
    tokens = _CONVERTED_RE.split(body)
    new_parts = []
    for i, token in enumerate(tokens):
        if i % 2 == 1:
            # Already-converted block (captured separator) — pass through.
            new_parts.append(token)
        else:
            # Regular text — apply mermaid rendering.
            new_parts.append(_MERMAID_BLOCK_RE.sub(_replace, token))
    new_body = "".join(new_parts)

    if rendered_count > 0 and new_body != body and not dry_run:
        with open(item_path, "w", encoding="utf-8") as fh:
            fh.write(frontmatter + new_body)
        print(f"  Updated: {item_path}")

    return rendered_count


# ---------------------------------------------------------------------------
# Undo (restore readable mermaid blocks)
# ---------------------------------------------------------------------------


def undo_mermaid_in_file(item_path: str) -> int:
    """Restore base64-encoded sentinels back to fenced mermaid blocks.

    Each ``<!-- c5-mermaid-source:<base64> -->`` + image reference pair is
    replaced with the original ````` ```mermaid ````` fenced code block
    decoded from the base64 payload.

    Args:
        item_path: Absolute path to the ``.md`` item file.

    Returns:
        Number of blocks restored.
    """
    with open(item_path, "r", encoding="utf-8") as fh:
        content = fh.read()

    if _SENTINEL not in content:
        return 0

    restored_count = 0

    def _undo_replace(m: re.Match) -> str:
        nonlocal restored_count
        indent = m.group("indent")
        payload = m.group("payload")
        try:
            decoded = base64.b64decode(payload).decode("utf-8")
        except Exception:
            # If decoding fails, leave the block untouched.
            return m.group(0)
        # Payload is either JSON (new format) or raw mermaid code (v1 format).
        mermaid_code = decoded
        display_attrs = None
        try:
            obj = json.loads(decoded)
            if isinstance(obj, dict) and "code" in obj:
                mermaid_code = obj["code"]
                display_attrs = obj.get("attrs")
        except (json.JSONDecodeError, ValueError):
            pass
        restored_count += 1
        # Reconstruct the original fenced block.  The decoded source
        # already ends with a newline (it was the content between the
        # opening and closing ``` fences).
        fence_suffix = f"\n{{{display_attrs}}}" if display_attrs else ""
        return (
            f"{indent}```mermaid\n"
            f"{mermaid_code}"
            f"{indent}```{fence_suffix}"
        )

    new_content = _UNDO_RE.sub(_undo_replace, content)

    if restored_count > 0 and new_content != content:
        with open(item_path, "w", encoding="utf-8") as fh:
            fh.write(new_content)
        print(f"  Restored {restored_count} block(s): {item_path}")

    return restored_count


def undo_all(specs_folder: str) -> int:
    """Restore all encoded mermaid sentinels under *specs_folder*.

    Args:
        specs_folder: Path to the top-level specs directory.

    Returns:
        Total number of blocks restored.
    """
    item_files = _find_item_files(specs_folder)
    if not item_files:
        print("No Doorstop item files found.")
        return 0

    total = 0
    for item_path in item_files:
        total += undo_mermaid_in_file(item_path)
    return total


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def render_all(
    specs_folder: str,
    output_format: str = DEFAULT_FORMAT,
    dry_run: bool = False,
) -> int:
    """Render Mermaid diagrams in all Doorstop items under *specs_folder*.

    A copy of every rendered image is also placed in the publish assets
    directory at ``<specs_folder>/docs/publish/assets/``.

    Args:
        specs_folder: Path to the top-level specs directory.
        output_format: ``"svg"`` or ``"png"``.
        dry_run: If ``True``, report but do not write anything.

    Returns:
        Total number of diagrams rendered.
    """
    if not check_mmdc_available():
        print(
            "WARNING: Mermaid CLI (mmdc) is not installed.\n"
            "Mermaid diagrams will NOT be rendered.\n"
            "Install with:  npm install -g @mermaid-js/mermaid-cli"
        )
        return 0

    item_files = _find_item_files(specs_folder)
    if not item_files:
        print("No Doorstop item files found.")
        return 0

    publish_assets_dir = os.path.join(
        os.path.abspath(specs_folder), PUBLISH_ASSETS_SUBPATH
    )

    total = 0
    for item_path in item_files:
        count = render_mermaid_in_file(
            item_path, output_format, dry_run, publish_assets_dir
        )
        total += count

    return total


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> None:
    """Entry point for command-line usage."""
    parser = argparse.ArgumentParser(
        description=(
            "Render Mermaid diagrams in Doorstop Markdown item files. "
            "Replaces fenced ```mermaid blocks with rendered SVG/PNG images "
            "and preserves the original source in an HTML comment.  "
            "Use 'undo' to restore encoded blocks back to readable source."
        ),
    )
    parser.add_argument(
        "specs_folder",
        nargs="?",
        default=".",
        help="Path to the specs directory (default: current directory).",
    )
    parser.add_argument(
        "action",
        nargs="?",
        default="render",
        choices=["render", "undo"],
        help="Action to perform: 'render' (default) or 'undo'.",
    )
    parser.add_argument(
        "--format",
        choices=["svg", "png"],
        default=DEFAULT_FORMAT,
        help=f"Output image format (default: {DEFAULT_FORMAT}).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would be rendered without modifying any files.",
    )
    args = parser.parse_args(argv)

    specs_path = os.path.abspath(args.specs_folder)

    if args.action == "undo":
        print(f"Mermaid undo: scanning {specs_path}")
        total = undo_all(specs_path)
        print(f"Mermaid undo complete: {total} block(s) restored.")
    else:
        action = "dry-run" if args.dry_run else "render"
        print(f"Mermaid {action}: scanning {specs_path} (format={args.format})")
        total = render_all(specs_path, args.format, args.dry_run)
        print(f"Mermaid {action} complete: {total} diagram(s) processed.")


if __name__ == "__main__":
    main()
