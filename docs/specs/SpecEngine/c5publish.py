import doorstop
import os
import time
import re
import argparse

EXPORT_FOLDER_NAME = "export"
EXPORT_FOLDER = os.path.join(os.getcwd(), EXPORT_FOLDER_NAME)

DOCS_FOLDER_NAME = "docs"
SPECS_FOLDER_NAME = "specs"
DB_FOLDER_NAME = "database"
INPUT_FOLDER_NAME = "input"
EXPORT_FOLDER_NAME = "export"
PUBLISH_FOLDER_NAME = "publish"
ASSETS_FOLDER_NAME = "assets"

PUBLISH_FOLDER_PATH = os.path.join(os.getcwd(), DOCS_FOLDER_NAME, PUBLISH_FOLDER_NAME)

HTML_INDEX_FILENAME = "index.html"
DOORSTOP_FOLDER_NAME = "doorstop"
DOORSTOP_CSS_FILENAME = "sidebar.css"

def create_dirname(path):
    """Ensure a parent directory exists for a path."""
    dirpath = os.path.dirname(path)
    if dirpath and not os.path.isdir(dirpath):
        os.makedirs(dirpath)


# Tokenises on existing anchor tags so IDs already used as link text or
# href values are never double-linked.
_ANCHOR_RE = re.compile(r'(<a\b[^>]*>.*?</a>)', re.DOTALL | re.IGNORECASE)

# Matches a Doorstop item ID (e.g. SRS-001, HARC-042) that is not part of
# an existing word, number, or quoted attribute value.
_ITEM_ID_RE = re.compile(r'(?<!["\w])([A-Z][A-Z0-9]+-\d+)(?!["\w])')


def _linkify_item_ids(html: str) -> str:
    """Replace bare Doorstop item IDs in *html* with relative hyperlinks.

    Each ID of the form ``PREFIX-NNN`` becomes::

        <a href="PREFIX.html#PREFIX-NNN">PREFIX-NNN</a>

    IDs that already appear inside an ``<a …>`` element are skipped.

    Args:
        html: Raw HTML content to process.

    Returns:
        HTML with bare item IDs replaced by hyperlinks.
    """
    def _replace(m: re.Match) -> str:
        uid = m.group(1)
        prefix = uid.rsplit("-", 1)[0]
        return f'<a href="{prefix}.html#{uid}">{uid}</a>'

    tokens = _ANCHOR_RE.split(html)
    result = []
    for token in tokens:
        if token.lower().startswith("<a ") or token.lower().startswith("<a>"):
            result.append(token)  # already an anchor — leave untouched
        else:
            result.append(_ITEM_ID_RE.sub(_replace, token))
    return "".join(result)


def linkify_html_file(filepath: str) -> bool:
    """Linkify Doorstop item IDs in a single HTML file in-place.

    Args:
        filepath: Absolute path to the HTML file to process.

    Returns:
        True if the file was modified, False otherwise.
    """
    with open(filepath, "r", encoding="utf-8") as fh:
        content = fh.read()
    updated = _linkify_item_ids(content)
    if updated != content:
        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write(updated)
        return True
    return False


def linkify_all_html_files(publish_folder: str) -> None:
    """Linkify Doorstop item IDs in every HTML file inside *publish_folder*.

    Args:
        publish_folder: Path to the folder containing published HTML files.
    """
    for filename in os.listdir(publish_folder):
        if not filename.endswith(".html"):
            continue
        filepath = os.path.join(publish_folder, filename)
        if linkify_html_file(filepath):
            print(f"Linkified item IDs in: {filename}")


# Keep the private alias so any existing internal callers are unaffected.
_linkify_all_html_files = linkify_all_html_files


def publish(prefix="all", path=None, format=None, exclude_cc_db=False):
    """
    Publish the project specifications to a specified format and path.
    Args:
        prefix (str): The prefix of the document to publish. Defaults to "all".
        path (str): The path to save the published document. Defaults to None.
        format (str): The format of the published document. Defaults to None.
        exclude_cc_db (bool): Flag to exclude CC database from published tech specs. Defaults to False.
    """

    if exclude_cc_db:
        print("Excluding CC database from published tech specs...")

        database_path = os.path.abspath(os.path.join(os.getcwd(), '..', '..', "c5dec", ASSETS_FOLDER_NAME, DB_FOLDER_NAME))

        # Rename all .doorstop.yml files in the database folder and its subfolders
        for root, _, files in os.walk(database_path):
            for file in files:
                if file.endswith('.doorstop.yml'):
                    file_path = os.path.join(root, file)
                    # old_file_path = os.path.join(root, file)
                    new_file_path = os.path.join(root, 'disabled_doorstop.yml')
                    os.rename(file_path, new_file_path)
                    print(f"Renamed {file_path} to {new_file_path}")
                    # os.remove(file_path)
                    # log.info(f"Deleted {file_path}")
    else:
        print("Including CC database in published tech specs...")

    tree = doorstop.build()
    if format is None:
        format = ".md"
    if prefix != "all":
        document = tree.find_document(prefix)
        current_time = time.strftime("%Y%m%d-%H%M%S")
        if path is None:
            path = "{}/{}-publish-{}{}".format(EXPORT_FOLDER, prefix, current_time, format)
        doorstop.publisher.publish(document, path, format)
    else:
        if path is None:
            path = PUBLISH_FOLDER_PATH
            create_dirname(path)
        doorstop.publisher.publish(tree, path, format)

    # Replace css refs in index.html
    if format == ".html":
        index_path = os.path.join(PUBLISH_FOLDER_PATH, HTML_INDEX_FILENAME)
        with open(index_path, 'r', encoding="utf-8") as fh:
            try:
                content = fh.read()
            except Exception as e:
                print(e)

        new_head = (
            "<head>\n"
            "                        <meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\">\n"
            "                        <link rel=\"stylesheet\" href=\"assets/doorstop/bootstrap.min.css\" />\n"
            "                        <link rel=\"stylesheet\" href=\"assets/doorstop/general.css\" />\n"
            "                        </head>"
        )
        content = re.sub(r'<head>.*?</head>', new_head, content, flags=re.DOTALL)
        content = re.sub(r'<table>', '<table class="table table-striped table-condensed">', content, flags=re.DOTALL)
        # Inject links to tooling report pages at the very top of <body>
        tooling_section = (
            "<body>\n"
            "<hr>\n"
            "<h3>C5-DEC CAD traceability tooling reports:</h3>\n"
            "<p>\n<ul>\n"
            '<li> <a href="items_browser.html">Specification browser</a> </li>\n'
            '<li> <a href="traceability_stats.html">Traceability statistics</a> </li>\n'
            '<li> <a href="specs-graph.html">Traceability graph</a> </li>\n'
            "</ul>\n</p>\n"
            "<hr>\n"
        )
        content = content.replace("<body>", tooling_section, 1)
        with open(index_path, "w", encoding="utf-8") as fh:
            fh.write(content)

        css_path = os.path.join(
            PUBLISH_FOLDER_PATH, ASSETS_FOLDER_NAME, DOORSTOP_FOLDER_NAME, DOORSTOP_CSS_FILENAME
        )
        with open(css_path, "a") as css_file:
            css_file.write(
                "\n@media (min-width: 1200px) {\n"
                "    .col-lg-2 {\n"
                "        width: 26.66666667%;\n"
                "    }\n"
                "}\n"
            )

        # Linkify Doorstop item IDs in the core published HTML files.
        # NOTE: tooling report files (traceability_stats.html, items_browser.html)
        # are generated by separate scripts. Call linkify_all_html_files() again
        # after those scripts have run, or invoke:
        #   python c5publish.py --linkify-only
        linkify_all_html_files(PUBLISH_FOLDER_PATH)

    print("Project specifications published to: {}".format(PUBLISH_FOLDER_PATH))

    if exclude_cc_db:
        # Reenable all .doorstop.yml files in the database folder and its subfolders
        for root, _, files in os.walk(database_path):
                for file in files:
                    if file.endswith('disabled_doorstop.yml'):
                        file_path = os.path.join(root, file)
                        new_file_path = os.path.join(root, '.doorstop.yml')
                        os.rename(file_path, new_file_path)
                        print(f"Renamed {file_path} to {new_file_path}")


def main(args=None, cwd=None):
    parser = argparse.ArgumentParser(description="Publish project specifications.")
    parser.add_argument(
        "--include-cc-db",
        action="store_true",
        help="Include CC database in published tech specs.",
    )
    parser.add_argument(
        "--linkify-only",
        action="store_true",
        help=(
            "Skip publishing; only (re-)linkify all HTML files in the publish folder. "
            "Run this after c5traceability.py and c5browser.py have generated their reports."
        ),
    )
    parser.add_argument(
        "--publish-folder",
        default=PUBLISH_FOLDER_PATH,
        help="Path to the publish folder (used with --linkify-only).",
    )
    args = parser.parse_args()

    if args.linkify_only:
        print(f"Linkifying all HTML files in: {args.publish_folder}")
        linkify_all_html_files(args.publish_folder)
        return

    exclude_cc_db = not args.include_cc_db
    publish(format=".html", exclude_cc_db=exclude_cc_db)

if __name__ == "__main__":
    main()