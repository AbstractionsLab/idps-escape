import doorstop
import os
import time
import re
import shutil
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
        with open(os.path.join(PUBLISH_FOLDER_PATH, HTML_INDEX_FILENAME), 'r') as source_file:
            try:
                input = source_file.read()

            except Exception as e:
                print(e)
            
            target = open(os.path.join(PUBLISH_FOLDER_PATH, HTML_INDEX_FILENAME), "w")
            new_head = """<head>
                        <meta http-equiv="content-type" content="text/html; charset=UTF-8">
                        <link rel="stylesheet" href="assets/doorstop/bootstrap.min.css" />
                        <link rel="stylesheet" href="assets/doorstop/general.css" />
                        </head>"""
            new_content = re.sub(r'<head>.*?</head>', new_head, input, flags=re.DOTALL)
            new_content = re.sub(r'<table>', '<table class="table table-striped table-condensed">', new_content, flags=re.DOTALL)
            target.write(new_content)

        with open(os.path.join(PUBLISH_FOLDER_PATH, ASSETS_FOLDER_NAME, DOORSTOP_FOLDER_NAME, DOORSTOP_CSS_FILENAME), "a") as css_file:
            c5dec_css_fix = """
                            @media (min-width: 1200px) {
                                .col-lg-2 {
                                width: 26.66666667%;
                                }
                            }
                            """
            css_file.write(c5dec_css_fix)

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
    parser.add_argument("--include-cc-db", action="store_true", help="Include CC database in published tech specs.")
    args = parser.parse_args()

    exclude_cc_db = not args.include_cc_db
    publish(format=".html", exclude_cc_db=exclude_cc_db)

if __name__ == "__main__":
    main()