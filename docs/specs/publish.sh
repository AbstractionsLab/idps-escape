#!/bin/bash
# This script is used to publish specifications using Doorstop and a C5-DEC Python script for keyword replacement.
# It first runs a Python script to replace keywords in the specifications, then publishes the specifications using Doorstop, and finally runs the Python script again to undo the keyword replacement.
# Ensure the script is executable
# chmod +x ./docs/specs/publish.sh

echo Usage guide:
echo ---
echo ./c5dec.sh
echo ... to publish tech specs without the CC database
echo ./publish.sh keep-cc
echo ... to keep CC database in published tech specs
echo ---

# Run c5 keyword replacement with "replace" argument
python ./c5-keyword.py ./tra replace
python ./c5-keyword.py ./trb replace
# python ./c5-keyword.py ./trs replace

# Parse the "keep-cc" argument
if [[ "$@" == *"keep-cc"* ]]; then
    python ./c5publish.py --include-cc-db
else
    python ./c5publish.py
fi

# Run c5 keyword replacement with "undo" argument
python ./c5-keyword.py ./tra undo
python ./c5-keyword.py ./trb undo
# python ./c5-keyword.py ./trs undo