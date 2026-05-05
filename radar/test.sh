#!/usr/bin/env bash
set -Eeuo pipefail

docker build -f Dockerfile.test -t radar-tests .

# run tests
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/workspace -w /workspace radar-tests ./tests/run-tests.sh