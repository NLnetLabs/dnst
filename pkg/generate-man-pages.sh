#!/usr/bin/env bash

set -e

cd doc/manual

tempdir=$(mktemp -d venv.XXXX)

uv venv "$tempdir"
# shellcheck disable=1091
source "$tempdir/bin/activate"

uv pip install -r source/requirements.txt

make man
