#!/usr/bin/env bash

set -e

# if the last argument is an rpm file, use rpmsign
# shellcheck disable=2199
if [[ "${@: -1}" == *.rpm ]]; then
	rpmsign "$@"
else
	# shellcheck disable=2145
	echo "rpmsign-only: Not signing ${@: -1}" >&2
fi
