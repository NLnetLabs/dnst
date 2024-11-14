#!/usr/bin/env bash

set -eo pipefail
set -x

case $1 in
  post-install)
    # Run some sanity checks
    dnst --version
    dnst nsec3-hash nlnetlabs.nl
    ldns-nsec3-hash nlnetlabs.nl
    ;;

  post-upgrade)
    # Nothing to do.
    ;;
esac