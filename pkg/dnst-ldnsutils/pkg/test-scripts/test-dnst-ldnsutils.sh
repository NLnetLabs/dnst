#!/usr/bin/env bash

set -eo pipefail
set -x

case $1 in
  post-install)
    # Run some sanity checks
    ldns-keygen -v
    ldns-nsec3-hash nlnetlabs.nl
    man ldns-keygen
    ;;

  post-upgrade)
    # Nothing to do.
    # Run some sanity checks
    ldns-keygen -v
    ldns-nsec3-hash nlnetlabs.nl
    man ldns-keygen
    ;;
esac
