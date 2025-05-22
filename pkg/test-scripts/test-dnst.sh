#!/usr/bin/env bash

set -eo pipefail
set -x

case $1 in
  post-install)
    # Run some sanity checks
    dnst --version
    ldns-keygen -v
    dnst nsec3-hash nlnetlabs.nl
    ldns-nsec3-hash nlnetlabs.nl
    man dnst
    man dnst-keygen
    man ldns-keygen
    ;;

  post-upgrade)
    # Nothing to do.
    # Run some sanity checks
    dnst --version
    ldns-keygen -v
    dnst nsec3-hash nlnetlabs.nl
    ldns-nsec3-hash nlnetlabs.nl
    man dnst
    man dnst-keygen
    man ldns-keygen
    ;;
esac