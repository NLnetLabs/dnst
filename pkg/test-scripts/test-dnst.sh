#!/usr/bin/env bash

set -eo pipefail
set -x

case $1 in
  post-install)
    # Run some sanity checks
    dnst --version
    dnst nsec3-hash nlnetlabs.nl
    man dnst
    man dnst-keygen
    ;;

  post-upgrade)
    # Nothing to do.
    # Run some sanity checks
    dnst --version
    dnst nsec3-hash nlnetlabs.nl
    man dnst
    man dnst-keygen
    ;;
esac
