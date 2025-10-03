#!/usr/bin/env bash

set -eo pipefail
set -x

case $1 in
  post-install)
    # Run some sanity checks
    /var/lib/cascade/bin/cascade-dnst --version
    # ldns-keygen -v
    # dnst nsec3-hash nlnetlabs.nl
    # ldns-nsec3-hash nlnetlabs.nl
    /var/lib/cascade/bin/cascade-dnst keyset --help
    man dnst
    # man dnst-keygen
    # man ldns-keygen
    man dnst-keyset
    ;;

  post-upgrade)
    # Nothing to do.
    # Run some sanity checks
    /var/lib/cascade/bin/cascade-dnst --version
    # ldns-keygen -v
    # dnst nsec3-hash nlnetlabs.nl
    # ldns-nsec3-hash nlnetlabs.nl
    /var/lib/cascade/bin/cascade-dnst keyset --help
    man dnst
    # man dnst
    # man dnst-keygen
    # man ldns-keygen
    man dnst-keyset
    ;;
esac
