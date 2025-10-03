#!/usr/bin/env bash

set -eo pipefail
set -x

case $1 in
  post-install)
    # Run some sanity checks
    /usr/libexec/cascade/cascade-dnst --version
    # ldns-keygen -v
    # dnst nsec3-hash nlnetlabs.nl
    # ldns-nsec3-hash nlnetlabs.nl
    /usr/libexec/cascade/cascade-dnst keyset --help
    man cascade-dnst
    # man dnst-keygen
    # man ldns-keygen
    man cascade-dnst-keyset
    ;;

  post-upgrade)
    # Nothing to do.
    # Run some sanity checks
    /usr/libexec/cascade/cascade-dnst --version
    # ldns-keygen -v
    # dnst nsec3-hash nlnetlabs.nl
    # ldns-nsec3-hash nlnetlabs.nl
    /usr/libexec/cascade/cascade-dnst keyset --help
    man cascade-dnst
    # man dnst
    # man dnst-keygen
    # man ldns-keygen
    man cascade-dnst-keyset
    ;;
esac
