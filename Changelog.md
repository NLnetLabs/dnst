# Changelog

## Unreleased next version

Breaking changes

New

- Add keyset subcommand. A DNSSEC key manager. ([#61])
- Add find-prefix option to nsec3hash to find a label that results in an
  NSEC3 hash with a specified prefix. ([#147])

Bug fixes

Other changes

[#61]: https://github.com/NLnetLabs/domain/pull/61
[#147]: https://github.com/NLnetLabs/domain/pull/147

## 0.1.0-rc1 ‘Prologue’

Released 2025-06-04.

This is an initial pre-release for inclusion in DEB and RPM packages to enable the wider community to get an early taste and give feedback on this Rust based successor to our popular C based LDNS example tools.
