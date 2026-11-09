# Changelog

<!-- Changelog template (remove empty sections on release of a version)
## Unreleased version

Released yyyy-mm-dd.

### Breaking changes
### New
### Bug fixes
### Other changes
### Documentation improvements
### Known issues
### Acknowledgements
-->

## Unreleased version

Released yyyy-mm-dd.

### Breaking changes
### New
### Bug fixes
### Other changes
### Documentation improvements
### Known issues
### Acknowledgements

## v0.3.0-alpha

Released 2026-11-06

### Breaking changes

- During key rolls, record the ttl before changes are made. This changes
  commands for manual key rolls and internal keyset state during a
  key roll. ([#198] by @Philip-NLnetLabs)
- Use latest domain and domain-kmip changes for improved KMIP HSM algorithm
  support. Requires Cascade-HSM-Bridge v0.2.0-beta1 due to a change in how
  the KMIP Response Header Date-Time field is encoded. ([#205] by @ximon18)

### Other changes

- Allow the user to specify the KMIP server name (SNI) to use. ([#193] by @ximon18)
- Support disabling use of KMIP server auth. ([#194] by @ximon18)
- Improve error reporting in keyset status and make keyset status less confusing. ([#190] and [#197] by @Philip-NLnetLabs)
- For dnst keyset. replace warning about wrong signature with info and better formatting. ([#192] by @Philip-NLnetLabs)

### Documentation

- Document the default values for `keyset set` subcommands. ([#184] by
  @ximon18)

[#184]: https://github.com/NLnetLabs/dnst/pull/184
[#193]: https://github.com/NLnetLabs/dnst/pull/193
[#190]: https://github.com/NLnetLabs/dnst/pull/190
[#192]: https://github.com/NLnetLabs/dnst/pull/192
[#194]: https://github.com/NLnetLabs/dnst/pull/194
[#197]: https://github.com/NLnetLabs/dnst/pull/197
[#198]: https://github.com/NLnetLabs/dnst/pull/198
[#205]: https://github.com/NLnetLabs/dnst/pull/205

## v0.2.0-alpha3

Released 2026-06-04

### Other changes

- Upgrade domain to 0.12.1.

## v0.2.0-alpha2

Released 2026-05-15.

### Bug fixes

- Use secure file permissions for key material created by `keygen` or `keyset`
  on Linux ([#171])

### Other changes

- Add apex_remove and apex_extra fields in keyset state files. This marks
  dnskey_rrset, cds_rrset, and ns_rrset as obsolete. They will be removed
  when signers that use these fields have been upgraded. ([#167])

[#167]: https://github.com/NLnetLabs/domain/pull/167
[#171]: https://github.com/NLnetLabs/domain/pull/171

## v0.2.0-alpha1

Released 2026-03-16.

### New

- Add keyset subcommand. A DNSSEC key manager. ([#61])
- Add find-prefix option to nsec3hash to find a label that results in an
  NSEC3 hash with a specified prefix. ([#147])

### Bug fixes

- Remove apex ZONEMD records from the input in dnst signzone. ([#164])

### Other changes

[#61]: https://github.com/NLnetLabs/domain/pull/61
[#147]: https://github.com/NLnetLabs/domain/pull/147
[#164]: https://github.com/NLnetLabs/domain/pull/147

## 0.1.0-rc1 ‘Prologue’

Released 2025-06-04.

This is an initial pre-release for inclusion in DEB and RPM packages to enable the wider community to get an early taste and give feedback on this Rust based successor to our popular C based LDNS example tools.
