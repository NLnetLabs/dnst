# Changelog

## v0.2.0-alpha2

Released 2026-05-15.

### Breaking changes

### New

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

### Breaking changes

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
