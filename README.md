# dnst

dnst
:: Domain Name System Tools - a toolset to assist DNS operators with zone and nameserver maintenance.

dnst is intended to offer both:
- a supported drop-in (see below) replacement and upgrade path for a subset of the popular NLnet Labs LDNS example tools, re-implemented in the Rust prpgramming language powered by the NLnet Labs [domain](https://crates.io/crates/domain) Rust library
- an evolving toolbox of commands to aid DNS operators in the maintenance and operation of their zones and nameservers.

dnst is not intended perform dig and drill-like functions; for this NLnet Labs offers [dnsi](https://github.com/NLnetLabs/dnsi).

## Summary

dnst supports two modes of operation:

1. dnst mode: the default.
2. ldns emulation mode: activated by invoking dnst using the name of a supported ldns example, e.g. `ldns-keygen`.

`dnst` currently offers drop-in (see below) replacement of the following `ldns` examples:

- key2ds
- keygen
- nsec3hash  
- signzone  
- notify  
- update

## Installation and documentation

See https://dnst.docs.nlnetlabs.nl/.

## Compatibility with supported LDNS examples

ldns mode allows for one-to-one replacement of the ldns example utilities by dnst, without having to change existing scripts. In this mode, the supported ldns examples are very closely emulated by dnst, though there are some exceptions. Please see the documentation for details. 

Because of a radically different achitechture and programming language, please note that the domain library is not intended as a drop-in replacement for the ldns library.

Incompatibilities, bug reports and feature requests should be reported at https://github.com/NLnetLabs/dnst/issues.

## Support

[Contact us](https://nlnetlabs.nl/services/contracts/) to learn about our paid support options.