# dnst

dnst
:: Domain Name System Tools - a toolset to assist DNS operators with zone and nameserver maintenance.

dnst is intended to offer both:
- a supported drop-in (see below) replacement and upgrade path for a subset of the popular NLnet Labs LDNS example tools, re-implemented in the Rust prpgramming language powered by the NLnet Labs "domain" Rust library
- an envolving toolbox of commands to aid DNS operators in the maintenance and operation of their zones and nameservers.

dnst is not intended perform dig and drill-like functions; for this NLnet Labs offers [dnsi](https://github.com/NLnetLabs/dnsi).

## Summary

dnst supports two modes of operation:

1. dnst mode: the default.
2. ldns emulation mode: activated by invoking dnst using the name of a supported ldns example, e.g. `ldns-keygen`.

`dnst` currently offers drop-in (see below) replacement of the following LDNS examples:

- key2ds
- keygen
- nsec3hash  
- signzone  
- notify  
- update

## Installation and documentation

See https://dnst.docs.nlnetlabs.nl/.

## Compatibility with supported LDNS examples

In LDNS mode the supported LDNS examples are very closely emulated by dnst, though there are some exceptions.

See the documentation for details.

Incompatibilities, bug reports and feature requests should be reported at https://github.com/NLnetLabs/dnst/issues.

## Support

[Contact us](https://nlnetlabs.nl/services/contracts/) to learn about our paid support options.