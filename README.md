# dnst

dnst
:: Domain Name Service Tools - tools to assist DNS operators with zone and nameserver maintenance.

dnst is intended to offer both:
- a supported drop-in (see below) replacement and upgrade path for a subset of the popular NLnet Labs LDNS example tools, re-implemented in the Rust prpgramming language powered by the NLnet Labs "domain" Rust library
- an envolving toolbox of commands to aid DNS operators in the maintenance and operation of their zones and nameservers.

It is NOT intended to be a dig-like query tool, for that see the NLnet Labs dnsi tool.

## tl;dr

dnst supports two modes of operation:

1. DNST mode: the default.
2. LDNS emulation mode: activated by invoking dnst using the name of a supported LDNS example, e.g. ldns-keygen.

`dnst` currently offers drop-in *1 replacement of the following LDNS examples:

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