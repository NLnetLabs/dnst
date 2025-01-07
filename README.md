A set of binaries that reimplement some of the widely used `ldns` utilities
in the Rust programming language. These support low-level DNS and DNSSEC
operations and define a higher level API which, for example, allow you create
or sign packets.

`dnst` currently offers drop-in replacement of the following tools:

- key2ds
- keygen
- nsec3hash  
- signzone  
- notify  
- update
