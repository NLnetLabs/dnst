# Application overview

Dnst is a collection of DNS utilities inspired by and designed to replace
the ldns utilities. Most dnst utilities are currently in early alpha
state and are not meant for production use.

There is one exception and that is the keyset utility. The keyset utility
is used by Cascade and will be considered production ready when Cascade
has a production release.

# Local environment

The dnst utilities run in an environment where local files, command arguments
and the Unix process environment can be trusted. 

Additionally, for the keyset utility, any KMIP HSM as well as the connection
to the HSM is trusted.

For the keyset utility it is also assumed that when a zone transfer is needed
during automatic key rolls, the contents of the zone as well as the connection
to the nameserver can be trusted.

# Error reporting

Some utilities generate DNS requests and receive DNS replies that can be
modified or spoofed by an attacker. It is possible that a utility panics
when receiving bad data. Such a panic is obviously a bug, but it is not
considered a security issue. A panic is just a poorly formatted error message.
