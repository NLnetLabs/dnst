dnst |version|
==============

**dnst** is a DNS administration toolbox. It offers DNS and DNSSEC related
functions like key generation, zone signing, printing NSEC3 hashed domain
names, and sending UPDATE or NOTIFY messages to your name servers. More is
coming soon.

It depends on OpenSSL for its cryptography related functions.

**dnst** supports two modes of operation:

* dnst mode: the default.
* ldns emulation mode: activated by invoking dnst using the name of a supported ldns example, e.g. ldns-keygen.

**dnst** currently offers drop-in replacement of the following ldns examples:

* key2ds
* keygen
* nsec3hash
* signzone
* notify
* update

In ldns emulation mode, the supported ldns examples are very closely emulated
by dnst, though there are some exceptions. Differences are noted in the
relevant man pages of individual commands.

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Getting Started
   :name: toc-getting-started

   installation
   building

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Reference
   :name: toc-reference
   
   man/dnst
   man/dnst-key2ds
   man/dnst-keygen
   man/dnst-keyset
   man/dnst-notify
   man/dnst-nsec3-hash
   man/dnst-signzone
   man/dnst-update

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: LDNS Tools reference
   :name: toc-reference-ldns

   man/ldns-key2ds
   man/ldns-keygen
   man/ldns-notify
   man/ldns-nsec3-hash
   man/ldns-signzone
   man/ldns-update
