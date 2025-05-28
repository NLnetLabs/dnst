ldns-signzone
===============

Synopsis
--------

:program:`ldns-signzone` ``[OPTIONS]`` ``<ZONEFILE>`` ``<KEY>...``

Description
-----------

``ldns-signzone`` is used to generate a DNSSEC signed zone. When run it will
create a new zonefile that contains RRSIG and NSEC(3) resource records, as
specified in RFC 4033, RFC 4034, RFC 4035 and RFC 5155.

This is a re-implementation of the original ``ldns-signzone`` which is largely
compatible with the original with some exceptions which are noted below.

Arguments
---------

.. option:: <ZONEFILE>

      The zonefile to sign.

      Note: Unlike the original LDNS, any existing NSEC(3), NSEC3PARAM and/or
      RRSIG resource records will be skipped when loading the zonefile.

.. option:: <KEY>...

      The keys to sign the zonefile with.

      Keys must be specified by their base file name (usually
      ``K<name>+<alg>+<id>``), i.e. WITHOUT the ``.private`` or ``.key``
      extension, with an optional path prefix. The ``.private`` file is
      required to exist. The ``.key`` file will be used if a ``DNSKEY`` record
      corresponding to the ``.private`` key cannot be found.

      Multiple keys can be specified. Key Signing Keys are used as such when
      they are either already present in the zone, or specified in a ``.key``
      file, and have the Secure Entry Point flag set.

      Note: Unlike the original LDNS, DNSKEY algorithms marked as ``MUST NOT``
      or ``NOT RECOMMENDED`` in table 3.1 of RFC 8624 "Algorithm
      Implementation Requirements and Usage Guidance for DNSSEC" are NOT
      supported.

Options
-------

.. option:: -a

      Sign the DNSKEY records with all keys. By default it is signed with a
      minimal number of keys, to keep the response size for the DNSKEY query
      small, only the SEP keys that are passed are used. If there are no
      SEP keys, the DNSKEY RRset is signed with the non-SEP keys. This option
      turns off the default and all keys are used to sign the DNSKEY RRset.

.. option:: -b

      Augments the zone and the RR's with extra comment texts for a more
      readable layout, easier to debug. NSEC3 records will have the unhashed
      owner names in the comment text.

      Without this option, only DNSKEY RR's will have their Key Tag annotated
      in the comment text.

      Note: This option is ignored if the ``-f -`` is used.

      Note: Unlike the original LDNS, DS records are printed without a
      bubblebabble version of the data in the comment text, and some ordering
      for easier consumption by humans is ONLY done if ``-b`` is in effect,
      e.g. ordering RRSIGs after the record they cover, and ordering NSEC3
      hashes by unhashed owner name rather than by hashed owner name.

.. option:: -d

      Do not add used keys to the resulting zonefile.

.. option:: -e <DATE>

      Set the expiration timestamp of signatures to the given date (and time,
      optionally, see :ref:`ldns-signzone-dates` for details about acceptable
      formats for the given ``<DATE>`` value). Defaults to 4 weeks from now.

.. option:: -f <FILE>

      Write signed zone to file. Use ``-f -`` to output to stdout. Defaults to
      ``<ZONEFILE>.signed``.

.. option:: -h

      Print the help text.

.. option:: -i <DATE>

      Set the inception timestamp of signatures to the given date (and time,
      optionally, see :ref:`ldns-signzone-dates` for details about acceptable
      formats for the given ``<DATE>`` value). Defaults to now.

.. option:: -n

      Use NSEC3 instead of NSEC. If specified, you can use extra options (see
      :ref:`ldns-signzone-nsec3-options`).

.. option:: -o <DOMAIN>

      Use this owner name as the apex of the zone.
      
      If not specified the owner name of the first SOA record will be used as
      the apex of the zone.

.. option:: -u

      Set the SOA serial in the resulting zonefile to the given number of
      seconds since January 1st 1970.

.. option:: -u

      Sign with every unique algorithm in the provided keys. The DNSKEY set is
      signed with all the SEP keys, plus all the non-SEP keys that have an
      algorithm that was not present in the SEP key set.

.. option:: -v

      Print the version and exit.

.. option:: -z <[SCHEME:]HASH>

      Add a ZONEMD resource record. Accepts both mnemonics and numbers.
      This option can be provided more than once to add multiple ZONEMD RRs.
      However, only one per scheme-hash tuple will be added.

      | HASH supports ``sha384`` (1) and ``sha512`` (2).
      | SCHEME supports ``simple`` (1), the default.

.. option:: -Z

      Allow adding ZONEMD RRs without signing the zone. With this option, the
      <KEY>... argument becomes optional and determines whether to sign the
      zone.

.. _ldns-signzone-nsec3-options:

NSEC3 options
-------------

The following options can be used with ``-n`` to override the default NSEC3
settings used.

.. option:: -a <ALGORITHM>

      Specify the hashing algorithm. Only SHA-1 is supported.

.. option:: -t <NUMBER>

      Set the number of extra hash iterations. Defaults to 0.

      Note: The default value differs to that of the original LDNS which has a
      default of 1. The new default value is in accordance with RFC 9276
      "Guidance for NSEC3 Parameter Settings".

.. option:: -s <STRING>

      Specify the salt as a hex string. Defaults to ``-``, meaning empty salt.

.. option:: -p

      Set the opt-out flag on all NSEC3 RRs.

.. _ldns-signzone-dates:

Engine Options
--------------

Unlike the original LDNS, OpenSSL engines and their associated command line
arguments are not supported by this re-implementation.

Dates
-----

A date can be a UNIX timestamp as seconds since the Epoch (1970-01-01
00:00 UTC), or of the form ``<YYYYMMdd[hhmmss]>``.

Note: RRSIG inception and expiration timestamps in the signed output zone will
be in unsigned decimal integer form (indicating seconds since 1 January 1970
00:00:00 UTC) unlike the original LDNS which produced timestamps in the form
``YYYYMMDDHHmmSS``.
