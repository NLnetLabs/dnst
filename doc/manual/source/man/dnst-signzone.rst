dnst signzone
===============

Synopsis
--------

:program:`dnst signzone` ``[OPTIONS]`` ``<ZONEFILE>`` ``<KEY>...``

Description
-----------

**dnst signzone** signs the zonefile with the given key(s).

Keys must be specified by their base name (usually ``K<name>+<alg>+<id>``),
i.e. WITHOUT the ``.private`` or ``.key`` extension. Both ``.private`` and
``.key`` files are required.

Arguments
---------

.. option:: <ZONEFILE>

      The zonefile to sign. Any existing NSEC(3) and/or RRSIG resource records
      will be skipped when loaded the file.

.. option:: <KEY>...

      The keys to sign the zonefile with.

Options
-------

.. option:: -d

      Do not add used keys to the resulting zonefile.

.. option:: -e <DATE>

      Set the expiration date of signatures to this date (see
      :ref:`dnst-signzone-dates`). Defaults to 4 weeks from now.

.. option:: -f <FILE>

      Write signed zone to file. Use ``-f -`` to output to stdout. Defaults to
      ``<ZONEFILE>.signed``.

.. option:: -i <DATE>

      Set the inception date of signatures to this date (see
      :ref:`dnst-signzone-dates`). Defaults to now.

.. option:: -o <DOMAIN>

      Set the origin for the zone (only necessary for zonefiles with relative
      names and no $ORIGIN).

.. option:: -u

      Set SOA serial to the number of seconds since Jan 1st 1970.

      If this would NOT result in the SOA serial increasing it will be
      incremented instead.

.. option:: -n

      Use NSEC3 instead of NSEC. By default, RFC 9276 best practice settings
      are used: SHA-1, no extra iterations, empty salt. To use different NSEC3
      settings see :ref:`dnst-signzone-nsec3-options`.

.. option:: -A

      Sign DNSKEYs with all keys instead of the minimal set.

.. option:: -U

      Sign with every unique algorithm in the provided keys.

.. option:: -z <[SCHEME:]HASH>

      Add a ZONEMD resource record. Accepts both mnemonics and numbers.
      This option can be provided more than once to add multiple ZONEMD RRs.
      However, only one per scheme-hash tuple will be added.

      | HASH supports ``SHA384`` (1) and ``SHA512`` (2).
      | SCHEME supports ``SIMPLE`` (1), the default.

.. option:: -Z

      Allow adding ZONEMD RRs without signing the zone. With this option, the
      <KEY>... argument becomes optional and determines whether to sign the
      zone.

.. option:: -H

      Hash only, don't sign. With this option, the normally mandatory <KEY>...
      argument can be omitted.

.. option:: -M

      Do not require that key names match the apex of the zone to sign.

.. option:: -h, --help

      Print the help text (short summary with ``-h``, long help with
      ``--help``).


.. _dnst-signzone-formatting-options:

Output formatting options
--------------------------------

The following options can be used to affect the format of the output.

.. option:: -b

      Add comments on DNSSEC records. Without this option only DNSKEY RRs
      will have their key tag annotated in the comment.

.. option:: -L

      Preceed the zone output by a list that contains the NSEC3 hashes of the
      original ownernames.

.. option:: -O

      Order NSEC3 RRs by unhashed owner name.

.. option:: -R

      Order RRSIG RRs by the record type that they cover.

.. option:: -T

      Output YYYYMMDDHHmmSS RRSIG timestamps instead of seconds since epoch.


.. _dnst-signzone-nsec3-options:

NSEC3 options
--------------------------------

The following options can be used with ``-n`` to override the default NSEC3
settings used.

.. option:: -a <ALGORITHM NUMBER OR MNEMONIC>

      Specify the hashing algorithm. Defaults to SHA-1.

.. option:: -s <STRING>

      Specify the salt as a hex string. Defaults to ``-``, meaning empty salt.

.. option:: -t <NUMBER>

      Set the number of extra hash iterations. Defaults to 0.

.. option:: -p

      Set the opt-out flag on all NSEC3 RRs.

.. option:: -P

      Set the opt-out flag on all NSEC3 RRs and skip unsigned delegations.

.. TODO: document nsec3_opt_out

.. _dnst-signzone-dates:

DATES
-----

A date can be a UNIX timestamp as seconds since the Epoch (1970-01-01
00:00 UTC), or of the form ``<YYYYMMdd[hhmmss]>``.
