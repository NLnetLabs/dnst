ldns-signzone
===============

Synopsis
--------

:program:`ldns-signzone` [``OPTIONS``] ``<ZONEFILE>`` ``<KEY>...``

Description
-----------

**ldns-signzone** signs the zone with the given key(s).

Keys must be specified by their base name (usually ``K<name>+<alg>+<id>``),
i.e. WITHOUT the ``.private`` or ``.key`` extension. Both ``.private`` and
``.key`` files are required.

A date can be a timestamp (seconds since the epoch), or of the form
<YYYYMMdd[hhmmss]>.


Options
-------

.. option:: <ZONEFILE>

      The zonefile to sign.

.. option:: <KEY>...

      The keys to sign the zone with.

.. option:: -b

      Use a more readable layout in the signed zone file and print comments on
      DNSSEC records.

.. option:: -d

      Do not add used keys to the resulting zone file.

.. option:: -e <DATE>

      Set the expiration date. Defaults to 4 weeks from now.

.. option:: -f <FILE>

      Write signed zone to file. Use ``-f -`` to output to stdout. Defaults to
      ``<ZONEFILE>.signed``.

.. option:: -i <DATE>

      Set the inception date. Defaults to now.

.. option:: -o <domain>

      Set the origin for the zone (for zonefiles with relative names and no
      $ORIGIN).

.. option:: -u

      Set SOA serial to the number of seconds since Jan 1st 1970.

.. option:: -n

      Use NSEC3 instead of NSEC. If specified, you can use extra options (see
      :ref:`ldns-signzone-nsec3-options`).

.. option:: -h

      Print the help text.

.. option:: -v

      Print the version and exit.


.. _ldns-signzone-nsec3-options:

NSEC3 options
--------------------------------

NSEC3 options for use with ``-n``.

.. option:: -a <ALGORITHM>

      Specify the hashing algorithm. Defaults to SHA-1.

.. option:: -t <NUMBER>

      Set the number of hash iterations. Defaults to 0.

.. option:: -s <STRING>

      Specify the salt. Defaults to ``-``, meaning no salt.

.. option:: -p

      Set the opt-out flag on all NSEC3 RRs.
