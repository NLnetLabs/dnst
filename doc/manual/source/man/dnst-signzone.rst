dnst-signzone
===============

Synopsis
--------

:program:`dnst signzone` [``OPTIONS``] ``<ZONEFILE>`` ``<KEY>...``

Description
-----------

**dnst signzone** signs the zone with the given key(s).

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

      If this would NOT result in the SOA serial increasing it will be
      incremented instead.

.. option:: -n

      Use NSEC3 instead of NSEC. If specified, you can use extra options (see
      :ref:`dnst-signzone-nsec3-options`).

.. option:: -H

      Hash only, don't sign.

.. option:: -h, --help

      Print the help text (short summary with ``-h``, long help with
      ``--help``).


.. _dnst-signzone-nsec3-options:

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

.. option:: -A

      Set the opt-out flag on all NSEC3 RRs and skip unsigned delegations.

