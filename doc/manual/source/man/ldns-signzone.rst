ldns-signzone
===============

Synopsis
--------

:program:`ldns-signzone` ``[OPTIONS]`` ``<ZONEFILE>`` ``<KEY>...``

Description
-----------

**ldns-signzone** signs the zone with the given key(s).

Keys must be specified by their base name (usually ``K<name>+<alg>+<id>``),
i.e. WITHOUT the ``.private`` or ``.key`` extension. Both ``.private`` and
``.key`` files are required.

A date can be a unix timestamp (seconds since the epoch), or of the form
``<YYYYMMdd[hhmmss]>``.


Options
-------

.. option:: <ZONEFILE>

      The zonefile to sign.

.. option:: <KEY>...

      The keys to sign the zonefile with.

.. option:: -b

      Add comments on DNSSEC records. Without this option only DNSKEY RRs
      will have their key tag annotated in the comment.

.. option:: -d

      Do not add used keys to the resulting zonefile.

.. option:: -e <DATE>

      Set the expiration date of signatures to this date. Defaults to
      4 weeks from now.

.. option:: -f <FILE>

      Write signed zone to file. Use ``-f -`` to output to stdout. Defaults to
      ``<ZONEFILE>.signed``.

.. option:: -i <DATE>

      Set the inception date of signatures to this date. Defaults to now.

.. option:: -o <DOMAIN>

      Set the origin for the zone (only necessary for zonefiles with
      relative names and no $ORIGIN).

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

The following options can be used with ``-n`` to override the default NSEC3
settings used.

.. option:: -a <ALGORITHM>

      Specify the hashing algorithm. Defaults to SHA-1.

.. option:: -t <NUMBER>

      Set the number of hash iterations. Defaults to 0.

.. option:: -s <STRING>

      Specify the salt as a hex string. Defaults to ``-``, meaning no salt.

.. option:: -p

      Set the opt-out flag on all NSEC3 RRs.
