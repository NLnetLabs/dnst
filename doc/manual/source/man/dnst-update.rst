dnst update
===============

Synopsis
--------

:program:`dnst update` ``<DOMAIN NAME>`` ``[ZONE]`` ``<IP>``
``[<TSIG KEY NAME> <TSIG ALGORITHM> <TSIG KEY DATA>]``

Description
-----------

**dnst update** sends an RFC 2136 Dynamic Update message to the name servers
for a zone to update an IP address (or delete all existing IP addresses) for a
domain name.

The message to be sent can be optionally authenticated using a given TSIG key.

Arguments
---------

.. option:: <DOMAIN NAME>

      The domain name to update the IP address of.

.. option:: <ZONE>

      The zone to send the update to (if omitted, derived from SOA record).

.. option:: <IP>

      The IP address to update the domain with (``none`` to remove any
      existing IP addresses)

.. option:: <TSIG KEY NAME>

      TSIG key name.

.. option:: <TSIG ALGORITHM>

      TSIG algorithm (e.g. "hmac-sha256").

.. option:: <TSIG KEY DATA>

      Base64 encoded TSIG key data.

Options:
--------

.. option:: -h, --help

      Print the help text (short summary with ``-h``, long help with
      ``--help``).
