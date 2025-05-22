ldns-update
===============

Synopsis
--------

:program:`ldns-update` ``<DOMAIN NAME>`` ``[ZONE]`` ``<IP>``
``[<TSIG KEY NAME> <TSIG ALGORITHM> <TSIG KEY DATA>]``

Description
-----------

**ldns-update** sends a dynamic update packet to update an IP (or delete all
existing IPs) for a domain name.

Options
-------

.. option:: <DOMAIN NAME>

      The domain name to update the IP address of

.. option:: <ZONE>

      The zone to send the update to (if omitted, derived from SOA record)

.. option:: <IP>

      The IP to update the domain with (``none`` to remove any existing IPs)

.. option:: <TSIG KEY NAME>

      TSIG key name

.. option:: <TSIG ALGORITHM>

      TSIG algorithm (e.g. "hmac-sha256")

.. option:: <TSIG KEY DATA>

      Base64 encoded TSIG key data.

.. option:: -h, --help

      Print the help text (short summary with ``-h``, long help with
      ``--help``).
