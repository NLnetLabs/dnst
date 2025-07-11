dnst notify
===============

Synopsis
--------

:program:`dnst notify` ``[OPTIONS]`` ``-z <ZONE>`` ``<SERVERS>...``

Description
-----------

**dnst notify** sends a NOTIFY message to the specified name servers.

This tells them that an updated zone is available at the primaries. It can
perform TSIG signatures, and it can add a SOA serial number of the updated
zone. If a server already has that serial number it will disregard the message.

Arguments
---------

.. option:: <SERVERS>...

      One or more name servers to which NOTIFY messages will be sent, by
      default on port 53.

      Each name server can be specified as a domain name or IP address.

Options
-------

.. option:: -z <ZONE>

      The zone to send the NOTIFY for. Mandatory.

.. option:: -I <ADDRESS>

      Source IP to send the message from.

.. option:: -I <ADDRESS>

      Source IP to send the message from.

.. option:: -s <SOA VERSION>

      SOA version number to include in the NOTIFY message.

.. option:: -y, --tsig <NAME:KEY[:ALGO]>

      A base64 TSIG key and optional algorithm to use for the NOTIFY message.
      The algorithm defaults to **hmac-sha512**.

.. option:: -p, --port <PORT>

      Destination port to send the UDP packet to. Defaults to 53.

.. option:: -d, --debug

      Print debug information.

.. option:: -r, --retries <RETRIES>

      Max number of retries. Defaults to 15.

.. option:: -h, --help

      Print the help text (short summary with ``-h``, long help with
      ``--help``).
