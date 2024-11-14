ldns-notify
===============

Synopsis
--------

:program:`ldns-notify` [``OPTIONS``] ``-z <ZONE>`` ``<SERVERS>...``

Description
-----------

**ldns-notify** sends a NOTIFY packet to the specified name servers. A name
server can be specified as a domain name or IP address.

This tells them that an updated zone is available at the primaries. It can
perform TSIG signatures, and it can add a SOA serial number of the updated
zone. If a server already has that serial number it will disregard the message.

Options
-------

.. option:: -z <ZONE>

      The zone that is updated.

.. ..option:: -I <ADDRESS>
..
..       Source IP to send the message from.

.. option:: -s <SOA VERSION>

      Append a SOA record indicating the serial number of the updated zone.

.. option:: -p <PORT>

      Destination port to send the UDP packet to. Defaults to 53.

.. option:: -y <name:key[:algo]>

      A base64 TSIG key and optional algorithm to use for the NOTIFY message.
      The algorithm defaults to hmac-sha512.

.. option:: -d

      Print verbose debug information. The query that is sent and the query
      that is received.

.. option:: -r <RETRIES>

      Specify the maximum number of retries before notify gives up trying to
      send the UDP packet.

.. option:: -h

      Print the help text and exit.

.. option:: -v

      Print the version and exit.

