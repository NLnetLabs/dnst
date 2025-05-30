dnst
====

Synopsis
--------

:program:`dnst` ``[OPTIONS]`` ``<COMMAND>`` ``[ARGS]``

Description
-----------

Manage various aspects of the Domain Name System (DNS).

**dnst** provides a number of commands that perform various tasks related to
managing DNS servers and DNS zones.

Please consult the manual pages for these individual commands for more
information.

Options
-------

.. option:: -h, --help

      Print the help text (short summary with ``-h``, long help with
      ``--help``).

.. option:: -V, --version

      Print the version.

Commands
--------

.. glossary::

   :doc:`dnst-key2ds <dnst-key2ds>` (1)

        Generate DS RRs from the DNSKEYs in a keyfile.

   :doc:`dnst-keygen <dnst-keygen>` (1)

        Generate a new key pair for a domain name.

   :doc:`dnst-notify <dnst-notify>` (1)

        Send a NOTIFY message to a list of name servers.

   :doc:`dnst-nsec3-hash <dnst-nsec3-hash>` (1)

        Print out the NSEC3 hash of a domain name.

   :doc:`dnst-signzone <dnst-signzone>` (1)

        Sign the zone with the given key(s).

   :doc:`dnst-update <dnst-update>` (1)

        Send a dynamic update packet to update an IP (or delete all existing IPs) for a domain name.
