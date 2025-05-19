ldns-nsec3-hash
===============

Synopsis
--------

:program:`ldns-nsec3-hash` ``[OPTIONS]`` ``<DOMAIN NAME>``

Description
-----------

**ldns-nsec3-hash** is used to print out the NSEC3 hash for the given domain name.

Options
-------

.. option:: -a <NUMBER>

      Use the given algorithm number for the hash calculation. Defaults to
      1 (SHA-1).

.. option:: -s <SALT>

      Use the given salt for the hash calculation. The salt value should be
      in hexadecimal format. Defaults to an empty salt.

.. option:: -t <COUNT>

      Use the given number of additional iterations for the hash
      calculation. Defaults to 0. Note that this differs to the default value
      used by the original `ldns-nsec3-hash` command to comply with latest
      best practice per RFC 9276.
