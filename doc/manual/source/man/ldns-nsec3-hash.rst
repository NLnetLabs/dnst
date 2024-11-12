ldns-nsec3-hash
===============

Synopsis
--------

:program:`ldns-nsec3-hash` :samp:`<{domain-name}>`

Description
-----------

**ldns-nsec3-hash** is used to print out the NSEC3 hash for the given domain name.

Options
-------

.. option:: -a number

      Use the given algorithm number for the hash calculation. Defaults to
      1 (SHA-1).

.. option:: -s salt

      Use the given salt for the hash calculation. The salt value should be
      in hexadecimal format.

.. option:: -t count

      Use count iterations for the hash calculation.
