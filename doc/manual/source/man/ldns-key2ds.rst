ldns-key2ds
===============

Synopsis
--------

:program:`ldns-key2ds` ``[OPTIONS]`` ``<KEYFILE>``

Description
-----------

**ldns-key2ds** is used to transform a public DNSKEY RR to a DS RR.  When run
it will read ``<KEYFILE>`` with a DNSKEY RR in it, and it will create a .ds
file with the DS RR in it.

It prints out the basename for this file (``K<name>+<alg>+<id>``).

By default, it takes a pick of algorithm similar to the key algorithm,
SHA1 for RSASHA1, and so on.

Options
-------

.. option:: -f

      Ignore SEP flag (i.e. make DS records for any key)

.. option:: -n

      Write the result DS Resource Record to stdout instead of a file

.. option:: -1

      Use SHA1 as the hash function.

.. option:: -2

      Use SHA256 as the hash function

.. option:: -4

      Use SHA383 as the hash function
