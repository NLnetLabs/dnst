dnst-nsec3-hash
===============

Synopsis
--------

:program:`dnst nsec3-hash` [``options``] :samp:`domain-name`

Description
-----------

**dnst nsec3-hash** prints the NSEC3 hash for the given domain name.

Options
-------

.. option:: -a number-or-mnemonic, --algorithm=number-or-mnemonic

      Use the given algorithm number for the hash calculation. Defaults to
      ``sha1``.

.. option:: -s salt, --salt=count

      Use the given salt for the hash calculation. The salt value should be
      in hexadecimal format.

.. option:: -i count, -t count, --iterations=count

      Use *count* iterations for the hash calculation.

