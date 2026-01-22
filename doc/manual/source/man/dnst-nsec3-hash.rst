dnst nsec3-hash
===============

Synopsis
--------

:program:`dnst nsec3-hash` ``[OPTIONS]`` ``<DOMAIN NAME>``

Description
-----------

**dnst nsec3-hash** prints the NSEC3 hash of a given domain name.

Arguments
---------

.. option:: <DOMAIN NAME>

      The domain name to generate an NSEC3 hash for.

Options
-------

.. option:: -a <NUMBER OR MNEMONIC>, --algorithm <NUMBER OR MNEMONIC>

      Use the given algorithm number for the hash calculation. Defaults to
      1 (SHA-1).

.. option:: -i <NUMBER>, -t <NUMBER>, --iterations <NUMBER>

      Use the given number of additional iterations for the hash
      calculation. Defaults to 0.

.. option:: -s <HEX STRING>, --salt <HEX STRING>

      Use the given salt for the hash calculation. The salt value should be
      in hexadecimal format. Defaults to an empty salt.

.. option:: --find-prefix <BASE32 STRING>

      Find a label that result in an NSEC3 hash that starts with a given
      string.

.. option:: -h, --help

      Print the help text (short summary with ``-h``, long help with
      ``--help``).
