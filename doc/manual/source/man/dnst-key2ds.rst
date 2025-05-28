dnst key2ds
===============

Synopsis
--------

:program:`dnst key2ds` ``[OPTIONS]`` ``<KEYFILE>``

Description
-----------

**dnst key2ds** generates a DS RR for each DNSKEY in ``<KEYFILE>``.

The following file will be created for each key: ``K<name>+<alg>+<id>.ds``. The
base name ``K<name>+<alg>+<id>`` will be printed to stdout.

Arguments
---------

.. option:: <KEYFILE>

      ``<KEYFILE>`` must be a file containing one or more RFC 4034 ``DNSKEY``
      resource records in presentation format.

Options
-------

.. option:: -a <NUMBER OR MNEMONIC>, --algorithm <NUMBER OR MNEMONIC>

      Use the given algorithm for the digest. Defaults to the digest algorithm
      used for the DNSKEY, and if it can't be determined SHA-1.

.. option:: -f, --force

      Overwrite existing ``.ds`` files.

.. option:: --ignore-sep

      Ignore the SEP flag and make DS records for any key.

.. option:: -n

      Write the generated DS records to stdout instead of a file.

.. option:: -h, --help

      Print the help text (short summary with ``-h``, long help with
      ``--help``).

.. option:: -V, --version

      Print the version.
