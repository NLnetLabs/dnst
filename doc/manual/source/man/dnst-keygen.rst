dnst-keygen
===============

Synopsis
--------

:program:`dnst keygen` [``OPTIONS``] ``-a <ALGORITHM>`` ``<DOMAIN NAME>``

Description
-----------

**dnst keygen** generates a new key pair for a given domain name.

The following files will be created:

- ``K<name>+<alg>+<tag>.key``: The public key file containing a DNSKEY RR in
  zone file format.

- ``K<name>+<alg>+<tag>.private``: The private key file containing the private
  key data fields in BIND's *Private-key-format*.

- ``K<name>+<alg>+<tag>.ds``: The public key digest file containing the DS RR
  in zone file format. It is only created for key signing keys.

| ``<name>`` is the fully-qualified owner name for the key (with a trailing dot).
| ``<alg>`` is the algorithm number of the key, zero-padded to 3 digits.
| ``<tag>`` is the 16-bit tag of the key, zero-padded to 5 digits.

Upon completion, ``K<name>+<alg>+<tag>`` will be printed.

Options
-------

.. option:: -a <MNEMONIC>

      Use the given signing algorithm.

      Possible values are ``RSASHA256``, ``ECDSAP256SHA256``,
      ``ECDSAP384SHA384``, ``ED25519``, ``ED448``; or ``list`` to list all
      available algorithms.

.. option:: -k

      Generate a key signing key (KSK) instead of a zone signing key (ZSK).

.. option:: -b <BITS>

      The length of the key (for RSA keys only). Defaults to 2048.

.. option:: -r <DEVICE>

      The randomness source to use for generation. Defaults to ``/dev/urandom``.

.. option:: -s

      Create symlinks ``.key`` and ``.private`` to the generated keys.

.. option:: -f

      Overwrite existing symlinks (for use with ``-s``).

.. option:: -h, --help

      Print the help text (short summary with ``-h``, long help with
      ``--help``).
