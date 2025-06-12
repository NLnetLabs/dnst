ldns-keygen
===============

Synopsis
--------

:program:`ldns-keygen` ``[OPTIONS]`` ``<DOMAIN NAME>``

Description
-----------

**ldns-keygen** is used to generate a private/public keypair.

When run, it will create 3 files; a ``.key`` file with the public DNSKEY, a
``.private`` file with the private keydata and a ``.ds`` file with the DS
record of the DNSKEY record.

**ldns-keygen** prints the basename for the key files: ``K<name>+<alg>+<id>``

Options
-------

.. option:: -a <ALGORITHM>

      Create a key with this algorithm. Specifying 'list' here gives a list of
      supported algorithms. Several alias names are also accepted (from older
      versions and other software), the list gives names from the RFC. Also the
      plain algorithm number is accepted.

      Note: Unlike the original LDNS, this implementation does not support
      creation of symmetric keys (for TSIG).

.. option:: -b <BITS>

      Use this many bits for the key length.

.. option:: -k

      When given, generate a key signing key. This just sets the flag field to
      257 instead of 256 in the DNSKEY RR in the .key file.

.. option:: -r <DEVICE>

      Make ldns-keygen use this file to seed the random generator with. This
      will default to /dev/random.

.. option:: -s

      ldns-keygen will create symbolic links named ``.private`` to the new
      generated private key, ``.key`` to the public DNSKEY and ``.ds`` to the
      file containing DS record data.

.. option:: -f

      Force symlinks to be overwritten if they exist.

.. option:: -v

      Show the version and exit
