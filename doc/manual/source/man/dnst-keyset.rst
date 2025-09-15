dnst keyset
===========

Synopsis
--------

:program:`dnst keyset` ``-c <CONF>`` ``[OPTIONS]`` ``<COMMAND>`` ``[ARGS]``

Description
-----------

The **keyset** subcommand manages a set of DNSSEC signing keys.
This subcommand is meant to be part of a DNSSEC signing solution.
The **keyset** subcommand manages keys and generates a signed DNSKEY RRset.
A separate zone signer is expected to use the zone signing keys in the key set,
signed the zone and include the DNSKEY RRset (as well as the CDS and CDNSKEY
RRsets).
The keyset subcommand supports keys stored in files and, which the dnst
program is build with the kmip feature flag, keys stored in a
Hardware Securiy Module (HSM) that can be accessed using the
Key Management Interoperability Protocol (KMIP).

The keyset subcommand operates on one zone at a time.
For each zone, keyset
maintain a configuration file, that stores configuration parameters for
key generation (which algorithm to use, whether to use a CSK and a
KSK and a ZSK), parameters for key rolls (whether key rolls are automatic
or not), the lifetimes of keys and signatures, etc.
The keyset subcommand also maintains state file for each zone.
The state file lists the keys in the key set, the current key roll state,
and has the DNSKEY, CDS, and CDNSKEY RRsets.

In addition to the configuration and state files, keyset maintains file for 
keys that are stored on in the filesystem. 
Additionally, keyset can optionally maintain a credentials file that
contains user names and passwords for the KMIP connections.

The keyset subcommand uses the Keyset type from the Domain crate to store
the set of keys together with the keys' properties such as whether a key
should sign the zone, timestamps when creates are created or become stale.
The Keyset data type also implements the basics of key rolls.

The keyset subcommand supports importing existing keys, both standalone 
public keys as well as public/private key pairs can be imported.
A standalone public key can only be import from file whereas public/private
key pairs can be either files or keys stored in an HSM.
Note that the public and private key either need to be both files or both
stored in an HSM.

Signer
^^^^^^

The zone signer is expect to read the state file that is maintained by
keyset to find the current zone signing keys, to find the signed
DNSKEY/CDS/CDNSKEY RRset and to find the KMIP configuration.

See <ref> for a description of the state file.

The signer needs to poll the state file for changes.
If the signer is in full control of running keyset, then the state file needs
to be checked for changes after running keyset with commands the can
potientially change the state file (status subcommands, etc. do not change
the state file).
If keyset can be invoke independently of the signer then the signer needs
to periodically check for changes, for example, at least very hour.

Cron
~~~~

The signatures of the DNSKEY, CDS and CDNSKEY RRsets need to updated
periodically.
In addition, key roll automation requires periodic invocation of keyset
to start new key rolls and to make progress on ones that are currently
executing.

For this purpose, keyset has a cron subcommand.
This subcommand handles any house keeping work that needs to be done.
The cron subcommand can either be executed at regular times, for example,
once an hour from the cron(1) utility.

However, keyset also maintains a field in that state file, called
``cron-next``, that specifies when the cron subcommand should be run next.
Running the cron subcommand early is fine, the current time is compared
again the ``cron-next`` field and the subcommand exits early if
``cron-next`` is in the future. 
Running the cron subcommand late may cause signatures to expire.

Create / Init
~~~~~~~~~~~~~

The initialisation of a key set for a zone consists of two steps.
First the create subcommand create a configuration file with mostly default
values and state file without any keys.
The init subcommand finishes the initialisation.

This two step procedure allows configuration parameters to be set between
the create and the init subcommand, for example, the algorithm to use.
It also allows existing public/private key pairs to be imported.

The init subcommand checks if any public/private key pairs have been imported.
If so, init checks if both a both rolls (KSK and ZSK) are present.
A single CSK combines both rolls.
Absent a CSK, both a KSK and a ZSK need to present otherwise the init command
fails.
Any import public keys are ignored by init.

If no public/private key pairs have been imported then the init subcommand
will start an algorithm roll.
The algorithm roll will create new keys based on the current configuration:
either as files or in an HSM and either a CSK or a pair of KSK and ZSK.

Key Rolls
~~~~~~~~~

The keyset subcommand can perform four different types of key rolls: 
KSK rolls, ZSK rolls, CSK rolls and algorithm rolls.
A KSK roll replaces one KSK with a new KSK.
Similarly, ZSK roll replaces one ZSK with a new ZSK.
A CSK roll also replaces a CSK with a new CSK but the roll also treat a
pair of KSK and ZSK keys as equivalent to a CSK.
So a CSK roll can also roll from KSK plus ZSK to a new CSK or from a CSK
to new a KSK and ZSK pair.
Somewhat surprisingly, a roll from KSK plus ZSK to a new KSK plus ZSK pair
is also supported.
Finally, an algorithm roll is similar to a CSK roll, but design in 
a specific way to handle the case where the new key or keys have an algorithm
that is different from one used by the current signing keys.

The KSK and ZSK rolls are completely independent and can run in parallel.
Consistency checks are performed at the start of a key roll.
For example, a KSK key roll cannot start when another KSK is in progress or
when a CSK or algorithm roll is in progress.
A KSK roll cannot start either when the current signing key is a CSK or
when the configuration specifies that the new signing key has to be a CSK.
Finally, KSK rolls are also prevented when the algorithm for new keys is
different from the one use by the current key.
Similar limitations apply to the other roll types. Note however that an
algorithm roll can be started even when it is not needed.

A key roll consists of six steps: ``start-roll``, ``propagation1-complete``,
``cache-expired1``, ``propagation2-complete``, ``cache-expired2``, and
``roll-done``.
For each key roll these six steps follow in the same order.
Associated which each step is a (possibly empty) list of actions.
Actions fall in three categories.
The category consists of actions that require updating the zone or the
parent zone.
The second category consist of actions that require checking of changes
have propagated to all nameservers and require reporting of the 
TTLs of the changed RRset as seen at the nameservers.
Finally, the last category requires waiting for changes to propagate to 
all nameservers but there is no need to report the TTL.

Typically, in a list of actions, an action of the first category is paired
with one from the second of third category. 
For example, ``UpdateDnskeyRrset`` is paired with eiher
``ReportDnskeyPropagated`` or ``WaitDnskeyPropagated``.

A key roll start with the ``start-roll`` step, which creates new keys.
The next step, ``propagation1-complete`` has a TTL argument which is the
maximum of the TTLs of the Report actions.
The ``cache-expired1`` and ``cache-expired2`` have no associated actions.
They simply require waiting for the TTL (in seconds) reported by the
previous ``propagation1-complete`` or ``propagation2-complete``.
The ``propagation2-complete`` is similar to ``propagation1-complete``.
Finally, the ``roll-done`` step typically has associated Wait actions.
These actions are cleanup actions and are harmless but confusing if they
are skipped.

The keyset subcommand provides fine grained control over automation.
Automation is configured separately for each of the four roll types.
For each roll type, there are four booleans called``start``, ``report``,
``expire`` and ``done``.

When set, ``start`` boolean directs the cron subcommand to start a key roll
when a relvant key has expired. 
KSK and ZSK key roll can start automatically if respectively a KSK or a ZSK
has expired.
A CSK can start automatically when a CSK has expired but also when a KSK or
ZSK has expired and the new key will be a CSK.
Finally, an algorithm roll start automatically when the new algorithm is
different from the one used by the existing keys and any key has expired.

The ``report`` flags control the automation of the ``propagation1-complete``
and ``propagation2-complete`` steps.
When enabled, the cron subcommand contact the nameservers of the zone or
(in the case of ``ReportDsPropagated``, the nameservers of the parent zone)
to check if change have propagated to all nameservers.
The check obtains the list of nameservers from the apex of the (parent) zone
and collect all IPv4 and IPv6 address. 
For the ReportDnskeyPropagated and ReportDsPropagated action, each address is
the queried to see if the DNSKEY RRset matches or the DS RRset matches
the KSKs.
The ReportRrsigPropagated action is more complex.
First the entire zone is transfer from the primary nameserver listed in the
SOA record.
Then all relevant signatures are checked if they have the expected key tags.
The maximum TTL in the zone is recorded to be reported.
Finally, all addresses of listed nameservers are checked to see if they
have a SOA serial that is greater or equal to the one that was checked.

Automation of ``cache-expired1`` and ``cache-expired2`` is enabled by the
``expire`` boolean.
When enabled, the cron subcommand simply checks if enough time has passed
to invoke ``cache-expired1`` or ``cache-expired2``.

Finally the ``done`` boolean enabled automation of the ``roll-done`` step.
This automation is very similar to the ``report`` automation.
This only difference is that the Wait actions are automated so propagation
is track but no TTL is reported.

Fine grained control of over automation makes it possible to automate
KSK or algorithm except that they are start manually.
Or let a key roll progress automatically except that the ``cache-expired``
steps are manual to be able insert extra manual steps.

The ``report`` and ``done`` automations require that keyset has network access
to all nameservers of the zone and all nameservers of the parent.

HSM Support (KMIP)
~~~~~~~~~~~~~~~~~~

Importing Keys
~~~~~~~~~~~~~~

There are three basic ways to import exiting keys: public-key,
a public/private key pair from files or a public/private key pair in an HSM.

A public key can only be import from a file.
When the key is imported the name of the file is stored in the key set and
the key will be included in DNSKEY RRset.
This is useful for certain migration and to manually implement a 
multi-signer DNSSEC signing setup.
Note that automation does not work for the case.

A public/private key pair can be imported from files.
It sufficient to give the name of the file that holds the public key if
the filename ends in ``.key`` and the filename is the private key is the
same except that it ends in ``.private``. 
If this is not the case then the private key filename can be specified 
separately.

Importing a public/private key on an HSM require specifying the KMIP
server ID, the ID of the public key, the ID of the private key, the
DNSSEC algorithm of the key and the flags (typically 256 for a ZSK and
257 for a KSK).

Normally, keyset assumes ownership of any keys it hold.
This mean that when a key is deleted from the key set, the keyset subcommand
will also delete the files that hold the public and private or delete the
key from the HSM.

For an import public/private key pair this is considered too dangerous
because another signer may need the keys.
For this reason keys are imported in so-called ``decoupled`` state.
When a decoupled key is deleted, only the reference to the key is deleted
from the key set, the underlying keys are left untouched.
There is a ``--coupled`` option to tell keyset to take ownership of the key.


Migration
~~~~~~~~~

Options
-------

.. option:: -v

      Enable verbose output.

.. option:: -h, --help

      Print the help text (short summary with ``-h``, long help with
      ``--help``).

Commands
--------

Here come the commands.
