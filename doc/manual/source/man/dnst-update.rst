dnst update
===============

Synopsis
--------

:program:`dnst update` ``[OPTIONS]`` ``<DOMAIN NAME>`` ``<COMMAND>``

:program:`dnst update` ``[OPTIONS]`` ``<DOMAIN NAME>`` :subcmd:`add` ``<RRTYPE>`` ``[RDATA]...``

:program:`dnst update` ``[OPTIONS]`` ``<DOMAIN NAME>`` :subcmd:`delete` ``<RRTYPE>`` ``[RDATA]...``

:program:`dnst update` ``[OPTIONS]`` ``<DOMAIN NAME>`` :subcmd:`clear` ``<RRTYPE>``

Description
-----------

**dnst update** sends an RFC 2136 Dynamic Update message to the name servers
for a zone to add, update, or delete arbitrary Resource Records for a domain
name.

The message to be sent can be optionally authenticated using a given TSIG key.

**dnst update [...] add** adds the given RRs to the domain.

**dnst update [...] delete** deletes the given RRs from the domain. It can be
used to delete individual RRs or a whole RRset.

**dnst update [...] clear** clears (deletes) all RRs of any type from the
domain name.

Arguments
---------

.. option:: <DOMAIN NAME>

      The domain name of the RR(s) to update.

.. option:: <COMMAND>

      Which action to take: add, delete, or clear.

Options:
--------

.. option:: -c, --class <CLASS>

      Class

      Defaults to IN.

.. option:: -t, --ttl <TTL>

      TTL in seconds or with unit suffix (s, m, h, d, w, M, y).

      Defaults to 3600.

.. option:: -s, --server <IP>

      Name server to send the update to (can be provided multiple times).

      The UPDATE message will be sent to each server in a row until a name server replies with 
      TODO: 

      By default, the list of name servers to try one-by-one is fetched from
      the zone's NS RRset.

.. option:: -z, --zone <ZONE>

      The zone the domain name belongs to (to skip a SOA query)

.. option:: -y, --tsig <NAME:KEY[:ALGO]>

      TSIG credentials for the UPDATE packet

.. option:: --rrset-exists <DOMAIN_NAME_AND_TYPE>

      RRset exists (value independent). (Optionally) provide this option
      multiple times, with format ``<DOMAIN_NAME> <TYPE>`` each, to build up
      a list of RR(set)s.

      This specifies the prerequisite that at least one RR with a specified
      NAME and TYPE must exist.

      If the domain name is relative, it will be relative to the zone's apex.

      [aliases: --rrset]

.. option:: --rrset-exists-exact <RESOURCE_RECORD>

      RRset exists (value dependent). (Optionally) provide this option multiple
      times, each with one RR in zonefile format, to build up one or more
      RRsets that is required to exist. CLASS and TTL can be omitted.

      This specifies the prerequisite that a set of RRs with a specified NAME
      and TYPE exists and has the same members with the same RDATAs as the
      RRset specified.

      If the domain name is relative, it will be relative to the zone's apex.

      [aliases: --rrset-exact]

.. option:: --rrset-non-existent <DOMAIN_NAME_AND_TYPE>

      RRset does not exist. (Optionally) provide this option multiple times,
      with format ``<DOMAIN_NAME> <TYPE>`` each, to build up a list of RRs that
      specify that no RRs with a specified NAME and TYPE can exist.

      If the domain name is relative, it will be relative to the zone's apex.

      [aliases: --rrset-empty]

.. option:: --name-in-use <DOMAIN_NAME>

      Name is in use. (Optionally) provide this option multiple times, with
      format ``<DOMAIN_NAME>`` each, to collect a list of NAMEs that must own
      at least one RR.

      Note that this prerequisite is NOT satisfied by empty nonterminals.

      If the domain name is relative, it will be relative to the zone's apex.

      [aliases: --name-used]

.. option:: --name-not-in-use <DOMAIN_NAME>

      Name is not in use. (Optionally) provide this option multiple times, with
      format ``<DOMAIN_NAME>`` each, to collect a list of NAMEs that must NOT
      own any RRs.

      Note that this prerequisite IS satisfied by empty nonterminals.

      If the domain name is relative, it will be relative to the zone's apex.

      [aliases: --name-unused]

.. option:: -h, --help

      Print the help text (short summary with ``-h``, long help with
      ``--help``). Can also be used on the individual sub commands.

Arguments for :subcmd:`add` and :subcmd:`delete`
------------------------------------------------------

.. option:: <RRTYPE>

      The RR type to add or delete.

.. option:: [RDATA]...

      One or more RDATA arguments (fully optional for :subcmd:`delete`).

      Each argument corresponds to a single RR's RDATA, so beware of (shell and
      DNS) quoting rules.

      Each RDATA argument will be parsed as if it was read from a zone file.

      | Examples:
      | :code:`dnst update some.example.com add AAAA ::1 2001:db8::`
      | :code:`dnst update some.example.com add TXT '"Spacious String" "Another
          string for the same TXT record"' '"This is another TXT RR"'`
