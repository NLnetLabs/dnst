// Relevant RFCs:
//
// - [RFC2136]: Dynamic Updates in the Domain Name System (DNS UPDATE)
// - [RFC3007]: Secure Domain Name System (DNS) Dynamic Update
//
// [RFC2136]: https://www.rfc-editor.org/rfc/rfc2136.html
// [RFC3007]: https://www.rfc-editor.org/rfc/rfc3007.html
//
// Important notes:
//
// - No duplicate protection through update ordering with marker RRs

use std::ffi::OsString;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use clap::Subcommand;
use domain::base::iana::{Class, Opcode, Rcode};
use domain::base::message_builder::AnswerBuilder;
use domain::base::name::{FlattenInto, UncertainName};
use domain::base::{
    Message, MessageBuilder, Name, Question, Record, Rtype, ToName, Ttl, UnknownRecordData,
};
use domain::net::client::request::{RequestMessage, SendRequest};
use domain::net::client::{dgram, tsig};
use domain::rdata::{Aaaa, AllRecordData, Ns, Soa, ZoneRecordData, A};
use domain::resolv::stub::conf::{ResolvConf, ServerConf, Transport};
use domain::tsig::Key;
use domain::utils::base64;
use domain::zonefile::inplace::{Entry, Zonefile};

use crate::env::Env;
use crate::error::{Context, Error};
use crate::parse::TSigInfo;
use crate::Args;

use super::{parse_os, parse_os_with, Command, LdnsCommand};

type ParsedRecord = Record<Name<Vec<u8>>, ZoneRecordData<Vec<u8>, Name<Vec<u8>>>>;
type NameTypeTuple = (Name<Vec<u8>>, Rtype);

//------------ Update --------------------------------------------------------

#[derive(Clone, Debug, clap::Args, PartialEq, Eq)]
pub struct Update {
    /// Domain name to update
    #[arg(value_name = "DOMAIN NAME")]
    domain: Name<Vec<u8>>,

    /// Update action
    #[command(subcommand)]
    action: UpdateAction,

    /// Class
    #[arg(short = 'c', long = "class", default_value_t = Class::IN)]
    class: Class,

    /// TTL in seconds or with unit suffix (s, m, h, d, w, M, y).
    ///
    /// Is only used by the `add` command and ignored otherwise.
    #[arg(short = 't', long = "ttl", value_parser = Update::parse_ttl, default_value = "3600")]
    ttl: Ttl,

    /// Name server to send the update to
    #[arg(short = 's', long = "server", value_name = "IP")]
    nameservers: Option<IpAddr>,

    /// Zone the domain name belongs to (to skip SOA query)
    #[arg(short = 'z', long = "zone", value_name = "ZONE")]
    zone: Option<Name<Vec<u8>>>,

    /// TSIG credentials for the UPDATE packet
    #[arg(short = 'y', long = "tsig", value_name = "NAME:KEY[:ALGO]")]
    tsig: Option<TSigInfo>,

    /// RRset exists (value independent). (Optionally) provide this option
    /// multiple times, with format "<DOMAIN_NAME> <TYPE>" each, to
    /// build up a list of RR(set)s.
    ///
    /// This specifies the prerequisite that at least one RR with a specified
    /// NAME and TYPE must exist.
    ///
    /// If the domain name is relative, it will be relative to the zone's apex.
    #[arg(
        long = "rrset-exists",
        visible_alias = "rrset",
        value_name = "DOMAIN_NAME_AND_TYPE"
    )]
    rrset_exists: Option<Vec<String>>,

    /// RRset exists (value dependent). (Optionally) provide this option
    /// multiple times, each with one RR in zonefile format, to build up one
    /// or more RRsets that is required to exist. CLASS and TTL can be
    /// omitted.
    ///
    /// This specifies the prerequisite that a set of RRs with a specified
    /// NAME and TYPE exists and has the same members with the same RDATAs as
    /// the RRset specified.
    ///
    /// If the domain name is relative, it will be relative to the zone's apex.
    #[arg(
        long = "rrset-exists-exact",
        visible_alias = "rrset-exact",
        value_name = "RESOURCE_RECORD"
    )]
    rrset_exists_exact: Option<Vec<String>>,

    /// RRset does not exist. (Optionally) provide this option multiple times,
    /// with format "<DOMAIN_NAME> <TYPE>" each, to build up a list of RRs
    /// that specify that no RRs with a specified NAME and TYPE can exist.
    ///
    /// If the domain name is relative, it will be relative to the zone's apex.
    #[arg(
        long = "rrset-non-existent",
        visible_alias = "rrset-empty",
        value_name = "DOMAIN_NAME_AND_TYPE"
    )]
    rrset_non_existent: Option<Vec<String>>,

    /// Name is in use. (Optionally) provide this option multiple times,
    /// with format "<DOMAIN_NAME>" each, to collect a list of NAMEs that must
    /// own at least one RR.
    ///
    /// Note that this prerequisite is NOT satisfied by empty nonterminals.
    ///
    /// If the domain name is relative, it will be relative to the zone's apex.
    #[arg(
        long = "name-in-use",
        visible_alias = "name-used",
        value_name = "DOMAIN_NAME"
    )]
    name_in_use: Option<Vec<String>>,

    /// Name is not in use. (Optionally) provide this option multiple times,
    /// with format "<DOMAIN_NAME>" each, to collect a list of NAMEs that must
    /// NOT own any RRs.
    ///
    /// Note that this prerequisite IS satisfied by empty nonterminals.
    ///
    /// If the domain name is relative, it will be relative to the zone's apex.
    #[arg(
        long = "name-not-in-use",
        visible_alias = "name-unused",
        value_name = "DOMAIN_NAME"
    )]
    name_not_in_use: Option<Vec<String>>,
}

impl Update {
    pub fn execute(self, env: impl Env) -> Result<(), Error> {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(self.run(&env))
    }

    /// Run the command as an async function
    pub async fn run(self, env: &impl Env) -> Result<(), Error> {
        // 1. Know apex and name servers for zone
        // 2. If update ordering desired, fetch existing SOA RR from primary
        //      - If updating SOA, must update in serial in positive direction and preserve other
        //      fields, unless intent to change them; serial must never be 0
        //    (not yet implemented)
        // 3. Order nameserver list, listing primary first
        // 4. Create UPDATE and send to first server in list
        // 5. If response != SERVFAIL | NOTIMP, then return success
        // 6. If response == SERVFAIL | NOTIMP, OR no response in software
        //    dependent timeout, OR ICMP error, THEN delete unusable server
        //    from list and try the next one. Repeat 4,5,6 until success, or
        //    list empty; return.

        // 1. If not provided, determine zone apex and fetch name servers
        let (apex, mname, _soa) = match &self.zone {
            Some(zone) => {
                let tmp = update_helpers::find_mname_and_soa(env, zone)
                    .await
                    .context("fetching the SOA record")?;
                (zone.clone(), tmp.0, tmp.1)
            }
            None => update_helpers::find_mname_and_zone_and_soa(env, &self.domain)
                .await
                .context("fetching the SOA record and determining the zone apex")?,
        };

        // // mname is only used to put the primary first in the later fetched
        // // list of name servers, therefore, if we have IP addresses to sent
        // // the update to, we don't need to put the primary first and can let
        // // the user determine the ordering, and therefore can skip the SOA
        // // query.
        // let (apex, mname) = match (&self.zone, self.nameservers.is_empty()) {
        //     (Some(zone), true) => (
        //         zone.clone(),
        //         Some(update_helpers::find_mname(env, &zone).await?),
        //     ),
        //     (Some(zone), false) => (zone.clone(), None),
        //     (None, _) => {
        //         let (a, b) = update_helpers::find_mname_and_zone(env, &self.domain).await?;
        //         (a, Some(b))
        //     }
        // };

        // Parse prerequisites before fetching nameservers, in case parsing fails
        let prerequisites = self.parse_prerequisites(apex.clone().flatten_into())?;

        // 1. (Cont.) If not provided, determine zone apex and fetch name servers
        let nsnames = if self.nameservers.is_none() {
            Some(
                // 3. Order nameserver list, listing primary first
                update_helpers::determine_nsnames(env, &apex, &mname)
                    .await
                    .context("while fetching the authoritative nameservers for the zone")?,
            )
        } else {
            None
        };

        // 4. Create UPDATE and send to first server in list
        // TODO: pass SOA record fetched above to make sure changes to the SOA
        // record by the user adhere to the RFC specifications of e.g. only
        // increasing serial
        let msg = self.create_update_message(&apex, prerequisites)?;

        self.send_update(env, msg, nsnames).await?;

        Ok(())
    }

    fn parse_prerequisite_name_type(
        args: &Vec<String>,
        origin: &Name<Vec<u8>>,
    ) -> Result<Vec<NameTypeTuple>, Error> {
        let mut records = Vec::new();
        for arg in args {
            if let Some((name, typ)) = arg.split_once(' ') {
                let typ = Rtype::from_str(typ).map_err(|e| -> Error {
                    format!("Invalid resource record type '{typ}': {e}").into()
                })?;
                let uncertain = UncertainName::from_str(name).map_err(|e| -> Error {
                    format!("Invalid domain name '{name}': {e}").into()
                })?;
                let name = match uncertain.as_absolute() {
                    Some(name) => name.clone(),
                    None => uncertain
                        .chain(origin)
                        .expect("we just checked that its not absolute")
                        .to_name(),
                };
                records.push((name, typ))
            } else {
                return Err(format!(
                    "Invalid prerequisite argument format. Expected format '<DOMAIN_NAME> <TYPE>', was '{arg}'."
                )
                .into());
            }
        }
        Ok(records)
    }

    fn parse_prerequisite_name(
        args: &Vec<String>,
        origin: &Name<Vec<u8>>,
    ) -> Result<Vec<Name<Vec<u8>>>, Error> {
        let mut names = Vec::new();
        for name in args {
            let uncertain = UncertainName::from_str(name)
                .map_err(|e| -> Error { format!("Invalid domain name '{name}': {e}").into() })?;
            let name = match uncertain.as_absolute() {
                Some(name) => name.clone(),
                None => uncertain
                    .chain(origin)
                    .expect("we just checked that its not absolute")
                    .to_name(),
            };
            names.push(name)
        }
        Ok(names)
    }

    fn parse_prerequisite_rrset_exists_exact(
        args: &Vec<String>,
        origin: &Name<Vec<u8>>,
        class: Class,
    ) -> Result<Vec<ParsedRecord>, Error> {
        let mut records = Vec::new();
        for arg in args {
            let mut zonefile = Zonefile::new();
            zonefile.extend_from_slice(arg.as_bytes());
            zonefile.extend_from_slice(b"\n");
            zonefile.set_default_class(class);
            zonefile.set_origin(origin.clone().flatten_into());
            if let Ok(Some(Entry::Record(mut record))) = zonefile.next_entry() {
                record.set_ttl(Ttl::from_secs(0));
                records.push(record.flatten_into());
            } else {
                return Err(
                    format!("Provided argument is not a valid resource record: {arg}").into(),
                );
            }
        }
        Ok(records)
    }

    fn parse_ttl(arg: &str) -> Result<Ttl, Error> {
        Ok(Ttl::from_secs(
            if let Some(ttl) = arg.strip_suffix('s') {
                ttl.parse()
            } else if let Some(ttl) = arg.strip_suffix('m') {
                ttl.parse::<u32>().map(|t| t / 60)
            } else if let Some(ttl) = arg.strip_suffix('h') {
                ttl.parse::<u32>().map(|t| t / 3600)
            } else if let Some(ttl) = arg.strip_suffix('d') {
                ttl.parse::<u32>().map(|t| t / 86400)
            } else if let Some(ttl) = arg.strip_suffix('w') {
                ttl.parse::<u32>().map(|t| t / 604800)
            } else if let Some(ttl) = arg.strip_suffix('M') {
                ttl.parse::<u32>().map(|t| t / 2629746) // 30.436875 days
            } else if let Some(ttl) = arg.strip_suffix('y') {
                ttl.parse::<u32>().map(|t| t / 31556952) // 365.2425 days
            } else {
                arg.parse()
            }
            .map_err(|err| Error::from(format!("Invalid TTL: {err}")))?,
        ))
    }

    /// Create the packet of the update message to send to the name servers
    fn create_update_message(
        &self,
        zone: &Name<Vec<u8>>,
        prerequisites: UpdatePrerequisites,
    ) -> Result<Vec<u8>, Error> {
        // UPDATE message sections:
        // Zone Section (= Question),
        // Prerequisite Section (= Answer)
        // Update Section (= Authority)
        // Additional (= Additional)

        let mut message = MessageBuilder::new_vec();

        let header = message.header_mut();
        header.set_opcode(Opcode::UPDATE);
        header.set_qr(false);

        let mut zone_section = message.question();
        zone_section
            .push(Question::new(zone, Rtype::SOA, Class::IN))
            .unwrap();

        let mut prereq_section = zone_section.answer();
        Self::insert_prerequisites(prerequisites, &mut prereq_section)?;

        let mut update_section = prereq_section.authority();

        match self.action {
            UpdateAction::Add { rtype, ref rdata } => {
                if rdata.is_empty() {
                    return Err("Provide at least one RDATA item to add".into());
                }
                for r in rdata {
                    let rdata = Self::parse_rdata(rtype, r)?;
                    update_section
                        .push(Self::create_rr_addition(
                            self.domain.clone(),
                            self.class,
                            self.ttl,
                            rdata,
                        ))
                        .map_err(|e| -> Error {
                            format!("Failed to add RR to UPDATE message: {e}").into()
                        })?
                }
            }
            UpdateAction::Delete { rtype, ref rdata } => {
                if rdata.is_empty() {
                    update_section
                        .push(Self::create_rrset_deletion(self.domain.clone(), rtype))
                        .map_err(|e| -> Error {
                            format!("Failed to add RRset deletion RR to UPDATE message: {e}").into()
                        })?
                } else {
                    for r in rdata {
                        let rdata = Self::parse_rdata(rtype, r)?;
                        update_section
                            .push(Self::create_rr_deletion(self.domain.clone(), rdata))
                            .map_err(|e| -> Error {
                                format!("Failed to add RR deletion RR to UPDATE message: {e}")
                                    .into()
                            })?
                    }
                }
            }
            UpdateAction::Clear => update_section
                .push(Self::create_all_rrset_deletion(self.domain.clone()))
                .map_err(|e| -> Error {
                    format!("Failed to add RRset deletion RR to UPDATE message: {e}").into()
                })?,
        }

        // Providing additional data is not yet implemented
        // let mut additional_section = update_section.additional();

        Ok(update_section.finish())
    }

    fn parse_rdata(
        rtype: Rtype,
        rdata: &str,
    ) -> Result<ZoneRecordData<Vec<u8>, Name<Vec<u8>>>, Error> {
        // TODO: add from_rtype_and_str to ZoneRecordData to skip this
        // workaround with zonefile?
        let mut zonefile = Zonefile::new();
        // The origin, ttl and class are irrelevant here and only needed to
        // parse the rdata
        let rr = format!(". 1 IN {rtype} {rdata}\n");
        zonefile.extend_from_slice(rr.as_bytes());
        match zonefile.next_entry() {
            Ok(Some(Entry::Record(record))) => Ok(record.data().clone().flatten_into()),
            Ok(_) => unreachable!("We always create a record"),
            Err(e) => {
                Err(format!("Failed to parse rdata for {rtype} {rdata} -- Error: {e}").into())
            }
        }
    }

    fn create_rr_addition(
        domain: Name<Vec<u8>>,
        class: Class,
        ttl: Ttl,
        rdata: ZoneRecordData<Vec<u8>, Name<Vec<u8>>>,
    ) -> ParsedRecord {
        // From [RFC2136] Section 2.5.1:
        // RRs are added to the Update Section whose NAME, TYPE, TTL, RDLENGTH
        // and RDATA are those being added, and CLASS is the same as the zone
        // class.
        ParsedRecord::new(domain, class, ttl, rdata)
    }

    fn create_rr_deletion(
        domain: Name<Vec<u8>>,
        rdata: ZoneRecordData<Vec<u8>, Name<Vec<u8>>>,
    ) -> ParsedRecord {
        // From [RFC2136] Section 2.5.4:
        // The NAME, TYPE, RDLENGTH and RDATA must match the RR being deleted.
        // TTL must be specified as zero (0) [...].
        // CLASS must be specified as NONE to distinguish this from an addition.
        ParsedRecord::new(domain, Class::NONE, Ttl::from_secs(0), rdata)
    }

    fn create_rrset_deletion(domain: Name<Vec<u8>>, rtype: Rtype) -> ParsedRecord {
        // From [RFC2136] Section 2.5.2:
        // - One RR is added to the Update Section whose NAME and TYPE are those
        //   of the RRset to be deleted.
        // - TTL must be specified as zero (0) [...].
        // - CLASS must be specified as ANY.
        // - RDLENGTH must be zero (0) and RDATA must therefore be empty.
        let rdata = ZoneRecordData::Unknown(
            UnknownRecordData::from_octets(rtype, Vec::new())
                .expect("Failed to create empty rdata"),
        );
        ParsedRecord::new(domain, Class::ANY, Ttl::from_secs(0), rdata)
    }

    fn create_all_rrset_deletion(domain: Name<Vec<u8>>) -> ParsedRecord {
        // From [RFC2136] Section 2.5.3:
        // - One RR is added to the Update Section whose NAME is that of the
        // name to be cleansed of RRsets.
        // - TYPE must be specified as ANY.
        // - TTL must be specified as zero (0) [...]
        // - CLASS must be specified as ANY.
        // - RDLENGTH must be zero (0) and RDATA must therefore be empty.
        let rdata = ZoneRecordData::Unknown(
            UnknownRecordData::from_octets(Rtype::ANY, Vec::new())
                .expect("Failed to create empty rdata"),
        );
        ParsedRecord::new(domain, Class::ANY, Ttl::from_secs(0), rdata)
    }

    fn parse_prerequisites(&self, origin: Name<Vec<u8>>) -> Result<UpdatePrerequisites, Error> {
        let mut prerequisites = UpdatePrerequisites {
            rrset_exists: None,
            rrset_exists_exact: None,
            rrset_non_existent: None,
            name_in_use: None,
            name_not_in_use: None,
        };
        if let Some(ref v) = self.rrset_exists {
            prerequisites.rrset_exists = Some(Self::parse_prerequisite_name_type(v, &origin)?)
        }
        if let Some(ref v) = self.rrset_exists_exact {
            prerequisites.rrset_exists_exact = Some(Self::parse_prerequisite_rrset_exists_exact(
                v, &origin, self.class,
            )?)
        }
        if let Some(ref v) = self.rrset_non_existent {
            prerequisites.rrset_non_existent = Some(Self::parse_prerequisite_name_type(v, &origin)?)
        }
        if let Some(ref v) = self.name_in_use {
            prerequisites.name_in_use = Some(Self::parse_prerequisite_name(v, &origin)?)
        }
        if let Some(ref v) = self.name_not_in_use {
            prerequisites.name_not_in_use = Some(Self::parse_prerequisite_name(v, &origin)?)
        }
        Ok(prerequisites)
    }

    fn insert_prerequisites(
        prerequisites: UpdatePrerequisites,
        prereq_section: &mut AnswerBuilder<Vec<u8>>,
    ) -> Result<(), Error> {
        if let Some(rrset_exists) = prerequisites.rrset_exists {
            for (domain, rtype) in rrset_exists {
                prereq_section
                    .push(Self::create_prereq_rrset_exists(domain, rtype))
                    .map_err(|e| -> Error {
                        format!("Failed to add RR to UPDATE message: {e}").into()
                    })?
            }
        }
        if let Some(rrset_exists_exact) = prerequisites.rrset_exists_exact {
            for rr in rrset_exists_exact {
                // The ttl is set while parsing the record, but in case that
                // changes, here an extra check.
                debug_assert!(rr.ttl() == Ttl::from_secs(0));
                // From [RFC2136] Section 2.4.2 - RRset Exists (Value Dependent)
                // - [...] an entire RRset whose preexistence is required.
                // - NAME and TYPE are that of the RRset being denoted.
                // - CLASS is that of the zone.
                // - TTL must be specified as zero (0) [...]
                prereq_section.push(rr).map_err(|e| -> Error {
                    format!("Failed to add RR to UPDATE message: {e}").into()
                })?
            }
        }
        if let Some(rrset_non_existent) = prerequisites.rrset_non_existent {
            for (domain, rtype) in rrset_non_existent {
                prereq_section
                    .push(Self::create_prereq_rrset_non_existent(domain, rtype))
                    .map_err(|e| -> Error {
                        format!("Failed to add RR to UPDATE message: {e}").into()
                    })?
            }
        }
        if let Some(name_in_use) = prerequisites.name_in_use {
            for domain in name_in_use {
                prereq_section
                    .push(Self::create_prereq_name_in_use(domain))
                    .map_err(|e| -> Error {
                        format!("Failed to add RR to UPDATE message: {e}").into()
                    })?
            }
        }
        if let Some(name_not_in_use) = prerequisites.name_not_in_use {
            for domain in name_not_in_use {
                prereq_section
                    .push(Self::create_prereq_name_not_in_use(domain))
                    .map_err(|e| -> Error {
                        format!("Failed to add RR to UPDATE message: {e}").into()
                    })?
            }
        }
        Ok(())
    }

    fn create_prereq_rrset_exists(domain: Name<Vec<u8>>, rtype: Rtype) -> ParsedRecord {
        // From [RFC2136] Section 2.4.1 - RRset Exists (Value Independent):
        // - [...] a single RR whose NAME and TYPE are equal to that of the zone
        // RRset whose existence is required.
        // - RDLENGTH is zero and RDATA is therefore empty.
        // - CLASS must be specified as ANY [...]
        // - TTL is specified as zero (0).
        let rdata = ZoneRecordData::Unknown(
            UnknownRecordData::from_octets(rtype, Vec::new())
                .expect("Failed to create empty rdata"),
        );
        ParsedRecord::new(domain, Class::ANY, Ttl::from_secs(0), rdata)
    }

    fn create_prereq_rrset_non_existent(domain: Name<Vec<u8>>, rtype: Rtype) -> ParsedRecord {
        // From [RFC2136] Section 2.4.3 - RRset Does Not Exist
        // - [...] a single RR whose NAME and TYPE are equal to that of the
        // RRset whose nonexistence is required.
        // - The RDLENGTH of this record is zero (0), and RDATA field is
        // therefore empty.
        // - CLASS must be specified as NONE [...]
        // - TTL must be specified as zero (0).
        let rdata = ZoneRecordData::Unknown(
            UnknownRecordData::from_octets(rtype, Vec::new())
                .expect("Failed to create empty rdata"),
        );
        ParsedRecord::new(domain, Class::NONE, Ttl::from_secs(0), rdata)
    }

    fn create_prereq_name_in_use(domain: Name<Vec<u8>>) -> ParsedRecord {
        // From [RFC2136] Section 2.4.4 - Name Is In Use
        // - [...] a single RR whose NAME is equal to that of the name whose
        // ownership of an RR is required.
        // - RDLENGTH is zero and RDATA is therefore empty.
        // - CLASS must be specified as ANY [...]
        // - TYPE must be specified as ANY [...]
        // - TTL is specified as zero (0).
        let rdata = ZoneRecordData::Unknown(
            UnknownRecordData::from_octets(Rtype::ANY, Vec::new())
                .expect("Failed to create empty rdata"),
        );
        ParsedRecord::new(domain, Class::ANY, Ttl::from_secs(0), rdata)
    }

    fn create_prereq_name_not_in_use(domain: Name<Vec<u8>>) -> ParsedRecord {
        // From [RFC2136] Section 2.4.5 - Name Is Not In Use
        // - [...] a single RR whose NAME is equal to that of the name whose
        // nonownership of any RRs is required.
        // - RDLENGTH is zero and RDATA is therefore empty.
        // - CLASS must be specified as NONE.
        // - TYPE must be specified as ANY.
        // - TTL must be specified as zero (0).
        let rdata = ZoneRecordData::Unknown(
            UnknownRecordData::from_octets(Rtype::ANY, Vec::new())
                .expect("Failed to create empty rdata"),
        );
        ParsedRecord::new(domain, Class::NONE, Ttl::from_secs(0), rdata)
    }

    /// Send the update packet to the names in nsnames in order until one responds
    async fn send_update(
        &self,
        env: impl Env,
        msg: Vec<u8>,
        nsnames: Option<Vec<Name<Vec<u8>>>>,
    ) -> Result<(), Error> {
        let msg = Message::from_octets(msg).unwrap();
        let resolver = env.stub_resolver().await;

        let tsig_key = self
            .tsig
            .as_ref()
            .map(|tsig| {
                Key::new(tsig.algorithm, &tsig.key, tsig.name.clone(), None, None)
                    .map_err(|e| format!("TSIG key is invalid: {e}"))
            })
            .transpose()?;

        async fn connect_and_send_request(
            env: &impl Env,
            socket: SocketAddr,
            msg: &Message<Vec<u8>>,
            tsig_key: &Option<Key>,
        ) -> Result<Message<bytes::Bytes>, domain::net::client::request::Error> {
            // // Using TCP directly to skip check whether the request fits
            // // in a UDP packet.
            // let tcp_connect = TcpConnect::new(socket);
            // let (tcp_connection, transport) = multi_stream::Connection::new(tcp_connect);
            // tokio::spawn(transport.run());

            // let connection: Box<dyn SendRequest<_>> = if let Some(k) = &tsig_key {
            //     Box::new(tsig::Connection::new(k.clone(), tcp_connection))
            // } else {
            //     Box::new(tcp_connection)
            // };

            let local: SocketAddr = if socket.is_ipv4() {
                ([0u8; 4], 0).into()
            } else {
                ([0u16; 8], 0).into()
            };
            let dgram_connection = dgram::Connection::new(env.dgram(local, socket));

            let connection: Box<dyn SendRequest<_>> = if let Some(k) = tsig_key {
                Box::new(tsig::Connection::new(k.clone(), dgram_connection))
            } else {
                Box::new(dgram_connection)
            };

            connection
                .send_request(RequestMessage::new(msg.clone()).unwrap())
                .get_response()
                .await
        }

        if let Some(nsnames) = nsnames {
            for name in nsnames {
                let found_ips = resolver.lookup_host(&name).await?;
                for socket in found_ips.port_iter(53) {
                    let resp = match connect_and_send_request(&env, socket, &msg, &tsig_key).await {
                        Ok(resp) => resp,
                        Err(err) => {
                            writeln!(env.stderr(), "{name} @ {socket}: {err}");
                            continue;
                        }
                    };

                    let rcode = resp.header().rcode();
                    if rcode == Rcode::SERVFAIL || rcode == Rcode::NOTIMP {
                        writeln!(env.stderr(), "Skipping {name} @ {socket}: {rcode}");
                        continue;
                    } else if rcode != Rcode::NOERROR {
                        writeln!(env.stdout(), "UPDATE response was {rcode}");
                    }
                    return Ok(());
                }
            }
        } else {
            // This is always the case if we reach this branch, but just in case
            // of later changes we can leave this check in place
            if let Some(ip) = &self.nameservers {
                let socket = SocketAddr::new(*ip, 53);
                let resp = match connect_and_send_request(&env, socket, &msg, &tsig_key).await {
                    Ok(resp) => resp,
                    Err(err) => {
                        return Err(format!("Unable to send update to {socket}: {err}").into());
                    }
                };

                let rcode = resp.header().rcode();
                if rcode == Rcode::SERVFAIL || rcode == Rcode::NOTIMP {
                    return Err(
                        format!("Name server {socket} was unable to handle the update. Got response: {rcode}").into()
                    );
                } else if rcode != Rcode::NOERROR {
                    writeln!(env.stdout(), "UPDATE response was {rcode}");
                }
                return Ok(());
            }
        }

        // Our list of nsnames has been exhausted, we can only report that
        // we couldn't find anything.
        writeln!(env.stdout(), "No successful responses");

        Ok(())
    }
}

//------------ UpdateAction --------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Subcommand)]
enum UpdateAction {
    /// Add RRs to a domain
    Add {
        /// RRtype
        #[arg(value_name = "RRTYPE")]
        rtype: Rtype,

        /// RDATA (One or more). Each argument corresponds to a single RR's
        /// RDATA, so beware of (shell and DNS) quoting rules.
        ///
        /// Each RDATA argument will be parsed as if it was read from a zone file.
        ///
        /// Examples:
        ///   $ dnst update some.example.com add TXT \
        ///       '"Spacious String" "Another string for the same TXT record"' \
        ///       '"This is another TXT RR"'
        #[arg(value_name = "RDATA", verbatim_doc_comment)]
        rdata: Vec<String>,
    },

    /// Delete specific RRs or a complete RRsets from a domain
    Delete {
        /// RRtype
        #[arg(value_name = "RRTYPE")]
        rtype: Rtype,

        /// RDATA (Optional. Delete whole RRset, if none provided). Each
        /// argument corresponds to a single RR's RDATA, so beware of (shell
        /// and DNS) quoting rules.
        ///
        /// Each RDATA argument will be parsed as if it was read from a zone file.
        ///
        /// For quoting example see `dnst update add --help`
        #[arg(value_name = "RDATA")]
        rdata: Vec<String>,
    },

    /// Clear domain, aka delete all RRsets on the domain
    Clear,
}

//------------ UpdatePrerequisites -------------------------------------------

#[derive(Clone, Debug)]
struct UpdatePrerequisites {
    rrset_exists: Option<Vec<NameTypeTuple>>,
    rrset_exists_exact: Option<Vec<ParsedRecord>>,
    rrset_non_existent: Option<Vec<NameTypeTuple>>,
    name_in_use: Option<Vec<Name<Vec<u8>>>>,
    name_not_in_use: Option<Vec<Name<Vec<u8>>>>,
}

//------------ LdnsUpdate ----------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LdnsUpdate {
    /// Domain name to update
    domain: Name<Vec<u8>>,

    /// IP address to associate with the given domain name.
    /// Use `none` to delete the records for the domain name.
    ip: Option<IpAddr>,

    /// Zone to update
    zone: Option<Name<Vec<u8>>>,

    /// TSIG credentials for the UPDATE packet
    tsig: Option<TSigInfo>,
}

const LDNS_HELP: &str = "\
ldns-update domain [zone] ip tsig_name tsig_alg tsig_hmac
    send a dynamic update packet to <ip>

    Use 'none' instead of ip to remove any previous address
    If 'zone'  is not specified, try to figure it out from the zone's SOA
    Example: ldns-update my.example.org 1.2.3.4

This command exists for compatibility purposes.
For a more modern version of this command try `dnst update`\
";

impl LdnsCommand for LdnsUpdate {
    const NAME: &'static str = "update";
    const HELP: &'static str = LDNS_HELP;
    const COMPATIBLE_VERSION: &'static str = "1.8.4";

    fn parse_ldns<I: IntoIterator<Item = OsString>>(args: I) -> Result<Args, Error> {
        let args: Vec<_> = args.into_iter().collect();

        // We have this signature
        // <DOMAIN> [ZONE] <IP> [TSIG_NAME TSIG_ALG TSIG_HMAC]
        // So we parse it by splitting the cases by number of arguments:
        //  1: DOMAIN IP
        //  2: DOMAIN ZONE IP
        //  4: DOMAIN IP TSIG_NAME TSIG_ALG TSIG_HMAC
        //  5: DOMAIN ZONE IP TSIG_NAME TSIG_ALG TSIG_HMAC
        let (domain, zone, ip, tsig) = match &args[..] {
            [domain, ip] => (domain, None, ip, None),
            [domain, zone, ip] => (domain, Some(zone), ip, None),
            [domain, ip, tsig_name, tsig_key, tsig_hmac] => {
                (domain, None, ip, Some((tsig_name, tsig_key, tsig_hmac)))
            }
            [domain, zone, ip, tsig_name, tsig_alg, tsig_hmac] => (
                domain,
                Some(zone),
                ip,
                Some((tsig_name, tsig_alg, tsig_hmac)),
            ),
            _ => {
                return if args.len() < 2 {
                    Err("Not enough arguments. ldns-update requires at least 2 arguments".into())
                } else if args.len() > 6 {
                    Err("Too many arguments. ldns-update requires at most 6 arguments".into())
                } else {
                    Err("Cannot take 4 arguments. ldns-update needs 2, 3, 5 or 6 arguments".into())
                }
            }
        };

        let domain = parse_os("domain name", domain)?;

        let ip = if *ip != "none" {
            Some(parse_os("IP address", ip)?)
        } else {
            None
        };

        let zone = match zone {
            Some(z) => Some(parse_os("zone", z)?),
            None => None,
        };

        Ok(Args::from(Command::LdnsUpdate(Self {
            domain,
            ip,
            zone,
            tsig: match tsig {
                Some((name, algorithm, key)) => Some(TSigInfo {
                    name: parse_os("TSIG name", name)?,
                    key: parse_os_with("TSIG key", key, base64::decode)?,
                    algorithm: parse_os("TSIG algorithm", algorithm)?,
                }),
                None => None,
            },
        })))
    }
}

impl LdnsUpdate {
    pub fn execute(self, env: impl Env) -> Result<(), Error> {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(self.run(&env))
    }

    /// Run the command as an async function
    pub async fn run(self, env: &impl Env) -> Result<(), Error> {
        writeln!(
            env.stdout(),
            ";; trying UPDATE with FQDN \"{}\" and IP \"{}\"",
            self.domain,
            self.ip.map_or("<none>".into(), |ip| ip.to_string())
        );

        let soa_zone;
        let soa_mname;
        if let Some(zone) = &self.zone {
            (soa_mname, _) = update_helpers::find_mname_and_soa(env, zone).await?;
            soa_zone = zone.clone();
        } else {
            let name = self.domain.clone();
            (soa_zone, soa_mname, _) =
                update_helpers::find_mname_and_zone_and_soa(env, &name).await?;
        };

        let nsnames = update_helpers::determine_nsnames(env, &soa_zone, &soa_mname).await?;
        let msg = self.create_update_message(&soa_zone);

        self.send_update(env, msg, nsnames).await
    }

    /// Create the packet of the update message to send to the name servers
    fn create_update_message(&self, zone: &Name<Vec<u8>>) -> Vec<u8> {
        let mut message = MessageBuilder::new_vec();

        let header = message.header_mut();
        header.set_opcode(Opcode::UPDATE);
        header.set_qr(false);

        let mut zone_section = message.question();
        zone_section
            .push(Question::new(zone, Rtype::SOA, Class::IN))
            .unwrap();

        let mut update_section = zone_section.authority();

        // If we have an IP address, remove that ip address
        // else remove A and/or AAAA as defined in RFC2136 2.5.2.
        if let Some(ip) = self.ip {
            let rdata: AllRecordData<&[u8], Name<&[u8]>> = match ip {
                IpAddr::V4(ip) => AllRecordData::A(A::new(ip)),
                IpAddr::V6(ip) => AllRecordData::Aaaa(Aaaa::new(ip)),
            };
            update_section
                .push(Record::new(
                    &self.domain,
                    Class::IN,
                    Ttl::from_secs(300),
                    rdata,
                ))
                .unwrap();
        } else {
            let tmp = Record::new(
                &self.domain,
                Class::ANY,
                Ttl::from_secs(0),
                UnknownRecordData::from_octets(Rtype::A, &[]).unwrap(),
            );
            update_section.push(tmp).unwrap();

            update_section
                .push(Record::new(
                    &self.domain,
                    Class::ANY,
                    Ttl::from_secs(0),
                    UnknownRecordData::from_octets(Rtype::AAAA, &[]).unwrap(),
                ))
                .unwrap();
        }

        update_section.finish()
    }

    /// Send the update packet to the names in nsnames in order until one responds
    async fn send_update(
        &self,
        env: impl Env,
        msg: Vec<u8>,
        nsnames: Vec<Name<Vec<u8>>>,
    ) -> Result<(), Error> {
        let msg = Message::from_octets(msg).unwrap();
        let resolver = env.stub_resolver().await;

        let tsig_key = self
            .tsig
            .as_ref()
            .map(|tsig| {
                Key::new(tsig.algorithm, &tsig.key, tsig.name.clone(), None, None)
                    .map_err(|e| format!("TSIG key is invalid: {e}"))
            })
            .transpose()?;

        for name in nsnames {
            let found_ips = resolver.lookup_host(&name).await?;
            for socket in found_ips.port_iter(53) {
                let local: SocketAddr = if socket.is_ipv4() {
                    ([0u8; 4], 0).into()
                } else {
                    ([0u16; 8], 0).into()
                };
                let dgram_connection = dgram::Connection::new(env.dgram(local, socket));

                let connection: Box<dyn SendRequest<_>> = if let Some(k) = &tsig_key {
                    Box::new(tsig::Connection::new(k.clone(), dgram_connection))
                } else {
                    Box::new(dgram_connection)
                };

                let response = connection
                    .send_request(RequestMessage::new(msg.clone()).unwrap())
                    .get_response()
                    .await;

                let resp = match response {
                    Ok(resp) => resp,
                    Err(err) => {
                        writeln!(env.stderr(), "{name} @ {socket}: {err}");
                        continue;
                    }
                };

                let rcode = resp.header().rcode();
                if rcode != Rcode::NOERROR {
                    writeln!(env.stdout(), ";; UPDATE response was {rcode}");
                }
                return Ok(());
            }
        }

        // Our list of nsnames has been exhausted, we can only report that
        // we couldn't find anything.
        writeln!(env.stdout(), ";; No responses");

        Ok(())
    }
}

//------------ update_helpers ------------------------------------------------

mod update_helpers {
    use super::*;

    /// Find the MNAME by sending a SOA query for the zone
    pub async fn find_mname_and_soa(
        env: &impl Env,
        zone: &Name<Vec<u8>>,
    ) -> Result<(Name<Vec<u8>>, Soa<Name<Vec<u8>>>), Error> {
        let resolver = env.stub_resolver().await;

        let response = resolver
            .query(Question::new(&zone, Rtype::SOA, Class::IN))
            .await?;

        let mut answer = response.answer()?.limit_to::<Soa<_>>();
        if let Some(Ok(soa)) = answer.next() {
            Ok((
                soa.data().mname().to_name(),
                soa.data().clone().flatten_into(),
            ))
        } else {
            Err(format!("No SOA record found for {zone}").into())
        }
    }

    /// Find the MNAME and zone
    ///
    /// This is achieved in 3 steps:
    ///  1. Get the MNAME with a SOA query for the domain name
    ///  2. Get the IP addresses for the MNAME
    ///  3. Send a SOA query to that IP address and use the owner as zone
    ///     and the MNAME from that response.
    pub async fn find_mname_and_zone_and_soa(
        env: &impl Env,
        name: &Name<Vec<u8>>,
    ) -> Result<(Name<Vec<u8>>, Name<Vec<u8>>, Soa<Name<Vec<u8>>>), Error> {
        let resolver = env.stub_resolver().await;

        // Step 1 - first find a name server that should know *something*
        let response = resolver
            .query(Question::new(&name, Rtype::SOA, Class::IN))
            .await?;

        // We look in both the answer and authority sections.
        // The answer section is used if the domain name is the zone apex,
        // otherwise the SOA is in the authority section.
        let mut sections = response
            .answer()?
            .limit_to_in::<Soa<_>>()
            .chain(response.authority()?.limit_to_in::<Soa<_>>());

        let Some(soa) = sections.next() else {
            return Err("no SOA found".into());
        };

        let soa_mname: Name<Vec<u8>> = soa?.data().mname().to_name();

        // Step 2 - find SOA MNAME IP address, add to resolver
        let response = resolver.lookup_host(&soa_mname).await?;

        let Some(ipaddr) = response.iter().next() else {
            return Err(format!("No A or AAAA record found for {soa_mname}").into());
        };

        // Step 3 - Redo SOA query, sending to SOA MNAME directly.
        let mut conf = ResolvConf::new();
        conf.servers = vec![ServerConf::new(
            SocketAddr::new(ipaddr, 53),
            Transport::UdpTcp,
        )];
        // Querying the SOA RR again, but from the primary directly, makes
        // sure that we have an up-to-date SOA record and not a cached
        // version. This would be relevant if we'd want to implement update
        // ordering, or want to update the SOA serial.
        let resolver = env.stub_resolver_from_conf(conf).await;

        let response = resolver
            .query(Question::new(&name, Rtype::SOA, Class::IN))
            .await?;

        // We look in both the answer and authority sections.
        // The answer section is used if the domain name is the zone apex,
        // otherwise the SOA is in the authority section.
        let mut sections = response
            .answer()?
            .limit_to_in::<Soa<_>>()
            .chain(response.authority()?.limit_to_in::<Soa<_>>());

        let Some(soa) = sections.next() else {
            return Err("no SOA found".into());
        };

        let soa = soa?;

        let zone = soa.owner().to_name();
        let mname = soa.data().mname().to_name();
        Ok((zone, mname, soa.data().clone().flatten_into()))
    }

    /// Send an NS query to find all name servers for the given zone
    ///
    /// The name server with the given MNAME is put at the start of the list.
    // async fn determine_nsnames(
    pub async fn determine_nsnames(
        env: &impl Env,
        zone: &Name<Vec<u8>>,
        mname: &Name<Vec<u8>>,
    ) -> Result<Vec<Name<Vec<u8>>>, Error> {
        let response = env
            .stub_resolver()
            .await
            .query(Question::new(&zone, Rtype::NS, Class::IN))
            .await?;

        let mut nsnames = response
            .answer()?
            .limit_to_in::<Ns<_>>()
            .map(|ns| Ok(ns?.data().nsdname().to_name::<Vec<u8>>()))
            .collect::<Result<Vec<_>, Error>>()?;

        // The MNAME should be tried first according to RFC2136 4.3
        // so we put that NSNAME first in the list.
        if let Some(mname_idx) = nsnames.iter().position(|name| name == mname) {
            nsnames.swap(0, mname_idx);
        }

        Ok(nsnames)
    }
}

//------------ test ----------------------------------------------------------

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use domain::base::iana::Class;
    use domain::base::{Name, Rtype, Ttl};
    use domain::{tsig::Algorithm, utils::base64};

    use crate::commands::update::{LdnsUpdate, UpdateAction};
    use crate::{commands::Command, env::fake::FakeCmd};

    use super::{TSigInfo, Update};

    #[track_caller]
    fn parse_ldns(cmd: FakeCmd) -> LdnsUpdate {
        let res = cmd.parse().unwrap();
        let Command::LdnsUpdate(x) = res.command else {
            panic!("Not an Update!");
        };
        x
    }

    #[track_caller]
    fn parse(cmd: FakeCmd) -> Update {
        let res = cmd.parse().unwrap();
        let Command::Update(x) = res.command else {
            panic!("Not an Update!");
        };
        x
    }

    // TODO: Add tests triggering the runtime checks
    // TODO: Add stelline tests

    #[test]
    fn dnst_parse() {
        let cmd = FakeCmd::new(["dnst", "update"]);

        cmd.parse().unwrap_err();
        cmd.args(["example.test"]).parse().unwrap_err();
        cmd.args(["--zone", "example.test"]).parse().unwrap_err();
        cmd.args(["--zone", "example.test", "ns.example.test"])
            .parse()
            .unwrap_err();
        cmd.args(["example.test", "bar.test", "none"])
            .parse()
            .unwrap_err();
        // Error when missing rtype to add (missing rdata is a runtime error)
        cmd.args(["example.test", "add"]).parse().unwrap_err();
        // Error when missing rtype
        cmd.args(["example.test", "delete"]).parse().unwrap_err();

        let base = Update {
            domain: "example.test".parse().unwrap(),
            zone: None,
            tsig: None,
            // This is not actually a default, but I need to add something here
            action: UpdateAction::Add {
                rtype: Rtype::A,
                rdata: vec![String::from("127.0.0.1")],
            },
            class: Class::IN,
            ttl: Ttl::from_secs(3600),
            nameservers: Default::default(),
            rrset_exists: None,
            rrset_exists_exact: None,
            rrset_non_existent: None,
            name_in_use: None,
            name_not_in_use: None,
        };

        let res = parse(cmd.args(["example.test", "add", "A", "127.0.0.1"]));
        assert_eq!(res, base);

        let res = parse(cmd.args(["example.test", "add", "A", "127.0.0.1", "127.0.0.2"]));
        assert_eq!(
            res,
            Update {
                action: UpdateAction::Add {
                    rtype: Rtype::A,
                    rdata: vec!["127.0.0.1".into(), "127.0.0.2".into()],
                },
                ..base.clone()
            }
        );

        let res = parse(cmd.args(["example.test", "delete", "AAAA", "::1"]));
        assert_eq!(
            res,
            Update {
                action: UpdateAction::Delete {
                    rtype: Rtype::AAAA,
                    rdata: vec!["::1".into()],
                },
                ..base.clone()
            }
        );

        let res = parse(cmd.args(["example.test", "clear"]));
        assert_eq!(
            res,
            Update {
                action: UpdateAction::Clear,
                ..base.clone()
            }
        );

        let res = parse(cmd.args([
            "example.test",
            "--tsig",
            "somekey:1234",
            "--ttl",
            "60",
            "--server",
            "127.0.0.9",
            "add",
            "TXT",
            "Hallo",
        ]));
        assert_eq!(
            res,
            Update {
                tsig: Some(TSigInfo {
                    name: "somekey".parse().unwrap(),
                    key: base64::decode("1234").unwrap(),
                    algorithm: Algorithm::Sha256,
                }),
                ttl: Ttl::from_secs(60),
                nameservers: vec![[127, 0, 0, 9].into()],
                action: UpdateAction::Add {
                    rtype: Rtype::TXT,
                    rdata: vec!["Hallo".into()]
                },
                ..base.clone()
            }
        );

        let res = parse(cmd.args(["example.test", "--zone", "test", "add", "A", "127.0.0.1"]));
        assert_eq!(
            res,
            Update {
                zone: Some(Name::from_str("test").unwrap()),
                ..base.clone()
            }
        );

        // Parsing the prerequisites arguments here doesn't make much sense as
        // they only get validated at runtime
    }

    #[test]
    fn ldns_parse() {
        let cmd = FakeCmd::new(["ldns-update"]);

        let base = LdnsUpdate {
            domain: "foo.test".parse().unwrap(),
            ip: None,
            zone: None,
            tsig: None,
        };

        cmd.args(["foo.test"]).parse().unwrap_err();

        let res = parse_ldns(cmd.args(["foo.test", "none"]));
        assert_eq!(res, base.clone());

        let res = parse_ldns(cmd.args(["foo.test", "1.1.1.1"]));
        assert_eq!(
            res,
            LdnsUpdate {
                ip: Some("1.1.1.1".parse().unwrap()),
                ..base.clone()
            }
        );

        let res = parse_ldns(cmd.args(["foo.test", "base.test", "1.1.1.1"]));
        assert_eq!(
            res,
            LdnsUpdate {
                ip: Some("1.1.1.1".parse().unwrap()),
                zone: Some("base.test".parse().unwrap()),
                ..base.clone()
            }
        );
    }

    #[test]
    fn run_with_stelline() {
        let rpl = "
            CONFIG_END

            SCENARIO_BEGIN

            RANGE_BEGIN 0 100
            
            ENTRY_BEGIN
            MATCH question
            ADJUST copy_id copy_query
            REPLY QR
            SECTION QUESTION
                foo.test IN SOA
            SECTION ANSWER
                foo.test 0 IN SOA ns.foo.test admin.foo.test 1 1 1 1 1
            SECTION AUTHORITY
                foo.test 0 IN SOA ns.foo.test admin.foo.test 1 1 1 1 1
            ENTRY_END
             
            ENTRY_BEGIN
            MATCH question
            ADJUST copy_id copy_query
            REPLY QR
            SECTION QUESTION
                zone.foo.test IN SOA
            SECTION ANSWER
                zone.foo.test 0 IN SOA ns.foo.test admin.foo.test 1 1 1 1 1
            ENTRY_END

            ENTRY_BEGIN
            MATCH question
            ADJUST copy_id copy_query
            REPLY QR
            SECTION QUESTION
                zone.foo.test IN NS
            SECTION ANSWER
                zone.foo.test IN 0 NS ns.foo.test 
            ENTRY_END

            ENTRY_BEGIN
            MATCH question
            ADJUST copy_id copy_query
            REPLY QR
            SECTION QUESTION
               foo.test IN NS
            SECTION ANSWER
                foo.test IN 0 NS ns.foo.test 
            ENTRY_END

            ENTRY_BEGIN
            MATCH question
            ADJUST copy_id copy_query
            REPLY QR
            SECTION QUESTION
                ns.foo.test IN A
            SECTION ANSWER
                ns.foo.test IN 0 A 12.34.56.78
            ENTRY_END

            ENTRY_BEGIN
            MATCH question
            ADJUST copy_id copy_query
            REPLY QR
            SECTION QUESTION
                ns.foo.test IN AAAA
            SECTION ANSWER
            ENTRY_END

            ENTRY_BEGIN 
            MATCH question opcode
            ADJUST copy_id copy_query
            OPCODE UPDATE
            REPLY QR
            SECTION QUESTION
                zone.foo.test IN SOA
            SECTION ANSWER
            ENTRY_END

            RANGE_END
            SCENARIO_END
        ";

        let cmd = FakeCmd::new(["ldns-update", "foo.test", "zone.foo.test", "none"])
            .stelline(rpl.as_bytes(), "update.rpl");

        let res = cmd.run();
        assert_eq!(res.exit_code, 0);
        assert_eq!(
            res.stdout,
            ";; trying UPDATE with FQDN \"foo.test\" and IP \"<none>\"\n"
        );
        assert_eq!(res.stderr, "");

        let cmd = FakeCmd::new(["ldns-update", "foo.test", "none"])
            .stelline(rpl.as_bytes(), "update.rpl");

        let res = cmd.run();
        assert_eq!(res.exit_code, 0);
        assert_eq!(
            res.stdout,
            ";; trying UPDATE with FQDN \"foo.test\" and IP \"<none>\"\n"
        );
        assert_eq!(res.stderr, "");
    }
}
