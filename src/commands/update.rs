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

use bytes::Bytes;
use clap::Subcommand;
use domain::base::iana::{Class, Opcode, Rcode};
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
use domain::zonefile::inplace::{Entry, ScannedRecord, Zonefile};

use crate::env::Env;
use crate::error::Error;
use crate::parse::TSigInfo;
use crate::Args;

use super::{parse_os, parse_os_with, Command, LdnsCommand};

// TODO: add .context() to errors?

// UI:
// Synopsis:
// - `dnst update [options] add <domain name> <RRTYPE> <RRs>...`
// - `dnst update [options] delete <domain name> <RRTYPE> [<RRs>...]`
// - `dnst update [options] clear <domain name>` (distinction to avoid accidental deletion of whole domain names)

// Examples:
// - `dnst update add <domain name> AAAA "::1" "::2"` - Add multiple AAAA records
// - `dnst update add <domain name> TXT "challenge"` - Add multiple TXT records
// - `dnst update delete <domain name> AAAA ::1 ::2` - Delete exact AAAA RRs on domain name (`::1` and `::2` in this case)
// - `dnst update delete <domain name> AAAA` - Delete all AAAA RRs on domain name
// - `dnst update clear <domain name>` - Delete all RRSETs on domain name, aka delete the whole domain name

// type SomeRecord = Record<NameVecU8, ZoneRecordData<Vec<u8>, NameVecU8>>;
// type SomeRecord = Record<Name<Vec<u8>>, ZoneRecordData<Vec<u8>, Name<Vec<u8>>>>;
type SomeRecord = Record<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>;
// type SomeRecord = ScannedRecord;
type NameTypeTuple = (Name<Bytes>, Rtype);

// pub type ScannedDname = Chain<RelativeName<Bytes>, Name<Bytes>>;
// pub type ScannedRecordData = ZoneRecordData<Bytes, ScannedDname>;
// pub type ScannedRecord = Record<ScannedDname, ScannedRecordData>;
// pub type ScannedString = Str<Bytes>;

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
    #[arg(short = 't', long = "ttl", value_parser = Update::parse_ttl, default_value = "3600")]
    ttl: Ttl,

    /// Nameserver to send the update to
    #[arg(short = 's', long = "server", value_name = "IP")]
    nameserver: Option<IpAddr>,

    /// Zone the domain name belongs to (to skip SOA query)
    #[arg(short = 'z', long = "zone")]
    zone: Option<Name<Vec<u8>>>,

    /// TSIG credentials for the UPDATE packet
    #[arg(short = 'y', long = "tsig", value_name = "name:key[:algo]")]
    tsig: Option<TSigInfo>,

    /// RRset exists (value independent). (Optionally) provide this option
    /// multiple times, with format "<DOMAIN_NAME> <TYPE>" each, to
    /// build up a list of RR(set)s.
    ///
    /// This specifies the prerequisite that at least one RR with a specified
    /// NAME and TYPE must exist.
    #[arg(long = "rrset-exists", visible_alias = "rrset")]
    rrset_exists: Option<Vec<String>>,

    /// RRset exists (value dependent). (Optionally) provide this option
    /// multiple times, each with one RR in zonefile format, to build up one
    /// or more RRsets that is required to exist. CLASS and TTL can be
    /// omitted.
    ///
    /// This specifies the prerequisite that a set of RRs with a specified
    /// NAME and TYPE exists and has the same members with the same RDATAs as
    /// the RRset specified.
    #[arg(long = "rrset-exists-exact", visible_alias = "rrset-exact")]
    rrset_exists_exact: Option<Vec<String>>,

    /// RRset does not exist. (Optionally) provide this option multiple times,
    /// with format "<DOMAIN_NAME> <TYPE>" each, to build up a list of RRs
    /// that specify that no RRs with a specified NAME and TYPE can exist.
    #[arg(long = "rrset-empty")]
    rrset_empty: Option<Vec<String>>,

    /// Name is in use. (Optionally) provide this option multiple times,
    /// with format "<DOMAIN_NAME>" each, to collect a list of NAMEs that must
    /// own at least one RR.
    ///
    /// Note that this prerequisite is NOT satisfied by empty nonterminals.
    #[arg(long = "name-in-use", visible_alias = "name-used")]
    name_in_use: Option<Vec<String>>,

    /// Name is not in use. (Optionally) provide this option multiple times,
    /// with format "<DOMAIN_NAME>" each, to collect a list of NAMEs that must
    /// NOT own any RRs.
    ///
    /// Note that this prerequisite IS satisfied by empty nonterminals.
    #[arg(
        long = "name-not-in-use",
        visible_alias = "name-unused",
        // value_parser = Update::parse_prerequisite,
    )]
    name_not_in_use: Option<Vec<String>>,
}

impl Update {
    pub fn execute(self, _env: impl Env) -> Result<(), Error> {
        // let runtime = tokio::runtime::Runtime::new().unwrap();
        // runtime.block_on(self.run(&env))
        let origin = Name::<Bytes>::from_str("example.com.").expect("hardcoded");
        let mut prerequisites = UpdatePrerequisites {
            rrset_exists: None,
            rrset_exists_exact: None,
            rrset_empty: None,
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
        if let Some(ref v) = self.rrset_empty {
            prerequisites.rrset_empty = Some(Self::parse_prerequisite_name_type(v, &origin)?)
        }
        if let Some(ref v) = self.name_in_use {
            prerequisites.name_in_use = Some(Self::parse_prerequisite_name(v, &origin)?)
        }
        if let Some(ref v) = self.name_not_in_use {
            prerequisites.name_not_in_use = Some(Self::parse_prerequisite_name(v, &origin)?)
        }

        dbg!(self);
        dbg!(&prerequisites);
        Ok(())
    }

    fn parse_prerequisite_name_type(
        args: &Vec<String>,
        origin: &Name<Bytes>,
    ) -> Result<Vec<(Name<Bytes>, Rtype)>, Error> {
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
            }
        }
        Ok(records)
    }

    fn parse_prerequisite_name(
        args: &Vec<String>,
        origin: &Name<Bytes>,
    ) -> Result<Vec<Name<Bytes>>, Error> {
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
        origin: &Name<Bytes>,
        class: Class,
    ) -> Result<Vec<SomeRecord>, Error> {
        let mut records = Vec::new();
        for arg in args {
            let mut zonefile = Zonefile::new();
            zonefile.extend_from_slice(arg.as_bytes());
            zonefile.extend_from_slice(b"\n");
            zonefile.set_default_class(class);
            zonefile.set_origin(origin.clone());
            if let Ok(Some(Entry::Record(mut record))) = zonefile.next_entry() {
                record.set_ttl(Ttl::from_secs(0));
                records.push(record.flatten_into());
            } else {
                return Err(
                    format!("Provided argument is not a valid resource record: {arg}").into(),
                );
            }
            // .context("TODO")?;
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
}

//------------ UpdateAction --------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Subcommand)]
enum UpdateAction {
    // Add RRs to domain
    Add {
        /// RRtype
        #[arg(value_name = "RRTYPE")]
        rtype: Rtype,
    },

    // Delete specific RRs or complete RRset from domain
    Delete {
        /// RRtype
        #[arg(value_name = "RRTYPE")]
        rtype: Rtype,
    },

    // Clear domain, aka delete all RRsets on the domain
    Clear,
}

//------------ UpdatePrerequisites -------------------------------------------

#[derive(Clone, Debug)]
struct UpdatePrerequisites {
    rrset_exists: Option<Vec<NameTypeTuple>>,
    rrset_exists_exact: Option<Vec<SomeRecord>>,
    rrset_empty: Option<Vec<NameTypeTuple>>,
    name_in_use: Option<Vec<Name<Bytes>>>,
    name_not_in_use: Option<Vec<Name<Bytes>>>,
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
            soa_mname = self.find_mname(env, zone).await?;
            soa_zone = zone.clone();
        } else {
            let name = self.domain.clone();
            (soa_zone, soa_mname) = self.find_mname_and_zone(env, &name).await?;
        };

        let nsnames = self.determine_nsnames(env, &soa_zone, &soa_mname).await?;
        let msg = self.create_update_message(&soa_zone);

        self.send_update(env, msg, nsnames).await
    }

    /// Find the MNAME by sending a SOA query for the zone
    async fn find_mname(
        &self,
        env: &impl Env,
        zone: &Name<Vec<u8>>,
    ) -> Result<Name<Vec<u8>>, Error> {
        let resolver = env.stub_resolver().await;

        let response = resolver
            .query(Question::new(&zone, Rtype::SOA, Class::IN))
            .await?;

        let mut answer = response.answer()?.limit_to::<Soa<_>>();
        if let Some(soa) = answer.next() {
            Ok(soa?.data().mname().to_name())
        } else {
            Err("no SOA record found".into())
        }
    }

    /// Find the MNAME and zone
    ///
    /// This is achieved in 3 steps:
    ///  1. Get the MNAME with a SOA query for the domain name
    ///  2. Get the A record for the MNAME
    ///  3. Send a SOA query to that IP address and use the owner as zone
    ///     and the MNAME from that response.
    async fn find_mname_and_zone(
        &self,
        env: &impl Env,
        name: &Name<Vec<u8>>,
    ) -> Result<(Name<Vec<u8>>, Name<Vec<u8>>), Error> {
        let resolver = env.stub_resolver().await;

        // Step 1 - first find a nameserver that should know *something*
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
            return Err("no A record found".into());
        };

        // Step 3 - Redo SOA query, sending to SOA MNAME directly.
        let mut conf = ResolvConf::new();
        conf.servers = vec![ServerConf::new(
            SocketAddr::new(ipaddr, 53),
            Transport::UdpTcp,
        )];
        // TODO: Add the standard servers? Is that necessary or just a quirk
        // of ldns.
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
        Ok((zone, mname))
    }

    /// Send an NS query to find all nameservers for the given zone
    ///
    /// The name server with the given MNAME is put at the start of the list.
    async fn determine_nsnames(
        &self,
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

#[cfg(test)]
mod test {
    use domain::{tsig::Algorithm, utils::base64};

    use crate::commands::update::LdnsUpdate;
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

    // #[test]
    // fn dnst_parse() {
    //     let cmd = FakeCmd::new(["dnst", "update"]);

    //     cmd.parse().unwrap_err();
    //     cmd.args(["example.test"]).parse().unwrap_err();
    //     cmd.args(["--zone", "example.test"]).parse().unwrap_err();
    //     cmd.args(["--zone", "example.test", "ns.example.test"])
    //         .parse()
    //         .unwrap_err();
    //     cmd.args(["foo.test", "bar.test", "none"])
    //         .parse()
    //         .unwrap_err();

    //     let base = Update {
    //         domain: "foo.test".parse().unwrap(),
    //         ip: None,
    //         zone: None,
    //         tsig: None,
    //     };

    //     let res = parse(cmd.args(["foo.test", "none"]));
    //     assert_eq!(res, base);

    //     let res = parse(cmd.args(["foo.test", "1.1.1.1"]));
    //     assert_eq!(
    //         res,
    //         Update {
    //             ip: Some("1.1.1.1".parse().unwrap()),
    //             ..base.clone()
    //         }
    //     );

    //     let res = parse(cmd.args(["foo.test", "1.1.1.1", "--zone", "bar.test"]));
    //     assert_eq!(
    //         res,
    //         Update {
    //             ip: Some("1.1.1.1".parse().unwrap()),
    //             zone: Some("bar.test".parse().unwrap()),
    //             ..base.clone()
    //         }
    //     );

    //     let res = parse(cmd.args(["foo.test", "none", "--tsig", "somekey:1234"]));
    //     assert_eq!(
    //         res,
    //         Update {
    //             tsig: Some(TSigInfo {
    //                 name: "somekey".parse().unwrap(),
    //                 key: base64::decode("1234").unwrap(),
    //                 algorithm: Algorithm::Sha256,
    //             }),
    //             ..base.clone()
    //         }
    //     );
    // }

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
