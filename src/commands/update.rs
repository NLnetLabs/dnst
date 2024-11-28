use std::ffi::OsString;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::str::FromStr;

use domain::base::iana::{Class, Opcode, Rcode};
use domain::base::{
    Message, MessageBuilder, Name, Question, Record, Rtype, ToName, Ttl, UnknownRecordData,
};
use domain::net::client::request::{RequestMessage, SendRequest};
use domain::net::client::{dgram, tsig};
use domain::rdata::{Aaaa, AllRecordData, Ns, Soa, A};
use domain::resolv::stub::conf::{ResolvConf, ServerConf, Transport};
use domain::tsig::{Algorithm, Key, KeyName};
use domain::utils::base64;

use crate::env::Env;
use crate::error::Error;
use crate::Args;

use super::{parse_os, parse_os_with, Command, LdnsCommand};

// Clap gives `Option<T>` special handling by making the argument optional.
// This is not what we want because we require an explicit "none" value. So,
// we create an alias, so that clap doesn't recognize that we are using an
// option and pray that Ed Page doesn't make clap smart enough to figure
// this out.
type OptionIpAddr = Option<IpAddr>;

#[derive(Clone, Debug, clap::Args, PartialEq, Eq)]
pub struct Update {
    /// Domain name to update
    #[arg(value_name = "DOMAIN NAME")]
    domain: Name<Vec<u8>>,

    /// IP address to associate with the given domain name.
    /// Use `none` to delete the records for the domain name.
    #[arg(value_name = "IP", value_parser = optional_ip)]
    ip: OptionIpAddr,

    /// Zone to update
    #[arg(long = "zone")]
    zone: Option<Name<Vec<u8>>>,

    /// TSIG credentials for the UPDATE packet
    #[arg(long = "tsig", value_name = "name:key[:algo]")]
    tsig: Option<TSigInfo>,
}

fn optional_ip(s: &str) -> Result<Option<IpAddr>, Error> {
    if s == "none" {
        Ok(None)
    } else {
        let ip = s.parse().map_err(|_| format!("Invalid IP address: {s}"))?;
        Ok(Some(ip))
    }
}

impl FromStr for TSigInfo {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // TODO: better error messages
        let Some((mut name, rest)) = s.split_once(':') else {
            return Err("invalid TSIG string".into());
        };

        let mut key;
        let mut algorithm;
        if let Some((k, a)) = rest.split_once(':') {
            key = k;
            algorithm = a;
        } else {
            key = rest;
            algorithm = "hmac-sha512";
        };

        // With dig TSIG keys are also specified with -y,
        // but out format is: -y <name:key[:algo]>
        //      and dig's is: -y [hmac:]name:key
        //
        // When we detect an unknown tsig algorithm in algo,
        // but a known algorithm in name, we cane assume dig
        // order was used.
        //
        // We can correct this by checking whether the name contains a valid
        // algorithm while the name doesn't.
        if Algorithm::from_str(algorithm).is_err() && Algorithm::from_str(name).is_ok() {
            (name, key, algorithm) = (key, algorithm, name);
        }

        let algorithm = Algorithm::from_str(algorithm)
            .map_err(|_| format!("Unsupported TSIG algorithm: {algorithm}"))?;

        let key = base64::decode(key).map_err(|e| format!("TSIG key is invalid base64: {e}"))?;

        let name = KeyName::from_str(name).map_err(|e| format!("TSIG name is invalid: {e}"))?;

        Ok(TSigInfo {
            name,
            key,
            algorithm,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TSigInfo {
    name: KeyName,
    key: Vec<u8>,
    algorithm: Algorithm,
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

impl LdnsCommand for Update {
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
            Some(z) => Some(parse_os("zone (-z)", z)?),
            None => None,
        };

        Ok(Args::from(Command::Update(Self {
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

impl Update {
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
    ///  1. Get the MNAME with an SOA query for the domain name
    ///  2. Get the A record for the MNAME
    ///  3. Send an SOA query to that IP address and use use the owner as zone
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
        let response = resolver
            .query(Question::new(&soa_mname, Rtype::A, Class::IN))
            .await?;

        let Some(a) = response.answer()?.limit_to::<A>().next() else {
            return Err("no A record found".into());
        };
        let ipaddr = a?.data().addr();

        // Step 3 - Redo SOA query, sending to SOA MNAME directly.
        let mut conf = ResolvConf::new();
        conf.servers = vec![ServerConf::new(
            SocketAddr::V4(SocketAddrV4::new(ipaddr, 53)),
            Transport::UdpTcp,
        )];
        // TODO: Add the standard servers? Is that necessary or just a quirk
        // of ldns.
        let resolver = env.stub_resolver_from_conf(conf).await;

        let response = resolver
            .query(Question::new(&name, Rtype::SOA, Class::IN))
            .await?;

        let mut authority = response.authority()?.limit_to::<Soa<_>>();
        let Some(soa) = authority.next() else {
            return Err("no SOA record found hello".into());
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

        // The mname should be tried first according to RFC2136 4.3
        // so we put that nsname first in the list.
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
            update_section
                .push(Record::new(
                    &self.domain,
                    Class::ANY,
                    Ttl::from_secs(0),
                    UnknownRecordData::from_octets(Rtype::A, &[]).unwrap(),
                ))
                .unwrap();

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
                let dgram_connection = dgram::Connection::new(env.dgram(socket));

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

    use crate::{commands::Command, env::fake::FakeCmd};

    use super::{TSigInfo, Update};

    #[track_caller]
    fn parse(cmd: FakeCmd) -> Update {
        let res = cmd.parse().unwrap();
        let Command::Update(x) = res.command else {
            panic!("Not a Key2ds!");
        };
        x
    }

    #[test]
    fn dnst_parse() {
        let cmd = FakeCmd::new(["dnst", "update"]);

        cmd.parse().unwrap_err();
        cmd.args(["example.test"]).parse().unwrap_err();
        cmd.args(["--zone", "example.test"]).parse().unwrap_err();
        cmd.args(["--zone", "example.test", "ns.example.test"])
            .parse()
            .unwrap_err();
        cmd.args(["foo.test", "bar.test", "none"])
            .parse()
            .unwrap_err();

        let base = Update {
            domain: "foo.test".parse().unwrap(),
            ip: None,
            zone: None,
            tsig: None,
        };

        let res = parse(cmd.args(["foo.test", "none"]));
        assert_eq!(res, base);

        let res = parse(cmd.args(["foo.test", "1.1.1.1"]));
        assert_eq!(
            res,
            Update {
                ip: Some("1.1.1.1".parse().unwrap()),
                ..base.clone()
            }
        );

        let res = parse(cmd.args(["foo.test", "1.1.1.1", "--zone", "bar.test"]));
        assert_eq!(
            res,
            Update {
                ip: Some("1.1.1.1".parse().unwrap()),
                zone: Some("bar.test".parse().unwrap()),
                ..base.clone()
            }
        );

        let res = parse(cmd.args(["foo.test", "none", "--tsig", "somekey:1234"]));
        assert_eq!(
            res,
            Update {
                tsig: Some(TSigInfo {
                    name: "somekey".parse().unwrap(),
                    key: base64::decode("1234").unwrap(),
                    algorithm: Algorithm::Sha512,
                }),
                ..base.clone()
            }
        );
    }

    #[test]
    fn ldns_parse() {
        let cmd = FakeCmd::new(["ldns-update"]);

        let base = Update {
            domain: "foo.test".parse().unwrap(),
            ip: None,
            zone: None,
            tsig: None,
        };

        cmd.args(["foo.test"]).parse().unwrap_err();

        let res = parse(cmd.args(["foo.test", "none"]));
        assert_eq!(res, base.clone());

        let res = parse(cmd.args(["foo.test", "1.1.1.1"]));
        assert_eq!(
            res,
            Update {
                ip: Some("1.1.1.1".parse().unwrap()),
                ..base.clone()
            }
        );

        let res = parse(cmd.args(["foo.test", "base.test", "1.1.1.1"]));
        assert_eq!(
            res,
            Update {
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

        let cmd = FakeCmd::new([
            "dnst",
            "update",
            "foo.test",
            "none",
            "--zone",
            "zone.foo.test",
        ])
        .stelline(rpl.as_bytes(), "update.rpl");

        let res = cmd.run();
        assert_eq!(res.exit_code, 0);
        assert_eq!(
            res.stdout,
            ";; trying UPDATE with FQDN \"foo.test\" and IP \"<none>\"\n"
        );
        assert_eq!(res.stderr, "");

        let cmd = FakeCmd::new(["dnst", "update", "foo.test", "none"])
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
