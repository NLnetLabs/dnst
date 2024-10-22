use std::{
    net::{IpAddr, SocketAddr, SocketAddrV4},
    str::FromStr,
};

use bytes::Bytes;
use domain::{
    base::{
        iana::{Class, Opcode, Rcode},
        Message, MessageBuilder, Name, Question, Record, Rtype, ToName, Ttl, UnknownRecordData,
    },
    net::client::{
        dgram_stream,
        protocol::{TcpConnect, UdpConnect},
        request::{self, RequestMessage, RequestMessageMulti, SendRequest, SendRequestMulti},
        stream, tsig,
    },
    rdata::{Aaaa, AllRecordData, Ns, Soa, A},
    resolv::{
        stub::conf::{ResolvConf, ServerConf, Transport},
        StubResolver,
    },
    tsig::{Algorithm, Key, KeyName},
    utils::base64,
};
use octseq::Array;
use tokio::net::TcpStream;

use crate::error::Error;

#[derive(Clone, Debug, clap::Args)]
pub struct Update {
    /// Domain name to update
    #[arg()]
    domain: Name<Vec<u8>>,
    /// IP address to associate with the given domain name.
    /// Use `none` to delete the records for the domain name.
    #[arg(required = true, value_parser = optional_ip)]
    ip: Option<IpAddr>,
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

        let Some((mut key, mut algorithm)) = rest.split_once(':') else {
            return Err("invalid TSIG string".into());
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

        let name =
            Name::<Array<255>>::from_str(name).map_err(|e| format!("TSIG name is invalid: {e}"))?;

        Ok(TSigInfo {
            name,
            key,
            algorithm,
        })
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct TSigInfo {
    name: KeyName,
    key: Vec<u8>,
    algorithm: Algorithm,
}

static LDNS_HELP: &str = "\
ldns-update domain [zone] ip tsig_name tsig_alg tsig_hmac
    send a dynamic update packet to <ip>

    Use 'none' instead of ip to remove any previous address
    If 'zone'  is not specified, try to figure it out from the zone's SOA
    Example: ldns-update my.example.org 1.2.3.4

This command exists for compatibility purposes.
For a more modern version of this command try `dnst update`\
";

impl Update {
    pub fn parse_ldns_args(args: &[String]) -> Result<Self, Error> {
        if args.iter().any(|s| s == "-h" || s == "--help") {
            return Err(LDNS_HELP.into());
        }

        // We have this signature
        // <DOMAIN> [ZONE] <IP> [TSIG_NAME TSIG_ALG TSIG_HMAC]
        // So we parse it by splitting the cases by number of arguments:
        //  1: DOMAIN IP
        //  2: DOMAIN ZONE IP
        //  4: DOMAIN IP TSIG_NAME TSIG_ALG TSIG_HMAC
        //  5: DOMAIN ZONE IP TSIG_NAME TSIG_ALG TSIG_HMAC
        let (domain, zone, ip, tsig) = match args {
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
                    Err(format!("Not enough arguments. ldns-update requires at least 2 arguments\n\n{LDNS_HELP}").into())
                } else if args.len() > 6 {
                    Err(format!("Too many arguments. ldns-update requires at most 6 arguments\n\n{LDNS_HELP}.").into())
                } else {
                    Err(
                        format!("Cannot take 4 arguments. ldns-update needs 2, 3, 5 or 6 arguments\n\n{LDNS_HELP}")
                            .into(),
                    )
                }
            }
        };

        let domain = Name::from_str(domain)
            .map_err(|_| format!("Invalid domain name: {domain}\n\n{LDNS_HELP}"))?;

        let ip = if *ip != "none" {
            Some(
                ip.parse()
                    .map_err(|_| format!("Invalid IP address: {ip}\n\n{LDNS_HELP}"))?,
            )
        } else {
            None
        };

        let zone = match zone {
            Some(z) => {
                Some(Name::from_str(z).map_err(|_| format!("Invalid zone: {z}\n\n{LDNS_HELP}"))?)
            }
            None => None,
        };

        Ok(Self {
            domain,
            ip,
            zone,
            tsig: match tsig {
                Some((name, algorithm, key)) => Some(TSigInfo {
                    name: Name::<Array<255>>::from_str(name)
                        .map_err(|e| format!("TSIG name is invalid: {e}\n\n{LDNS_HELP}"))?,
                    key: base64::decode(key)
                        .map_err(|e| format!("TSIG key is invalid base64: {e}\n\n{LDNS_HELP}"))?,
                    algorithm: Algorithm::from_str(algorithm).map_err(|_| {
                        format!("Unsupported TSIG algorithm: {algorithm}\n\n{LDNS_HELP}")
                    })?,
                }),
                None => None,
            },
        })
    }

    pub fn execute(self) -> Result<(), Error> {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(self.run())
    }

    /// Run the command as an async function
    pub async fn run(self) -> Result<(), Error> {
        println!(
            ";; trying UPDATE with FQDN \"{}\" and IP \"{}\"",
            self.domain,
            self.ip.map_or("<none>".into(), |ip| ip.to_string())
        );

        let soa_zone;
        let soa_mname;
        if let Some(zone) = &self.zone {
            soa_mname = self.find_mname(zone).await?;
            soa_zone = zone.clone();
        } else {
            let name = self.domain.clone();
            (soa_zone, soa_mname) = self.find_mname_and_zone(&name).await?;
        };

        let nsnames = self.determine_nsnames(&soa_zone, &soa_mname).await?;
        let msg = self.create_update_message(&soa_zone);

        self.send_update(msg, nsnames).await
    }

    /// Find the MNAME by sending a SOA query for the zone
    async fn find_mname(&self, zone: &Name<Vec<u8>>) -> Result<Name<Vec<u8>>, Error> {
        let resolver = StubResolver::new();

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
        name: &Name<Vec<u8>>,
    ) -> Result<(Name<Vec<u8>>, Name<Vec<u8>>), Error> {
        let resolver = StubResolver::new();

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
        let resolver = StubResolver::from_conf(conf);

        let response = resolver
            .query(Question::new(&name, Rtype::SOA, Class::IN))
            .await?;

        let mut authority = response.authority()?.limit_to::<Soa<_>>();
        let Some(soa) = authority.next() else {
            return Err("no SOA record found".into());
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
        zone: &Name<Vec<u8>>,
        mname: &Name<Vec<u8>>,
    ) -> Result<Vec<Name<Vec<u8>>>, Error> {
        let resolver = StubResolver::new();
        let response = resolver
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
    async fn send_update(&self, msg: Vec<u8>, nsnames: Vec<Name<Vec<u8>>>) -> Result<(), Error> {
        let msg = Message::from_octets(msg).unwrap();
        let resolver = StubResolver::new();
        for name in nsnames {
            let found_ips = resolver.lookup_host(&name).await?;
            for socket in found_ips.port_iter(53) {
                let response = match &self.tsig {
                    Some(tsig) => {
                        let key =
                            Key::new(tsig.algorithm, &tsig.key, tsig.name.clone(), None, None)
                                .unwrap();
                        let msg = RequestMessageMulti::new(msg.clone()).unwrap();
                        self.send_update_with_tsig(msg, key, socket).await
                    }
                    None => {
                        let msg = RequestMessage::new(msg.clone()).unwrap();
                        self.send_update_without_tsig(msg, socket).await
                    }
                };

                let resp = match response {
                    Ok(resp) => resp,
                    Err(err) => {
                        eprintln!("{name} @ {socket}: {err}");
                        continue;
                    }
                };
                let rcode = resp.header().rcode();
                if rcode != Rcode::NOERROR {
                    println!(";; UPDATE response was {rcode}");
                }
                return Ok(());
            }
        }

        // Our list of nsnames has been exhausted, we can only report that
        // we couldn't find anything.
        println!(";; No responses");

        Ok(())
    }

    async fn send_update_with_tsig(
        &self,
        msg: RequestMessageMulti<Vec<u8>>,
        key: Key,
        socket: SocketAddr,
    ) -> Result<Message<Bytes>, domain::net::client::request::Error> {
        let tcp_conn = TcpStream::connect(socket).await.unwrap();
        let (connection, transport) =
            stream::Connection::<RequestMessage<Vec<u8>>, _>::new(tcp_conn);
        let connection = tsig::Connection::new(key, connection);

        tokio::spawn(async move {
            transport.run().await;
        });

        let mut req = connection.send_request(msg);
        Ok(req.get_response().await?.unwrap())
    }

    async fn send_update_without_tsig(
        &self,
        msg: request::RequestMessage<Vec<u8>>,
        socket: SocketAddr,
    ) -> Result<Message<Bytes>, domain::net::client::request::Error> {
        let udp_connect = UdpConnect::new(socket);
        let tcp_connect = TcpConnect::new(socket);
        let (connection, transport) = dgram_stream::Connection::new(udp_connect, tcp_connect);
        tokio::spawn(async move {
            transport.run().await;
        });

        let mut req = connection.send_request(msg.clone());
        req.get_response().await
    }
}
