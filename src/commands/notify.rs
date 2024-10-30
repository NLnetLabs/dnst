use core::fmt;
use std::{net::SocketAddr, str::FromStr};

use bytes::Bytes;
use chrono::{DateTime, Local, TimeDelta};
use clap::builder::ValueParser;
use domain::{
    base::{
        iana::{Class, Opcode},
        Message, MessageBuilder, Name, Question, Record, Rtype, Serial, Ttl,
    },
    dep::octseq::Array,
    net::client::{
        dgram,
        protocol::UdpConnect,
        request::{RequestMessage, SendRequest},
        tsig,
    },
    rdata::Soa,
    resolv::stub::StubResolver,
    tsig::{Algorithm, Key, KeyName},
    utils::{base16, base64},
};

use crate::error::Error;

#[derive(Clone, Debug)]
struct TSigInfo {
    name: KeyName,
    key: Vec<u8>,
    algorithm: Algorithm,
}

// Clippy complains about the unread fields but they are used for display
#[allow(dead_code)]
struct Response<Octs> {
    msg: Message<Octs>,
    when: DateTime<Local>,
    server: Option<SocketAddr>,
    time: TimeDelta,
}

impl<Octs: AsRef<[u8]>> fmt::Display for Response<Octs> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.msg.display_dig_style())?;
        writeln!(f, ";; Query time: {} msec", self.time.num_milliseconds())?;
        if let Some(server) = self.server {
            writeln!(f, ";; Server: {}#{}", server.ip(), server.port())?;
        }
        writeln!(
            f,
            ";; WHEN: {}",
            self.when.format("%a %b %d %H:%M:%S %Z %Y")
        )?;
        writeln!(f, ";; MSG SIZE  rcvd: {}", self.msg.as_slice().len())?;
        Ok(())
    }
}

impl FromStr for TSigInfo {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // TODO: better error messages
        let Some((mut name, rest)) = s.split_once(':') else {
            return Err("invalid tsig string".into());
        };

        let mut key;
        let mut algorithm;
        if let Some((k, a)) = rest.split_once(':') {
            key = k;
            algorithm = a;
        } else {
            key = rest;
            // This is different from ldns's default of
            // hmac-md5.sig-alg.reg.int but we don't support that algorithm.
            algorithm = "hmac-sha512";
        }

        // With dig TSIG keys are also specified with -y,
        // but our format is: <name:key[:algo]>
        //      and dig's is: [hmac:]name:key
        //
        // When we detect an unknown tsig algorithm in algo,
        // but a known algorithm in name, we can assume dig
        // order was used.
        //
        // We can correct this by checking whether the name contains a valid
        // algorithm while the algorithm doesn't.
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

#[derive(Clone, Debug, clap::Args)]
pub struct Notify {
    /// The zone
    #[arg(short = 'z', required = true)]
    zone: Name<Vec<u8>>,

    /// Source address to query from
    #[arg(short = 'I', required = false)]
    source_address: (),

    /// SOA version number to include
    #[arg(short = 's')]
    soa_version: Option<u32>,

    /// A base64 tsig key and optional algorithm to include
    #[arg(
        short = 'y',
        long = "tsig",
        value_parser = ValueParser::new(TSigInfo::from_str),
        value_name = "name:key[:algo]",
    )]
    tsig: Option<TSigInfo>,

    /// Port to use to send the packet
    #[arg(short = 'p', long = "port", default_value = "53")]
    port: u16,

    /// Print debug information
    #[arg(short = 'd', long = "debug")]
    debug: bool,

    /// Max number of retries
    #[arg(short = 'r', long = "retries", default_value = "15")]
    retries: usize,

    /// DNS servers to send packet to
    #[arg(required = true)]
    servers: Vec<String>,
}

impl Notify {
    pub fn execute(&self) -> Result<(), Error> {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(self.run())
    }

    async fn run(&self) -> Result<(), Error> {
        let mut msg = MessageBuilder::new_vec();

        let header = msg.header_mut();
        header.set_opcode(Opcode::NOTIFY);
        header.set_aa(true);
        header.set_random_id();

        let mut msg = msg.question();
        let question = Question::new(&self.zone, Rtype::SOA, Class::IN);
        msg.push(question)
            .map_err(|e| format!("could not create question section: {e}"))?;

        let mut msg = msg.answer();
        if let Some(soa_version) = self.soa_version {
            let soa = Record::new(
                &self.zone,
                Class::IN,
                Ttl::from_secs(3600),
                Soa::new(
                    Name::root_vec(),
                    Name::root_vec(),
                    Serial(soa_version),
                    Ttl::ZERO,
                    Ttl::ZERO,
                    Ttl::ZERO,
                    Ttl::ZERO,
                ),
            );
            msg.push(soa)
                .map_err(|e| format!("could not add SOA record: {e}"))?;
        }

        let msg = msg.additional();

        let tsig = self
            .tsig
            .as_ref()
            .map(|tsig| {
                Key::new(tsig.algorithm, &tsig.key, tsig.name.clone(), None, None)
                    .map_err(|e| format!("TSIG key is invalid: {e}"))
            })
            .transpose()?;

        let msg = msg.into_message();

        println!("# Sending packet:");
        println!("{}", msg.display_dig_style());

        if self.debug {
            println!("Hexdump of notify packet:");
            println!("{}", base16::encode_display(&msg));
        }

        let resolver = StubResolver::new();

        for server in &self.servers {
            println!("# sending to {}", server);

            // The specified server might be an IP address. In ldns, this case is
            // handled by `getaddrinfo`, but we have to do it ourselves.
            // We parse it as an IP address and then send it to the one socket we
            // can.
            if let Ok(addr) = server.parse() {
                let socket = SocketAddr::new(addr, self.port);
                self.notify_host(socket, msg.clone(), server, &tsig).await;
                continue;
            }

            let Ok(name) = Name::<Vec<u8>>::from_str(server) else {
                eprintln!("warning: invalid domain name \"{server}\", skipping.");
                continue;
            };

            let Ok(hosts) = resolver.lookup_host(&name).await else {
                eprintln!("warning: could not resolve host \"{name}\", skipping.");
                continue;
            };

            if hosts.is_empty() {
                eprintln!("skipping bad address: {name}: Name or service not known");
                continue;
            }

            for socket in hosts.port_iter(self.port) {
                self.notify_host(socket, msg.clone(), server, &tsig).await;
            }
        }

        Ok(())
    }

    async fn notify_host(
        &self,
        socket: SocketAddr,
        msg: Message<Vec<u8>>,
        server: &str,
        tsig: &Option<Key>,
    ) {
        let resp = match &tsig {
            Some(tsig) => self.notify_host_with_tsig(socket, msg, tsig.clone()).await,
            None => self.notify_host_without_tsig(socket, msg).await,
        };

        match resp {
            Ok(resp) => {
                println!("# reply from {server} at {socket}:");
                println!("{resp}");
            }
            Err(e) => {
                eprintln!("{e}");
            }
        }
    }

    async fn notify_host_with_tsig(
        &self,
        socket: SocketAddr,
        msg: Message<Vec<u8>>,
        key: Key,
    ) -> Result<Response<Bytes>, Error> {
        let mut config = dgram::Config::new();
        config.set_max_retries(self.retries as u8);
        let connection = dgram::Connection::with_config(UdpConnect::new(socket), config);
        let connection = tsig::Connection::new(key, connection);

        let req = RequestMessage::new(msg).unwrap();
        let mut req = connection.send_request(req);

        let when = Local::now();
        let msg = req
            .get_response()
            .await
            .map_err(|e| format!("warning: reply was not received or erroneous from {socket}: {e}"))?;
        let time2 = Local::now();
        Ok(Response {
            msg,
            when,
            server: Some(socket),
            time: time2 - when,
        })
    }

    async fn notify_host_without_tsig(
        &self,
        socket: SocketAddr,
        msg: Message<Vec<u8>>,
    ) -> Result<Response<Bytes>, Error> {
        let mut config = dgram::Config::new();
        config.set_max_retries(self.retries as u8);
        let connection = dgram::Connection::with_config(UdpConnect::new(socket), config);

        let req = RequestMessage::new(msg).unwrap();
        let mut req = SendRequest::send_request(&connection, req);

        let when = Local::now();
        let msg = req.get_response().await.map_err(|e| {
            format!("warning: reply was not received or erroneous from {socket}: {e}")
        })?;
        let time2 = Local::now();
        Ok(Response {
            msg,
            when,
            server: Some(socket),
            time: time2 - when,
        })
    }
}
