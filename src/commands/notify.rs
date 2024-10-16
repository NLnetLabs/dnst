use std::{net::SocketAddr, str::FromStr};

use clap::{builder::ValueParser, ArgAction};
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
    },
    rdata::{tsig::Time48, Soa},
    resolv::stub::StubResolver,
    tsig::{Algorithm, ClientTransaction, Key, KeyName},
    utils::{base16, base64},
};

use crate::error::Error;

#[derive(Clone, Debug)]
struct TSigInfo {
    name: KeyName,
    key: Vec<u8>,
    algorithm: Algorithm,
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
        if let Some((k, a)) = s.split_once(':') {
            key = k;
            algorithm = a;
        } else {
            key = rest;
            // This is different from ldns's default of
            // hmac-md5.sig-alg.reg.int but we don't support that algorithm.
            algorithm = "hmac-sha512";
        }

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
    #[arg(short = 'y', long = "tsig", value_parser = ValueParser::new(TSigInfo::from_str))]
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

    // Hidden extra argument for `-?` to trigger help, which ldns supports.
    #[arg(short = '?', action = ArgAction::Help, hide = true)]
    compatible_help: (),

    #[arg()]
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
            .map_err(|e| format!("Could not create question section: {e}"))?;

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
                .map_err(|e| format!("Could not add SOA record: {e}"))?;
        }

        let mut msg = msg.additional();

        if let Some(tsig) = &self.tsig {
            let key = Key::new(tsig.algorithm, &tsig.key, tsig.name.clone(), None, None)
                .map_err(|e| format!("TSIG key is invalid: {e}"))?;

            // ldns does not seem to validate anything coming in
            let _transaction = ClientTransaction::request(key, &mut msg, Time48::now());
        }

        let msg = msg.finish();

        if self.debug {
            println!("# Sending packet:\n");
            // todo!()
        }

        if self.debug {
            println!("Hexdump of notify packet:\n");
            println!("{}", base16::encode_display(&msg));
        }

        let resolver = StubResolver::new();

        for server in &self.servers {
            if self.debug {
                println!("# sending to {}", server);
            }

            let Ok(name) = Name::<Vec<u8>>::from_str(server) else {
                eprintln!("Invalid domain name \"{server}\", skipping.");
                continue;
            };

            let Ok(hosts) = resolver.lookup_host(&name).await else {
                eprintln!("Could not resolve host \"{name}\", skipping.");
                continue;
            };

            for socket in hosts.port_iter(self.port) {
                self.notify_host(socket, &msg, server).await?;
            }
        }

        Ok(())
    }

    async fn notify_host(&self, socket: SocketAddr, msg: &[u8], server: &str) -> Result<(), Error> {
        let mut config = dgram::Config::new();
        config.set_max_retries(self.retries as u8);
        let connection = dgram::Connection::with_config(UdpConnect::new(socket), config);

        let msg = msg.to_vec();
        let req = RequestMessage::new(Message::from_octets(msg).unwrap()).unwrap();
        let mut req = SendRequest::send_request(&connection, req);

        let resp = req.get_response().await.unwrap();

        println!("# reply from {server}:");
        println!("{resp:?}");

        Ok(())
    }
}
