use std::{net::SocketAddr, str::FromStr};

use clap::builder::ValueParser;
use domain::{
    base::{
        iana::{Class, Opcode},
        MessageBuilder, Name, Question, Record, Rtype, Serial, Ttl,
    },
    dep::octseq::Array,
    rdata::{tsig::Time48, Soa},
    tsig::{Algorithm, ClientTransaction, Key, KeyName},
    utils::{base16, base64},
    resolv::stub::StubResolver,
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
    #[arg(short = 'z', required = true)]
    zone: Name<Vec<u8>>,

    #[arg(short = 'I')]
    source_address: (),

    #[arg(short = 's')]
    soa_version: Option<u32>,

    #[arg(short = 'y', long = "tsig", value_parser = ValueParser::new(TSigInfo::from_str))]
    tsig: Option<TSigInfo>,

    #[arg(short = 'p', long = "port")]
    port: u16,

    #[arg(short = 'd', long = "debug")]
    debug: bool,

    #[arg(short = 'r', long = "retries")]
    retries: usize,

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
            todo!()
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
        
            let Ok(hosts) = resolver.lookup_host(name).await else {
                eprintln!("blabla");
                continue;
            };

            for socket in hosts.port_iter(self.port) {
                self.notify_host(socket, &msg, server).await?;
            }
        }

        Ok(())
    }

    async fn notify_host(&self, socket: SocketAddr, msg: &[u8], server: &str) -> Result<(), Error> {
        todo!()
    }
}
