use std::net::SocketAddr;
use std::str::FromStr;

use chrono::Local;
use clap::builder::ValueParser;
use domain::base::iana::{Class, Opcode};
use domain::base::{Message, MessageBuilder, Name, Question, Record, Rtype, Serial, Ttl};
use domain::net::client::request::{RequestMessage, SendRequest};
use domain::net::client::{dgram, tsig};
use domain::rdata::Soa;
use domain::tsig::{Algorithm, Key, KeyName};
use domain::utils::{base16, base64};
use lexopt::Arg;

use crate::env::Env;
use crate::error::Error;
use crate::Args;

use super::{parse_os, Command, LdnsCommand};

#[derive(Clone, Debug, PartialEq, Eq)]
struct TSigInfo {
    name: KeyName,
    key: Vec<u8>,
    algorithm: Algorithm,
}

impl FromStr for TSigInfo {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((mut name, rest)) = s.split_once(':') else {
            return Err("should contain at least one `:`".into());
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
        // When we detect an unknown TSIG algorithm in algo,
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

        let name = KeyName::from_str(name).map_err(|e| format!("TSIG name is invalid: {e}"))?;

        Ok(TSigInfo {
            name,
            key,
            algorithm,
        })
    }
}

#[derive(Clone, Debug, clap::Args, PartialEq, Eq)]
pub struct Notify {
    /// The zone
    #[arg(short = 'z', long = "zone", required = true)]
    zone: Name<Vec<u8>>,

    // The -I option is supported by ldns but is not available in domain yet.
    // It requires creating a connection from a UdpSocket (or similar).
    // /// Source address to query from
    // #[arg(short = 'I', required = false)]
    // source_address: (),
    //
    /// SOA version number to include
    #[arg(short = 's', long = "soa")]
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
    retries: u8,

    /// DNS servers to send packet to
    #[arg(required = true)]
    servers: Vec<String>,
}

const LDNS_HELP: &str = "\
usage: ldns-notify [other options] -z zone <servers>
Ldns notify utility

 Supported options:
        -z zone         The zone
        -I <address>    source address to query from
        -s version      SOA version number to include
        -y <name:key[:algo]>    specify named base64 tsig key, and optional an
                        algorithm (defaults to hmac-md5.sig-alg.reg.int)
        -p port         port to use to send to
        -v              Print version information
        -d              Print verbose debug information
        -r num          max number of retries (15)
        -h              Print this help information

Report bugs to <dns-team@nlnetlabs.nl>\
";

impl LdnsCommand for Notify {
    const NAME: &'static str = "notify";
    const HELP: &'static str = LDNS_HELP;
    const COMPATIBLE_VERSION: &'static str = "1.8.4";

    fn parse_ldns<I: IntoIterator<Item = std::ffi::OsString>>(args: I) -> Result<Args, Error> {
        let mut zone = None;
        let mut soa_version = None;
        let mut tsig = None;
        let mut port = 53;
        let mut debug = false;
        let mut retries = 15;
        let mut servers = Vec::new();

        let mut parser = lexopt::Parser::from_args(args);

        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Short('z') => {
                    let val = parser.value()?;
                    zone = Some(parse_os("zone (-z)", &val)?);
                }
                Arg::Short('I') => todo!(),
                Arg::Short('s') => {
                    let val = parser.value()?;
                    soa_version = Some(parse_os("soa version (-s)", &val)?);
                }
                Arg::Short('y') => {
                    let val = parser.value()?;
                    tsig = Some(parse_os("tsig key (-y)", &val)?);
                }
                Arg::Short('p') => {
                    let val = parser.value()?;
                    port = parse_os("port (-p)", &val)?;
                }
                Arg::Short('d') => debug = true,
                Arg::Short('r') => {
                    let val = parser.value()?;
                    retries = parse_os("retries (-r)", &val)?;
                }
                Arg::Short('h') => return Ok(Self::report_help()),
                Arg::Short('v') => return Ok(Self::report_version()),
                Arg::Short(x) => return Err(format!("Invalid short option: -{x}").into()),
                Arg::Long(x) => {
                    return Err(format!("Long options are not supported, but `--{x}` given").into())
                }
                Arg::Value(x) => {
                    servers.push(parse_os("server", &x)?);
                }
            }
        }

        let Some(zone) = zone else {
            return Err("Missing zone name argument".into());
        };

        if servers.is_empty() {
            return Err("Missing servers".into());
        }

        Ok(Args::from(Command::Notify(Notify {
            zone,
            soa_version,
            tsig,
            port,
            debug,
            retries,
            servers,
        })))
    }
}

impl Notify {
    pub fn execute(&self, env: impl Env) -> Result<(), Error> {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(self.run(env))
    }

    async fn run(&self, env: impl Env) -> Result<(), Error> {
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

        writeln!(env.stdout(), "# Sending packet:");
        writeln!(env.stdout(), "{}", msg.display_dig_style());

        if self.debug {
            writeln!(env.stdout(), "Hexdump of notify packet:");
            writeln!(env.stdout(), "{}", base16::encode_display(&msg));
        }

        let resolver = env.stub_resolver().await;

        for server in &self.servers {
            writeln!(env.stdout(), "# sending to {}", server);

            // The specified server might be an IP address. In ldns, this case is
            // handled by `getaddrinfo`, but we have to do it ourselves.
            // We parse it as an IP address and then send it to the one socket we
            // can.
            if let Ok(addr) = server.parse() {
                let socket = SocketAddr::new(addr, self.port);
                self.notify_host(&env, socket, msg.clone(), server, &tsig)
                    .await;
                continue;
            }

            let Ok(name) = Name::<Vec<u8>>::from_str(server) else {
                writeln!(
                    env.stderr(),
                    "warning: invalid domain name \"{server}\", skipping."
                );
                continue;
            };

            let Ok(hosts) = resolver.lookup_host(&name).await else {
                writeln!(
                    env.stderr(),
                    "warning: could not resolve host \"{name}\", skipping."
                );
                continue;
            };

            if hosts.is_empty() {
                writeln!(
                    env.stderr(),
                    "skipping bad address: {name}: Name or service not known"
                );
                continue;
            }

            for socket in hosts.port_iter(self.port) {
                self.notify_host(&env, socket, msg.clone(), server, &tsig)
                    .await;
            }
        }

        Ok(())
    }

    /// Send a notify packet to a single server and print the result
    async fn notify_host(
        &self,
        env: &impl Env,
        socket: SocketAddr,
        msg: Message<Vec<u8>>,
        server: &str,
        tsig_key: &Option<Key>,
    ) {
        let mut config = dgram::Config::new();
        config.set_max_retries(self.retries);

        let dgram_connection = dgram::Connection::with_config(env.dgram(socket), config);

        let connection: Box<dyn SendRequest<_>> = if let Some(k) = tsig_key {
            Box::new(tsig::Connection::new(k.clone(), dgram_connection))
        } else {
            Box::new(dgram_connection)
        };

        let req = RequestMessage::new(msg).unwrap();
        let mut req = connection.send_request(req);

        let time1 = Local::now();
        let res = req.get_response().await;
        let time2 = Local::now();

        match res {
            Ok(msg) => {
                let mut out = env.stdout();
                writeln!(out, "# reply from {server} at {socket}:");
                writeln!(out, "{}", msg.display_dig_style());
                writeln!(
                    out,
                    ";; Query time: {} msec",
                    (time2 - time1).num_milliseconds()
                );
                writeln!(out, ";; Server: {}#{}", socket.ip(), socket.port());
                writeln!(out, ";; WHEN: {}", time1.format("%a %b %d %H:%M:%S %Z %Y"));
                writeln!(out, ";; MSG SIZE  rcvd: {}", msg.as_slice().len());
            }
            Err(e) => {
                writeln!(
                    env.stdout(),
                    "warning: reply was not received or erroneous from: {socket}: {e}"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    use domain::base::Name;
    use domain::tsig::Algorithm;
    use domain::utils::base64;

    use crate::commands::notify::TSigInfo;
    use crate::commands::Command;
    use crate::env::fake::FakeCmd;

    use super::Notify;

    #[track_caller]
    fn parse(cmd: FakeCmd) -> Notify {
        let res = cmd.parse().unwrap();
        let Command::Notify(x) = res.command else {
            panic!("not a notify!");
        };
        x
    }

    #[test]
    fn dnst_parse() {
        let cmd = FakeCmd::new(["dnst", "notify"]);

        cmd.parse().unwrap_err();
        cmd.args(["--zone", "example.test"]).parse().unwrap_err();
        cmd.args(["--zone=example.test"]).parse().unwrap_err();
        cmd.args(["-z", "example.test"]).parse().unwrap_err();
        cmd.args(["-zexample.test"]).parse().unwrap_err();

        let base = Notify {
            zone: Name::from_str("example.test").unwrap(),
            soa_version: None,
            tsig: None,
            port: 53,
            debug: false,
            retries: 15,
            servers: vec!["some.example.test".into()],
        };

        // Create a command with some arguments that we reuse for some tests
        let cmd2 = cmd.args(["-z", "example.test", "some.example.test"]);

        let res = parse(cmd2.clone());
        assert_eq!(res, base);

        for arg in ["-p", "--port"] {
            let res = parse(cmd2.args([arg, "10"]));
            assert_eq!(
                res,
                Notify {
                    port: 10,
                    ..base.clone()
                }
            );
        }

        let res = parse(cmd2.args(["-s", "10"]));
        assert_eq!(
            res,
            Notify {
                soa_version: Some(10),
                ..base.clone()
            }
        );

        for arg in ["-y", "--tsig"] {
            let res = parse(cmd2.args([arg, "somekey:1234"]));
            assert_eq!(
                res,
                Notify {
                    tsig: Some(TSigInfo {
                        name: "somekey".parse().unwrap(),
                        key: base64::decode("1234").unwrap(),
                        algorithm: Algorithm::Sha512,
                    }),
                    ..base.clone()
                }
            );
        }
    }

    #[test]
    fn ldns_parse() {
        let cmd = FakeCmd::new(["ldns-notify"]);

        cmd.parse().unwrap_err();

        // Shouldn't work at all
        cmd.args(["--zone", "example.test"]).parse().unwrap_err();
        cmd.args(["--zone=example.test"]).parse().unwrap_err();

        // Missing servers
        cmd.args(["-z", "example.test"]).parse().unwrap_err();
        cmd.args(["-zexample.test"]).parse().unwrap_err();

        // Create a command with some arguments that we reuse for some tests
        let cmd2 = cmd.args(["-z", "example.test", "some.example.test"]);

        // Invalid numbers
        cmd2.args(["-p", "blabla"]).parse().unwrap_err();
        cmd2.args(["-r", "blabla"]).parse().unwrap_err();

        let base = Notify {
            zone: Name::from_str("example.test").unwrap(),
            soa_version: None,
            tsig: None,
            port: 53,
            debug: false,
            retries: 15,
            servers: vec!["some.example.test".into()],
        };

        let res = parse(cmd2.clone());
        assert_eq!(res, base);

        let res = parse(cmd2.args(["-p", "10"]));
        assert_eq!(
            res,
            Notify {
                port: 10,
                ..base.clone()
            }
        );

        let res = parse(cmd2.args(["-s", "10"]));
        assert_eq!(
            res,
            Notify {
                soa_version: Some(10),
                ..base.clone()
            }
        );

        let res = parse(cmd2.args(["-y", "somekey:1234"]));
        assert_eq!(
            res,
            Notify {
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
    fn version() {
        let res = FakeCmd::new(["ldns-notify", "-v"]).run();
        assert_eq!(res.exit_code, 0);
        assert!(res.stdout.contains("ldns-notify provided by dnst v"));
        assert!(res.stdout.contains("(compatible with ldns v1.8.4)"));
    }

    fn entries_for_name(name: &str, v4: &[Ipv4Addr], v6: &[Ipv6Addr]) -> String {
        let v4 = v4
            .iter()
            .map(|a| format!("{name} IN 10 A {a}"))
            .collect::<Vec<_>>()
            .join("\n");

        let v6 = v6
            .iter()
            .map(|a| format!("{name} IN 10 AAAA {a}"))
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            "
            ENTRY_BEGIN
            MATCH question
            ADJUST copy_id copy_query
            REPLY QR RD RA NOERROR
            SECTION QUESTION
                {name} IN A
            SECTION ANSWER
                {v4}
            ENTRY_END
            
            ENTRY_BEGIN
            MATCH question
            ADJUST copy_id copy_query
            REPLY QR RD RA NOERROR
            SECTION QUESTION
                {name} IN AAAA
            SECTION ANSWER
                {v6}
            ENTRY_END
        "
        )
    }

    #[test]
    fn with_zone_and_ip() {
        let rpl = "
            CONFIG_END

            SCENARIO_BEGIN

            RANGE_BEGIN 0 100
            
            ENTRY_BEGIN
            ADJUST copy_id
            REPLY QR
            SECTION QUESTION
                nlnetlabs.test SOA
            SECTION ANSWER
                success.test 10 A 2.2.2.2
            ENTRY_END

            RANGE_END

            SCENARIO_END
        ";

        let cmd = FakeCmd::new(["dnst", "notify", "-z", "nlnetlabs.test", "1.1.1.1"])
            .stelline(rpl.as_bytes(), "notify.rpl");

        let res = cmd.run();
        assert_eq!(res.exit_code, 0);
        assert!(res.stdout.contains("success.test"));
        assert_eq!(res.stderr, "");
    }

    #[test]
    fn with_zone_and_domain_name() {
        let foo = entries_for_name("foo.test", &[Ipv4Addr::new(1, 2, 3, 4)], &[]);
        let bar = entries_for_name("bar.test", &[], &[]);

        let rpl = format!(
            "
            CONFIG_END

            SCENARIO_BEGIN

            RANGE_BEGIN 0 100
            
            {foo}

            {bar}
            
            ENTRY_BEGIN
            MATCH question
            ADJUST copy_id
            REPLY QR
            SECTION QUESTION
                nlnetlabs.test SOA
            SECTION ANSWER
                success.test IN 10 A 2.2.2.2
            ENTRY_END

            RANGE_END

            SCENARIO_END
        "
        );

        let cmd = FakeCmd::new(["dnst", "notify", "-z", "nlnetlabs.test", "foo.test"])
            .stelline(rpl.as_bytes(), "notify.rpl");

        let res = cmd.run();
        assert!(res.stdout.contains("success.test"));
        assert_eq!(res.stderr, "");

        let cmd = FakeCmd::new(["dnst", "notify", "-z", "nlnetlabs.test", "bar.test"])
            .stelline(rpl.as_bytes(), "notify.rpl");

        let res = cmd.run();
        assert_eq!(res.exit_code, 0);
        assert!(res.stderr.contains("Name or service not known"));
    }
}
