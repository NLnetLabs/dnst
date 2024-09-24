use crate::error::Error;
use clap::builder::ValueParser;
use domain::base::name::Name;
use domain::base::ToName;
use std::str::FromStr;

pub(crate) const UPDATE_USAGE: &str = "\
update <DOMAIN_NAME> [<ZONE>] <IP> [<TSIG_NAME> <TSIG_ALG> <TSIG_KEY>]

Arguments:
  <DOMAIN_NAME>  The domain name to update the IP address of
  <ZONE>         The zone to send the update to (if omitted, derived from SOA record)
  <IP>           The IP to update the domain with (\"none\" to remove any existing IPs)
  <TSIG_NAME>    TSIG Key name
  <TSIG_ALG>     TSIG algorithm (e.g. \"hmac-sha256\")
  <TSIG_KEY>     TSIG Key data
";

// The ldns-update command has an optional positional before a required one. This makes
// transitioning to clap impossible. Therefore the positional parsing is done by us, and clap is
// just used to collect all arguments.

#[derive(Clone, Debug, clap::Args)]
pub struct Update {
    /// Args containing <DOMAIN> [<ZONE>] <IP> [<TSIG_NAME> <TSIG_ALG> <TSIG_KEY>]
    args: Vec<String>,
}

#[derive(Clone, Debug)]
enum IpUpdateAction {
    Delete,
    Update(Vec<u8>),
}

#[derive(Clone, Debug)]
struct TsigData {
    /// TSIG Key name
    tsig_name: Name<Vec<u8>>,

    // TODO: md5 unsupported?
    /// TSIG algorithm (e.g. "hmac-sha256")
    tsig_alg: Name<Vec<u8>>,

    /// TSIG Key data
    tsig_key: Vec<u8>,
}

#[derive(Clone, Debug)]
struct UpdateArgs {
    /// The domain name to update the IP of
    domain: Name<Vec<u8>>,

    /// The zone to send the update to (if omitted, derived from SOA record)
    zone: Option<Name<Vec<u8>>>,

    /// The IP to update the domain with (if omitted or set to "none", remove all existing IPs)
    ip: IpUpdateAction,

    tsig_data: Option<TsigData>,
}

impl Update {
    fn parse_name(arg: &str) -> Result<Name<Vec<u8>>, Error> {
        Name::from_str(&arg.to_lowercase()).map_err(|e| Error::from(e.to_string()))
    }

    fn parse_tsig_alg(arg: &str) -> Result<Name<Vec<u8>>, Error> {
        let alg = arg.to_lowercase();
        let alg = match alg.as_str() {
            "hmac-md5" => "hmac-md5.sig-alg.reg.int.",
            _ => &alg
        };
        Name::from_str(alg).map_err(|e| Error::from(e.to_string()))
    }

    fn parse_ip_action(ip: &str) -> IpUpdateAction {
        if ip == "none" {
            IpUpdateAction::Delete
        } else {
            IpUpdateAction::Update(ip.as_bytes().to_vec())
        }
    }

    fn parse_positionals(args: &Vec<String>) -> Result<UpdateArgs, Error> {
        // <DOMAIN> [<ZONE>] <IP> [<TSIG_NAME> <TSIG_ALG> <TSIG_KEY>]
        match args.len() {
            2 /* domain + ip */ => {
                Ok(UpdateArgs {
                    domain: Self::parse_name(&args[0])?,
                    zone: None,
                    ip: Self::parse_ip_action(&args[1]),
                    tsig_data: None
                })
            },
            3 /* domain + zone + ip */ => {
                Ok(UpdateArgs {
                    domain: Self::parse_name(&args[0])?,
                    zone: Some(Self::parse_name(&args[1])?),
                    ip: Self::parse_ip_action(&args[2]),
                    tsig_data: None
                })
            },
            5 /* domain + ip + tsig{name,alg,key} */ => {
                Ok(UpdateArgs {
                    domain: Self::parse_name(&args[0])?,
                    zone: None,
                    ip: Self::parse_ip_action(&args[1]),
                    tsig_data: Some(TsigData {
                        tsig_name: Self::parse_name(&args[2])?,
                        tsig_alg: Self::parse_tsig_alg(&args[3])?,
                        tsig_key: args[4].as_bytes().to_vec(),
                    })
                })
            },
            6 /* domain + zone + ip + tsig{name,alg,key} */ => {
                Ok(UpdateArgs {
                    domain: Self::parse_name(&args[0])?,
                    zone: Some(Self::parse_name(&args[1])?),
                    ip: Self::parse_ip_action(&args[2]),
                    tsig_data: Some(TsigData {
                        tsig_name: Self::parse_name(&args[3])?,
                        tsig_alg: Self::parse_tsig_alg(&args[4])?,
                        tsig_key: args[5].as_bytes().to_vec(),
                    })
                })
            },
            _ => {
                Self::print_usage();
                Err("incorrect number of arguments provided".into())
            },
        }
    }
}

impl Update {
    fn print_usage() {
        eprintln!("Usage: {}", UPDATE_USAGE);
    }

    pub fn execute(self) -> Result<(), Error> {
        let update_args = Self::parse_positionals(&self.args)?;
        eprintln!("{:?}", update_args);
        Ok(())
    }
}
