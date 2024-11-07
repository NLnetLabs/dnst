use std::path::Path;

use clap::Parser;
use dnst::commands::{nsec3hash::Nsec3Hash, LdnsCommand};

fn main() {
    // If none of the ldns-* tools matched, then we continue with clap
    // argument parsing.
    let args = try_ldns_compatibility().unwrap_or_else(parse_clap);

    if let Err(err) = args.execute() {
        eprintln!("{}", err);
    }
}

fn try_ldns_compatibility() -> Option<dnst::Args> {
    let binary_path = std::env::args_os().next().unwrap();

    let binary_name = Path::new(&binary_path)
        .file_name()
        .unwrap_or_default()
        .to_str()
        .unwrap_or_default();

    let res = match binary_name {
        "ldns-nsec3-hash" => Nsec3Hash::parse_ldns_args(),
        _ => return None,
    };

    match res {
        Ok(args) => Some(args),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1)
        }
    }
}

fn parse_clap() -> dnst::Args {
    let res = dnst::Args::try_parse();
    match res {
        Ok(args) => args,
        Err(e) => {
            // Clap normally has an exit code of 2, but we want an
            // exit code of 1.
            e.print().unwrap();
            std::process::exit(1);
        }
    }
}
