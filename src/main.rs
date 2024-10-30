use clap::{command, Args, FromArgMatches};

fn main() {
    // Ensure that we exit with either 0 or 1, to match ldns-xxx command
    // behaviour. We can't just call Args::parse() because Clap will exit with
    // code 2 on argument parsing error, so instead call try_parse() and
    // handle it ourselves.
    let cli = dnst::Args::augment_args(command!());

    // Try with multicall first.
    let res = cli
        .clone()
        .multicall(true)
        .try_get_matches()
        .and_then(|m| dnst::commands::Command::from_arg_matches(&m))
        .or_else(|err| {
            if err.kind() == clap::error::ErrorKind::InvalidSubcommand {
                // Try without multicall.
                let matches = cli.get_matches();
                dnst::commands::Command::from_arg_matches(&matches)
            } else {
                Err(err)
            }
        });

    match res {
        Ok(cmd) => {
            if let Err(err) = cmd.execute() {
                eprintln!("{}", err);
            } else {
                std::process::exit(0);
            }
        }

        Err(err) => {
            // Ensure we benefit from Clap pretty coloured error output.
            let _ = err.print();
        }
    }

    std::process::exit(1);
}
