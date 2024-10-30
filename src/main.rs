use clap::{command, Args, FromArgMatches};

fn main() {
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
