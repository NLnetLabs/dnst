use clap::Parser;

fn main() {
    // Ensure that we exit with either 0 or 1, to match ldns-xxx command
    // behaviour. We can't just call Args::parse() because Clap will exit with
    // code 2 on argument parsing error, so instead call try_parse() and
    // handle it ourselves.
    match dnst::Args::try_parse() {
        Ok(args) => {
            if let Err(err) = args.execute() {
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
