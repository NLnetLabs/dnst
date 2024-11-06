use clap::Parser;

fn main() {
    // TODO: Exit with code 1 on CLI args error when run as ldns-nsec3-hash,
    // not code 2 as Clap does by default.
    if let Err(err) = dnst::Args::parse().execute() {
        eprintln!("{}", err);
    }
}
