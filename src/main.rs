use clap::Parser;

fn main() {
    if let Err(err) = dnst::Args::parse().execute() {
        eprintln!("Error: {}", err);
    }
}
