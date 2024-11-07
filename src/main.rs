use clap::Parser;

fn main() {
    if let Err(err) = dnst::Args::parse().execute(&mut std::io::stdout()) {
        eprintln!("{}", err);
    }
}
