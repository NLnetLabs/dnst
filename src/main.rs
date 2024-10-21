fn main() {
    if let Err(err) = dnst::Args::parse_args().execute() {
        eprintln!("{}", err);
    }
}
