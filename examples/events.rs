use barectf_parser::{Config, Error, Parser};
use clap::Parser as ClapParser;
use std::{fs, io, path::PathBuf};
use tracing::error;

/// barectf events reader example
#[derive(Debug, clap::Parser)]
struct Opts {
    /// The barectf effective-configuration yaml file
    pub config: PathBuf,

    /// The binary CTF stream(s) file
    pub stream: PathBuf,
}

fn main() {
    tracing_subscriber::fmt::init();

    let opts = Opts::parse();

    let cfg_str = fs::read_to_string(&opts.config).unwrap();

    let cfg: Config = serde_yaml::from_str(&cfg_str).unwrap();

    let mut stream = fs::File::open(&opts.stream).unwrap();

    let parser = Parser::new(&cfg).unwrap();

    loop {
        let pkt = match parser.parse(&mut stream) {
            Ok(p) => p,
            Err(Error::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                break;
            }
            Err(e) => {
                error!("{e}");
                break;
            }
        };

        println!("{pkt:#?}");
    }
}
