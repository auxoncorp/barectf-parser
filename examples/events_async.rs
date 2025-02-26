use barectf_parser::{Config, Error, Parser};
use clap::Parser as ClapParser;
use std::{fs, path::PathBuf};
use tokio::fs::File;
use tokio_stream::StreamExt;
use tokio_util::codec::FramedRead;
use tracing::error;

/// barectf events async reader example
#[derive(Debug, clap::Parser)]
struct Opts {
    /// The barectf effective-configuration yaml file
    pub config: PathBuf,

    /// The binary CTF stream(s) file
    pub stream: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();

    let opts = Opts::parse();

    let cfg_str = fs::read_to_string(&opts.config).unwrap();

    let cfg: Config = serde_yaml::from_str(&cfg_str).unwrap();

    let stream = File::open(&opts.stream).await.unwrap();

    let parser = Parser::new(&cfg).unwrap();

    let decoder = parser.into_packet_decoder();

    let mut reader = FramedRead::new(stream, decoder);

    while let Some(value) = reader.next().await {
        let pkt = match value {
            Ok(p) => p,
            Err(e) => {
                error!("{e}");
                break;
            }
        };
        println!("{pkt:#?}");
    }

    Ok(())
}
