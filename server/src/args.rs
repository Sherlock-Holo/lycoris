use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
pub struct Args {
    /// config path
    #[clap(short, long)]
    config: PathBuf,
}
