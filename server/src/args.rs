use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
pub struct Args {
    /// config path
    #[clap(short, long)]
    pub config: PathBuf,

    /// debug log
    #[clap(short, long, action)]
    pub debug: bool,
}
