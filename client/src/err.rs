use std::io::Error as IoError;

use aya::maps::MapError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("load bpf map failed: {0}")]
    BpfMap(#[from] MapError),

    #[error("io error: {0}")]
    Io(#[from] IoError),

    #[error("http/2 error: {0}")]
    H2(#[from] h2::Error),

    #[error("parse config failed: {0}")]
    Config(#[from] serde_yaml::Error),
}
