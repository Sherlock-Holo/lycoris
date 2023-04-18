use std::io::Error as IoError;

use aya::maps::MapError;
use thiserror::Error;
use trust_dns_resolver::error::ResolveError;

#[derive(Debug, Error)]
pub enum Error {
    #[error("load bpf map failed: {0}")]
    BpfMap(#[from] MapError),

    #[error("io error: {0}")]
    Io(#[from] IoError),

    #[error("http/2 error: {0}")]
    H2(#[from] h2::Error),

    #[error("hyper error: {0}")]
    Hyper(#[from] hyper::Error),

    #[error("parse config failed: {0}")]
    Config(#[from] serde_yaml::Error),

    #[error("build auth failed: {0:?}")]
    Auth(totp_rs::TotpUrlError),

    #[error("bpf error: {0}")]
    Bpf(#[from] aya::BpfError),

    #[error("bpf program error: {0}")]
    BpfProgram(#[from] aya::programs::ProgramError),

    #[error("resolve dns failed: {0}")]
    DnsResolve(#[from] ResolveError),

    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl From<totp_rs::TotpUrlError> for Error {
    fn from(err: totp_rs::TotpUrlError) -> Self {
        Self::Auth(err)
    }
}
