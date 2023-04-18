use std::io::Error as IoError;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] IoError),

    #[error("http/2 error: {0}")]
    H2(#[from] h2::Error),

    #[error("http error: {0}")]
    Hyper(#[from] hyper::Error),

    #[error("address data is not enough")]
    AddrNotEnough,

    #[error("address type {0} is invalid, valid is `4` and `6`")]
    AddrTypeInvalid(u8),

    #[error("address domain invalid")]
    AddrDomainInvalid,

    #[error("auth failed")]
    AuthFailed,

    #[error("parse config failed: {0}")]
    Config(#[from] serde_yaml::Error),

    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("build tls config failed: {0}")]
    TlsConfig(#[from] tokio_rustls::rustls::Error),

    #[error("build auth failed: {0:?}")]
    Auth(totp_rs::TotpUrlError),
}

impl From<totp_rs::TotpUrlError> for Error {
    fn from(err: totp_rs::TotpUrlError) -> Self {
        Self::Auth(err)
    }
}
