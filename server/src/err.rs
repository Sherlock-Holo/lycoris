use std::io::{Error as IoError, ErrorKind};

use h2::Reason;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] IoError),

    #[error("http/2 error: {0}")]
    H2(#[from] h2::Error),

    #[error("address data is not enough")]
    AddrNotEnough,

    #[error("address type {0} is invalid, valid is `4` and `6`")]
    AddrTypeInvalid(u8),

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

/// convert h2 error to io error
pub fn h2_err_to_io_err(err: h2::Error) -> IoError {
    if err.is_io() {
        err.into_io().unwrap()
    } else {
        let reason = if let Some(reason) = err.reason() {
            reason
        } else {
            return IoError::new(ErrorKind::Other, err);
        };

        match reason {
            Reason::NO_ERROR | Reason::CONNECT_ERROR => IoError::from(ErrorKind::BrokenPipe),
            Reason::PROTOCOL_ERROR | Reason::COMPRESSION_ERROR | Reason::FRAME_SIZE_ERROR => {
                IoError::from(ErrorKind::InvalidData)
            }

            reason => IoError::new(ErrorKind::Other, reason.description()),
        }
    }
}
