use std::io::{Error as IoError, ErrorKind};

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
}

/// convert h2 error to io error
pub fn h2_err_to_io_err(err: h2::Error) -> IoError {
    if err.is_io() {
        err.into_io().unwrap()
    } else {
        IoError::new(ErrorKind::Other, err)
    }
}
