use std::error::Error;
use std::fmt::{Display, Formatter};
use std::result;
use x509_client::api::X509IteratorError;
use x509_client::X509ClientError;

pub type DefaultResult<T> = result::Result<T, DefaultError>;

#[derive(Debug)]
pub enum DefaultError {
    Error(String),
    DerError(der::Error),
    RustlsError(rustls::Error),
}

impl X509IteratorError for DefaultError {}

impl Display for DefaultError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DefaultError::Error(e) => {
                write!(f, "default certificate -> error: {}", e)
            }
            DefaultError::DerError(e) => {
                write!(f, "default certificate -> der error: {}", e)
            }
            DefaultError::RustlsError(e) => {
                write!(f, "default certificate -> rustls error: {}", e)
            }
        }
    }
}

impl Error for DefaultError {}

impl From<der::Error> for DefaultError {
    fn from(e: der::Error) -> Self {
        Self::DerError(e)
    }
}

impl From<rustls::Error> for DefaultError {
    fn from(e: rustls::Error) -> Self {
        Self::RustlsError(e)
    }
}

impl From<DefaultError> for X509ClientError {
    fn from(e: DefaultError) -> Self {
        Self::X509IteratorError(Box::new(e))
    }
}
