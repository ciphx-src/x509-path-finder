use crate::X509PathFinderError;
use openssl::error::ErrorStack;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::result;
use x509_client::provided::openssl::OpenSSLX509IteratorError;

pub type OpenSSLPathValidatorResult<T> = result::Result<T, OpenSSLPathValidatorError>;

#[derive(Debug)]
pub enum OpenSSLPathValidatorError {
    Error(String),
    OpenSslErrorStack(ErrorStack),
    OpenSSLX509IteratorError(OpenSSLX509IteratorError),
    DerError(der::Error),
}

impl Display for OpenSSLPathValidatorError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenSSLPathValidatorError::Error(e) => {
                write!(f, "openssl path validator -> error: {}", e)
            }
            OpenSSLPathValidatorError::OpenSslErrorStack(e) => {
                write!(f, "openssl path validator -> openssl error stack: {}", e)
            }
            OpenSSLPathValidatorError::DerError(e) => {
                write!(f, "openssl path validator -> der error: {}", e)
            }
            OpenSSLPathValidatorError::OpenSSLX509IteratorError(e) => {
                write!(f, "openssl path validator -> {}", e)
            }
        }
    }
}

impl Error for OpenSSLPathValidatorError {}

impl From<ErrorStack> for OpenSSLPathValidatorError {
    fn from(e: ErrorStack) -> Self {
        Self::OpenSslErrorStack(e)
    }
}

impl From<OpenSSLX509IteratorError> for OpenSSLPathValidatorError {
    fn from(e: OpenSSLX509IteratorError) -> Self {
        Self::OpenSSLX509IteratorError(e)
    }
}

impl From<der::Error> for OpenSSLPathValidatorError {
    fn from(e: der::Error) -> Self {
        Self::DerError(e)
    }
}

impl From<OpenSSLPathValidatorError> for X509PathFinderError {
    fn from(e: OpenSSLPathValidatorError) -> Self {
        Self::PathValidatorError(Box::new(e))
    }
}
