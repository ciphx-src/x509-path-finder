use crate::X509PathFinderError;
use openssl::error::ErrorStack;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::result;

pub type OpenSSLPathValidatorResult<T> = result::Result<T, OpenSSLPathValidatorError>;

#[derive(Debug)]
pub enum OpenSSLPathValidatorError {
    Error(String),
    OpenSslErrorStack(ErrorStack),
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
        }
    }
}

impl Error for OpenSSLPathValidatorError {}

impl From<ErrorStack> for OpenSSLPathValidatorError {
    fn from(e: ErrorStack) -> Self {
        Self::OpenSslErrorStack(e)
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
