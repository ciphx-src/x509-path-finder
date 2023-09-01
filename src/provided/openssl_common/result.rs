use openssl::error::ErrorStack;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::result;
use x509_client::api::X509IteratorError;
use x509_client::provided::openssl::OpenSSLX509IteratorError;
use x509_client::X509ClientError;

pub type OpenSSLResult<T> = result::Result<T, OpenSSLError>;

#[derive(Debug)]
pub enum OpenSSLError {
    Error(String),
    OpenSslErrorStack(ErrorStack),
    OpenSSLX509IteratorError(OpenSSLX509IteratorError),
    DerError(der::Error),
}

impl X509IteratorError for OpenSSLError {}

impl Display for OpenSSLError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenSSLError::Error(e) => {
                write!(f, "openssl certificate -> error: {}", e)
            }
            OpenSSLError::OpenSslErrorStack(e) => {
                write!(f, "openssl certificate -> openssl error stack: {}", e)
            }
            OpenSSLError::DerError(e) => {
                write!(f, "openssl certificate -> der error: {}", e)
            }
            OpenSSLError::OpenSSLX509IteratorError(e) => {
                write!(f, "openssl certificate -> {}", e)
            }
        }
    }
}

impl Error for OpenSSLError {}

impl From<ErrorStack> for OpenSSLError {
    fn from(e: ErrorStack) -> Self {
        Self::OpenSslErrorStack(e)
    }
}

impl From<OpenSSLX509IteratorError> for OpenSSLError {
    fn from(e: OpenSSLX509IteratorError) -> Self {
        Self::OpenSSLX509IteratorError(e)
    }
}

impl From<der::Error> for OpenSSLError {
    fn from(e: der::Error) -> Self {
        Self::DerError(e)
    }
}

impl From<OpenSSLError> for X509ClientError {
    fn from(e: OpenSSLError) -> Self {
        Self::X509IteratorError(Box::new(e))
    }
}
