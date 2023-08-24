use crate::api::CertificateError;
use crate::api::PathValidatorError;
use std::convert::Infallible;
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::result;
use x509_client::X509ClientError;

pub type X509PathFinderResult<T> = result::Result<T, X509PathFinderError>;

/// Errors from [`X509PathFinder`](crate::X509PathFinder)
#[derive(Debug)]
pub enum X509PathFinderError {
    /// General errors
    Error(String),
    /// Errors from `X509Client`, when downloading certificates
    X509ClientError(X509ClientError),
    /// [`Certificate`](crate::api::Certificate) parsing errors
    CertificateError(Box<dyn CertificateError>),
    /// [`PathValidator`](crate::api::PathValidator) errors
    PathValidatorError(Box<dyn PathValidatorError>),
}

impl Display for X509PathFinderError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            X509PathFinderError::Error(e) => {
                write!(f, "x509-path-finder -> error: {}", e)
            }
            X509PathFinderError::X509ClientError(e) => {
                write!(f, "x509-path-finder -> {}", e)
            }
            X509PathFinderError::CertificateError(e) => {
                write!(f, "x509-path-finder -> {}", e)
            }
            X509PathFinderError::PathValidatorError(e) => {
                write!(f, "x509-path-finder -> {}", e)
            }
        }
    }
}

impl Error for X509PathFinderError {}

impl From<X509ClientError> for X509PathFinderError {
    fn from(e: X509ClientError) -> Self {
        Self::X509ClientError(e)
    }
}

impl From<Box<dyn CertificateError>> for X509PathFinderError {
    fn from(e: Box<dyn CertificateError>) -> Self {
        Self::CertificateError(e)
    }
}

impl From<Box<dyn PathValidatorError>> for X509PathFinderError {
    fn from(e: Box<dyn PathValidatorError>) -> Self {
        Self::PathValidatorError(e)
    }
}

impl PathValidatorError for Infallible {}
