use crate::api::CertificateError;
use crate::X509PathFinderError;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::result;
use x509_client::api::X509IteratorError;
use x509_client::X509ClientError;

pub type DefaultCertificateResult<T> = result::Result<T, DefaultCertificateError>;

#[derive(Debug)]
pub enum DefaultCertificateError {
    Error(String),
    DerError(cms::cert::x509::der::Error),
}

impl CertificateError for DefaultCertificateError {}
impl X509IteratorError for DefaultCertificateError {}

impl Display for DefaultCertificateError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DefaultCertificateError::Error(e) => {
                write!(f, "default certificate -> error: {}", e)
            }
            DefaultCertificateError::DerError(e) => {
                write!(f, "default certificate -> der error: {}", e)
            }
        }
    }
}

impl Error for DefaultCertificateError {}

impl From<cms::cert::x509::der::Error> for DefaultCertificateError {
    fn from(e: cms::cert::x509::der::Error) -> Self {
        Self::DerError(e)
    }
}

impl From<DefaultCertificateError> for X509PathFinderError {
    fn from(e: DefaultCertificateError) -> Self {
        Self::CertificateError(Box::new(e))
    }
}

impl From<DefaultCertificateError> for X509ClientError {
    fn from(e: DefaultCertificateError) -> Self {
        Self::X509IteratorError(Box::new(e))
    }
}
