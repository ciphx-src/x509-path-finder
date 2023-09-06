use openssl::error::ErrorStack;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::result;

pub type CertificatePathGeneratorResult<T> = result::Result<T, CertificatePathGeneratorError>;

#[derive(Debug)]
pub enum CertificatePathGeneratorError {
    Error(String),
    OpenSslErrorStack(ErrorStack),
    DerError(der::Error),
}

impl Display for CertificatePathGeneratorError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CertificatePathGeneratorError::Error(e) => {
                write!(f, "certificate path generator -> error: {}", e)
            }
            CertificatePathGeneratorError::OpenSslErrorStack(e) => {
                write!(
                    f,
                    "certificate path generator -> openssl error stack: {}",
                    e
                )
            }
            CertificatePathGeneratorError::DerError(e) => {
                write!(f, "certificate path generator -> der error: {}", e)
            }
        }
    }
}

impl Error for CertificatePathGeneratorError {}

impl From<ErrorStack> for CertificatePathGeneratorError {
    fn from(e: ErrorStack) -> Self {
        Self::OpenSslErrorStack(e)
    }
}

impl From<der::Error> for CertificatePathGeneratorError {
    fn from(e: der::Error) -> Self {
        Self::DerError(e)
    }
}
