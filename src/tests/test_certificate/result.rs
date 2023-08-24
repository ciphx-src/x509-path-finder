use crate::api::CertificateError;
use crate::X509PathFinderError;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::result;
use x509_client::api::X509IteratorError;
use x509_client::X509ClientError;

pub type TestCertificateResult<T> = result::Result<T, TestCertificateError>;

#[derive(Debug)]
pub enum TestCertificateError {
    Error(String),
}

impl CertificateError for TestCertificateError {}
impl X509IteratorError for TestCertificateError {}

impl Display for TestCertificateError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TestCertificateError::Error(e) => {
                write!(f, "debug certificate -> error: {}", e)
            }
        }
    }
}

impl Error for TestCertificateError {}
impl From<TestCertificateError> for X509PathFinderError {
    fn from(e: TestCertificateError) -> Self {
        Self::CertificateError(Box::new(e))
    }
}

impl From<TestCertificateError> for X509ClientError {
    fn from(e: TestCertificateError) -> Self {
        Self::X509IteratorError(Box::new(e))
    }
}
