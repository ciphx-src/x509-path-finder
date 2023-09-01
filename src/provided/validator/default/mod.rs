//! Default [`PathValidator`](crate::api::PathValidator) implementations

pub mod result;
#[cfg(test)]
pub mod tests;

use crate::api::{Certificate, CertificatePathValidation, PathValidator, PathValidatorError};
use crate::provided::validator::default::result::DefaultError;
use crate::report::ValidateFailure;
use der::Encode;
use rustls::server::ParsedCertificate;
use rustls::{Certificate as RustlsCertificate, RootCertStore};
use std::time::SystemTime;

/// Default [`PathValidator`](crate::api::PathValidator)
pub struct DefaultPathValidator {
    store: RootCertStore,
}
impl DefaultPathValidator {
    /// Constructor takes a configured Rustls store
    pub fn new(store: RootCertStore) -> Self {
        Self { store }
    }
}

impl PathValidator for DefaultPathValidator {
    type PathValidatorError = DefaultError;

    fn validate<'r>(
        &self,
        path: Vec<Certificate>,
    ) -> Result<CertificatePathValidation, Self::PathValidatorError> {
        if path.is_empty() {
            return Ok(CertificatePathValidation::NotFound(ValidateFailure {
                path,
                reason: "path is empty".to_string(),
            }));
        }

        let mut rustls_path: Vec<RustlsCertificate> = vec![];
        for certificate in &path[1..] {
            rustls_path.push(RustlsCertificate(certificate.to_der()?));
        }

        match rustls::client::verify_server_cert_signed_by_trust_anchor(
            &ParsedCertificate::try_from(&RustlsCertificate(path[0].to_der()?))?,
            &self.store,
            rustls_path.as_slice(),
            SystemTime::now(),
        ) {
            Ok(_) => Ok(CertificatePathValidation::Found(path)),

            Err(f) => Ok(CertificatePathValidation::NotFound(ValidateFailure {
                path,
                reason: f.to_string(),
            })),
        }
    }
}
impl PathValidatorError for DefaultError {}
