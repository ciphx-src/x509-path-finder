//! Default [`PathValidator`](crate::api::PathValidator) implementations

pub mod result;

use crate::api::{Certificate, CertificatePathValidation, PathValidator, PathValidatorError};
use crate::provided::validator::default::result::DefaultPathValidatorError;
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
    type PathValidatorError = DefaultPathValidatorError;

    fn validate<'r>(
        &self,
        path: &[Certificate],
    ) -> Result<CertificatePathValidation, Self::PathValidatorError> {
        if path.is_empty() {
            return Ok(CertificatePathValidation::NotFound(
                "path is empty".to_string(),
            ));
        }

        let mut rustls_path: Vec<RustlsCertificate> = vec![];
        for certificate in &path[1..] {
            rustls_path.push(RustlsCertificate(certificate.der().to_vec()));
        }

        match rustls::client::verify_server_cert_signed_by_trust_anchor(
            &ParsedCertificate::try_from(&RustlsCertificate(path[0].der().to_vec()))?,
            &self.store,
            rustls_path.as_slice(),
            SystemTime::now(),
        ) {
            Ok(_) => Ok(CertificatePathValidation::Found),

            Err(f) => Ok(CertificatePathValidation::NotFound(f.to_string())),
        }
    }
}
impl PathValidatorError for DefaultPathValidatorError {}
