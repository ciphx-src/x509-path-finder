//! Default [`PathValidator`](crate::api::PathValidator) implementations

use crate::api::{Certificate, CertificatePathValidation, PathValidator, PathValidatorError};
use crate::provided::certificate::default::DefaultCertificate;
use crate::provided::default_common::result::DefaultCertificateError;
use crate::report::{CertificatePath, ValidateFailure};
use rustls::server::ParsedCertificate;
use rustls::{Certificate as RustlsCertificate, RootCertStore};
use std::marker::PhantomData;
use std::time::SystemTime;

#[cfg(test)]
pub mod tests;

/// Default [`PathValidator`](crate::api::PathValidator)
pub struct DefaultPathValidator<'r> {
    store: RootCertStore,
    lifetime: PhantomData<&'r ()>,
}
impl<'r> DefaultPathValidator<'r> {
    /// Constructor takes a configured Rustls store
    pub fn new(store: RootCertStore) -> Self {
        Self {
            store,
            lifetime: PhantomData,
        }
    }
}

impl<'r> PathValidator<'r> for DefaultPathValidator<'r> {
    type Certificate = DefaultCertificate<'r>;
    type PathValidatorError = DefaultCertificateError;

    fn validate(
        &self,
        path: Vec<DefaultCertificate<'r>>,
    ) -> Result<CertificatePathValidation<'r, DefaultCertificate<'r>>, Self::PathValidatorError>
    {
        if path.is_empty() {
            return Ok(CertificatePathValidation::NotFound(ValidateFailure {
                path: CertificatePath::from_iter(path),
                reason: "path is empty".to_string(),
            }));
        }

        let ee = RustlsCertificate(path[0].der()?);

        let mut rustls_path: Vec<RustlsCertificate> = vec![];
        for certificate in &path[1..] {
            rustls_path.push(RustlsCertificate(certificate.der()?));
        }

        match rustls::client::verify_server_cert_signed_by_trust_anchor(
            &ParsedCertificate::try_from(&ee)?,
            &self.store,
            rustls_path.as_slice(),
            SystemTime::now(),
        ) {
            Ok(_) => Ok(CertificatePathValidation::Found(
                CertificatePath::from_iter(path),
            )),

            Err(f) => Ok(CertificatePathValidation::NotFound(ValidateFailure {
                path: CertificatePath::from_iter(path),
                reason: f.to_string(),
            })),
        }
    }
}
impl PathValidatorError for DefaultCertificateError {}
