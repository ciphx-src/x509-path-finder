//! OpenSSL [`PathValidator`](crate::api::PathValidator) implementations

use crate::api::{CertificatePathValidation, PathValidator, PathValidatorError};
use crate::provided::certificate::openssl::OpenSSLCertificate;
use crate::provided::openssl_common::result::OpenSSLError;
use crate::report::{CertificatePath, ValidateFailure};
use openssl::stack::Stack;
use openssl::x509::store::X509Store;
use openssl::x509::{X509StoreContext, X509VerifyResult};
use std::marker::PhantomData;

#[cfg(test)]
pub mod tests;

/// OpenSSL [`PathValidator`](crate::api::PathValidator) implementations
pub struct OpenSSLPathValidator<'r> {
    store: X509Store,
    lifetime: PhantomData<&'r ()>,
}
impl<'r> OpenSSLPathValidator<'r> {
    /// Constructor takes a configured OpenSSL X509Store
    pub fn new(store: X509Store) -> Self {
        Self {
            store,
            lifetime: PhantomData,
        }
    }
}

impl<'r> PathValidator<'r> for OpenSSLPathValidator<'r> {
    type Certificate = OpenSSLCertificate<'r>;
    type PathValidatorError = OpenSSLError;

    fn validate(
        &self,
        path: Vec<OpenSSLCertificate<'r>>,
    ) -> Result<CertificatePathValidation<'r, OpenSSLCertificate<'r>>, Self::PathValidatorError>
    {
        if path.is_empty() {
            return Ok(CertificatePathValidation::NotFound(ValidateFailure {
                path: CertificatePath::from_iter(path),
                reason: "path is empty".to_string(),
            }));
        }

        let mut openssl_path = Stack::new()?;
        for certificate in &path {
            openssl_path.push(certificate.clone().into())?;
        }

        let mut context = X509StoreContext::new()?;
        let verified = context.init(
            self.store.as_ref(),
            path[0].as_ref(),
            openssl_path.as_ref(),
            |context| {
                Ok(match context.verify_cert()? {
                    true => VerifyResult::Success,
                    false => VerifyResult::Failure(context.error()),
                })
            },
        )?;

        match verified {
            VerifyResult::Success => Ok(CertificatePathValidation::Found(
                CertificatePath::from_iter(path),
            )),

            VerifyResult::Failure(f) => Ok(CertificatePathValidation::NotFound(ValidateFailure {
                path: CertificatePath::from_iter(path),
                reason: f.error_string().to_string(),
            })),
        }
    }
}
impl PathValidatorError for OpenSSLError {}

enum VerifyResult {
    Success,
    Failure(X509VerifyResult),
}
