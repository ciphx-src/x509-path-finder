//! OpenSSL [`PathValidator`](crate::api::PathValidator) implementations

pub mod result;

use crate::api::{CertificatePathValidation, PathValidator, PathValidatorError};
use crate::provided::validator::openssl::result::OpenSSLPathValidatorError;
use der::Encode;
use openssl::stack::Stack;
use openssl::x509::store::X509Store;
use openssl::x509::{X509StoreContext, X509VerifyResult, X509};

/// OpenSSL [`PathValidator`](crate::api::PathValidator)
pub struct OpenSSLPathValidator {
    store: X509Store,
}
impl OpenSSLPathValidator {
    /// Constructor takes a configured OpenSSL X509Store
    pub fn new(store: X509Store) -> Self {
        Self { store }
    }
}

impl PathValidator for OpenSSLPathValidator {
    type PathValidatorError = OpenSSLPathValidatorError;

    fn validate(
        &self,
        path: Vec<&x509_cert::Certificate>,
    ) -> Result<CertificatePathValidation, Self::PathValidatorError> {
        if path.is_empty() {
            return Ok(CertificatePathValidation::NotFound(
                "path is empty".to_string(),
            ));
        }

        let mut openssl_path = Stack::new()?;
        for certificate in &path[1..] {
            openssl_path.push(X509::from_der(&certificate.to_der()?)?)?;
        }

        let mut context = X509StoreContext::new()?;
        let verified = context.init(
            self.store.as_ref(),
            X509::from_der(&path[0].to_der()?)?.as_ref(),
            openssl_path.as_ref(),
            |context| {
                Ok(match context.verify_cert()? {
                    true => VerifyResult::Success,
                    false => VerifyResult::Failure(context.error()),
                })
            },
        )?;

        match verified {
            VerifyResult::Success => Ok(CertificatePathValidation::Found),

            VerifyResult::Failure(f) => Ok(CertificatePathValidation::NotFound(
                f.error_string().to_string(),
            )),
        }
    }
}

impl PathValidatorError for OpenSSLPathValidatorError {}

enum VerifyResult {
    Success,
    Failure(X509VerifyResult),
}
