use crate::api::certificate::Certificate;
use crate::report::ValidateFailure;
use std::fmt::{Debug, Display};

/// Certificate path validation. Implement to customize behavior. Note: X509 certificate [path validation](https://datatracker.ietf.org/doc/html/rfc5280#section-6) is not
/// trivial. Implement to add business logic, but leverage a trusted X509 validator within.
pub trait PathValidator {
    /// Error type
    type PathValidatorError: PathValidatorError;

    /// Validates `path`, returning results as [`CertificatePathValidation`](crate::api::validator::CertificatePathValidation)
    fn validate<'r>(
        &self,
        path: Vec<&'r Certificate>,
    ) -> Result<CertificatePathValidation<'r>, Self::PathValidatorError>;
}

/// Result of [`validate`](crate::api::validator::PathValidator::validate)
pub enum CertificatePathValidation<'r> {
    /// Valid path found
    Found(Vec<&'r Certificate>),
    /// Valid path not found
    NotFound(ValidateFailure<'r>),
}

/// Error trait
pub trait PathValidatorError: Display + Debug {}
