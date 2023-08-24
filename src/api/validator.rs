use crate::api::certificate::Certificate;
use crate::report::{CertificatePath, ValidateFailure};
use std::fmt::{Debug, Display};

/// Certificate path validation. Implement to customize behavior. Note: X509 certificate [path validation](https://datatracker.ietf.org/doc/html/rfc5280#section-6) is not
/// trivial. Implement to add business logic, but leverage a trusted X509 validator within.
pub trait PathValidator<'r> {
    /// X509 certificate
    type Certificate: Certificate<'r>;
    /// Error type
    type PathValidatorError: PathValidatorError;

    /// Validates `path`, returning results as [`CertificatePathValidation`](crate::api::validator::CertificatePathValidation)
    fn validate(
        &self,
        path: Vec<Self::Certificate>,
    ) -> Result<CertificatePathValidation<'r, Self::Certificate>, Self::PathValidatorError>;
}

/// Result of [`validate`](crate::api::validator::PathValidator::validate)
pub enum CertificatePathValidation<'r, C: Certificate<'r>> {
    /// Valid path found
    Found(CertificatePath<'r, C>),
    /// Valid path not found
    NotFound(ValidateFailure<'r, C>),
}

/// Error trait
pub trait PathValidatorError: Display + Debug {}
