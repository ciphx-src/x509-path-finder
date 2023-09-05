use std::fmt::{Debug, Display};

/// Certificate path validation. Implement to customize behavior. Note: X509 certificate [path validation](https://datatracker.ietf.org/doc/html/rfc5280#section-6) is not
/// trivial. Implement to add business logic, but leverage a trusted X509 validator within.
pub trait PathValidator {
    /// Error type
    type PathValidatorError: PathValidatorError;

    /// Validates `path`, returning results as [`CertificatePathValidation`](crate::api::validator::CertificatePathValidation)
    fn validate(
        &self,
        path: Vec<&x509_cert::Certificate>,
    ) -> Result<CertificatePathValidation, Self::PathValidatorError>;
}

/// Result of [`validate`](crate::api::validator::PathValidator::validate)
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CertificatePathValidation {
    /// Valid path found
    Found,
    /// Valid path not found
    NotFound(String),
}

/// Error trait
pub trait PathValidatorError: Display + Debug {}
