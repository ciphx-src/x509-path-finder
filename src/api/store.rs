use crate::api::certificate::Certificate;
use std::fmt::{Debug, Display};
use std::sync::Arc;

/// Local cache for Certificates. Can be used to pre-load
/// cross certificates and bridges. Is used by [`X509PathFinder`](crate::X509PathFinder)
/// to cache certificates discovered by processing the
/// [Authority Information Access](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1) extension.
/// All methods are fallible, making concurrent implementations possible.
pub trait CertificateStore<'r>: Clone {
    /// X509 certificate
    type Certificate: Certificate<'r>;
    /// Error type
    type CertificateStoreError: CertificateStoreError;

    /// Create new store, populated by iterator
    fn from_iter<IT: Into<Self::Certificate>, I: IntoIterator<Item = IT>>(iter: I) -> Self;

    /// Return list of all certificates in store
    #[allow(clippy::type_complexity)]
    fn try_vec(
        &self,
    ) -> Result<Vec<Arc<<Self::Certificate as Certificate<'r>>::Native>>, Self::CertificateStoreError>;

    /// Insert certificate into store
    fn insert<IT: Into<Self::Certificate>>(
        &mut self,
        certificate: IT,
    ) -> Result<bool, Self::CertificateStoreError>;

    /// Append iterator into store
    fn append<IT: Into<Self::Certificate>, I: Iterator<Item = IT>>(
        &mut self,
        certificates: I,
    ) -> Result<(), Self::CertificateStoreError>;

    /// Return list of certificates that could have issued `subject`.
    /// Implementations MUST search for issuers in the order they were added
    fn issuers(
        &self,
        subject: &Self::Certificate,
    ) -> Result<Vec<Self::Certificate>, Self::CertificateStoreError>;
}

/// Error trait
pub trait CertificateStoreError: Display + Debug {}
