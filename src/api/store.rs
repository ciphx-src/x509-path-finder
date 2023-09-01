use crate::api::Certificate;
use std::fmt::{Debug, Display};

/// Local cache for Certificates. Can be used to pre-load
/// cross certificates and bridges. Is used by [`X509PathFinder`](crate::X509PathFinder)
/// to cache certificates discovered by processing the
/// [Authority Information Access](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1) extension.
pub trait CertificateStore:
    Clone + IntoIterator + FromIterator<Certificate> + Extend<Certificate> + Send + Sync
{
    /// Error type
    type CertificateStoreError: CertificateStoreError;

    /// Return list of certificates that could have issued `subject`.
    /// Implementations MUST search for issuers in the order they were added
    fn issuers(&self, subject: &Certificate) -> Vec<&Certificate>;
}

/// Error trait
pub trait CertificateStoreError: Display + Debug {}
