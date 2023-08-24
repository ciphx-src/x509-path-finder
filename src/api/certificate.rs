use std::fmt::{Debug, Display};
use std::sync::Arc;
use url::Url;

/// Model-agnostic representation of an X509 certificate.
/// Can be zero-copy if implemented correctly.
pub trait Certificate<'r>:
    AsRef<Self::NativeRef>
    + From<&'r Self::NativeRef>
    + From<&'r Self::Native>
    + From<Self::Native>
    + From<Arc<Self::Native>>
    + Into<Self::Native>
    + Into<Arc<Self::Native>>
    + Clone
    + Eq
    + Sync
    + Send
where
    <Self as Certificate<'r>>::Native: 'r,
{
    /// Native model type
    type Native;

    /// Native model type, reference form. Most implementations will use
    /// `type NativeRef = Self::Native`
    type NativeRef: 'r;

    /// Error type
    type CertificateError: CertificateError;

    /// Returns true if `self` issued `subject`.
    fn issued(&self, subject: &Self) -> Result<bool, Self::CertificateError>;

    /// Returns list of any URLs found in the [Authority Information Access](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1) extension.
    fn aia(&self) -> Vec<Url>;

    /// DER-encoded X509 representation, in bytes.
    fn der(&self) -> Result<Vec<u8>, Self::CertificateError>;
}

/// Error trait
pub trait CertificateError: Display + Debug {}
