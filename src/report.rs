//! Certificate path search report

use std::time::Duration;
use url::Url;

/// Path search report returned by [`X509PathFinder::find`](crate::X509PathFinder::find)
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Report {
    /// On path search success, `Option::Some` holds [`Found`](crate::report::Found)
    pub found: Option<Found>,
    /// Duration of path search
    pub duration: Duration,
    /// Any validation failures reported by [`PathValidator`](crate::api::PathValidator)
    pub failures: Vec<ValidationFailure>,
    /// All cached certificates not used in path
    pub store: Vec<crate::Certificate>,
}

/// Path search success
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Found {
    /// Discovered certificate path
    pub path: Vec<crate::Certificate>,
    /// Certificate path origins
    pub origin: Vec<CertificateOrigin>,
}

/// Origins of each certificate found in path
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum CertificateOrigin {
    #[doc(hidden)]
    Unknown,
    /// Certificate used in [`X509PathFinder::find`](crate::find::X509PathFinder::find)
    Target,
    /// Certificate found in store
    Store,
    /// Certificate downloaded from AIA url
    Url(Url),
}

/// Validation Failure
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ValidationFailure {
    /// Path origins where validation failure occurred
    pub origin: Vec<CertificateOrigin>,
    /// Human-readable reason for validation failure
    pub reason: String,
}
