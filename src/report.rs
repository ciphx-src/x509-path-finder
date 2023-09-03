//! Certificate path search report

use std::sync::Arc;
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
}

/// Path search success
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Found {
    /// Discovered certificate path
    pub path: Vec<Vec<u8>>,
    /// Certificate path origins
    pub origin: Vec<CertificateOrigin>,
}

/// Origins of each certificate found in path
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CertificateOrigin {
    /// Certificate used in [`X509PathFinder::find`](crate::find::X509PathFinder::find)
    Target,
    /// Certificate found in store
    Store,
    /// Certificate downloaded from AIA url
    Url(Arc<Url>),
}

/// Validation Failure
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ValidationFailure {
    /// Path where validation failure occurred
    pub path: Vec<Vec<u8>>,
    /// Path origins where validation failure occurred
    pub origin: Vec<CertificateOrigin>,
    /// Human-readable reason for validation failure
    pub reason: String,
}
