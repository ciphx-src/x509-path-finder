//! Certificate path validation report

use crate::api::Certificate;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

/// Path search report returned by [`X509PathFinder::find`](crate::X509PathFinder::find)
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Report<'r> {
    /// On validate success, `Option::Some` holds certificate path
    pub path: Option<Vec<Certificate>>,
    /// On validate success, `Option::Some` holds certificate path origins
    pub origin: Option<Vec<CertificateOrigin>>,
    /// Duration of path search
    pub duration: Duration,
    /// Any validation failures reported by [`PathValidator`](crate::api::PathValidator)
    pub failures: Vec<ValidateFailure<'r>>,
}

/// Validation failures
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ValidateFailure<'r> {
    /// Certificate path of failed validation attempt
    pub path: Vec<&'r Certificate>,
    /// Human-readable reason for validation failure
    pub reason: String,
}

/// Origins of each certificate found in path
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CertificateOrigin {
    /// Certificate used in [`X509PathFinder::find`](crate::find::X509PathFinder::find)
    Find,
    /// Certificate found in store
    Store,
    /// Certificate downloaded from AIA url
    Url(Arc<Url>),
}
