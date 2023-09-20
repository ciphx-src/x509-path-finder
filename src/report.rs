//! Certificate path search report

use std::sync::Arc;
use std::time::Duration;
use url::Url;

pub struct PathIter<'r> {
    path: &'r Vec<Arc<crate::Certificate>>,
    pos: usize,
}

impl<'r> Iterator for PathIter<'r> {
    type Item = &'r crate::Certificate;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.path.len() {
            None
        } else {
            self.pos += 1;
            Some(&self.path[self.pos - 1])
        }
    }
}

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
    pub path: Vec<Arc<crate::Certificate>>,
    /// Certificate path origins
    pub origin: Vec<CertificateOrigin>,
}

impl<'r> IntoIterator for &'r Found {
    type Item = &'r crate::Certificate;
    type IntoIter = PathIter<'r>;

    fn into_iter(self) -> Self::IntoIter {
        PathIter {
            path: &self.path,
            pos: 0,
        }
    }
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
    /// Path where validation failure occurred
    pub path: Vec<Arc<crate::Certificate>>,
    /// Path origins where validation failure occurred
    pub origin: Vec<CertificateOrigin>,
    /// Human-readable reason for validation failure
    pub reason: String,
}

impl<'r> IntoIterator for &'r ValidationFailure {
    type Item = &'r crate::Certificate;
    type IntoIter = PathIter<'r>;

    fn into_iter(self) -> Self::IntoIter {
        PathIter {
            path: &self.path,
            pos: 0,
        }
    }
}
