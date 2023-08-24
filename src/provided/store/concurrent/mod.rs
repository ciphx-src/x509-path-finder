#[cfg(test)]
mod tests;

use crate::api::{Certificate, CertificateStore};
use std::sync::{Arc, RwLock};
use std::vec;

use crate::provided::store::default::DefaultCertificateStore;
use crate::X509PathFinderError;

/// Concurrent [`CertificateStore`](crate::api::CertificateStore) implementation.
/// Useful for sharing a single store instance with multiple [`X509PathFinder`](crate::X509PathFinder) instances
#[derive(Clone)]
pub struct ConcurrentCertificateStore<'r, C: Certificate<'r>> {
    inner: Arc<RwLock<DefaultCertificateStore<'r, C>>>,
}

impl<'r, C: Certificate<'r>> ConcurrentCertificateStore<'r, C> {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(DefaultCertificateStore::default()).into(),
        }
    }

    /// Into inner [`DefaultCertificateStore`](crate::provided::store::DefaultCertificateStore)
    pub fn into_inner(self) -> Arc<RwLock<DefaultCertificateStore<'r, C>>> {
        self.inner
    }
}

impl<'r, C: Certificate<'r>> Default for ConcurrentCertificateStore<'r, C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'r, C: Certificate<'r>> CertificateStore<'r> for ConcurrentCertificateStore<'r, C>
where
    X509PathFinderError: From<<C as Certificate<'r>>::CertificateError>,
{
    type Certificate = C;
    type CertificateStoreError = X509PathFinderError;

    fn from_iter<IT: Into<Self::Certificate>, I: IntoIterator<Item = IT>>(iter: I) -> Self {
        Self {
            inner: RwLock::new(DefaultCertificateStore::from_iter(iter)).into(),
        }
    }

    fn try_vec(
        &self,
    ) -> Result<Vec<Arc<<Self::Certificate as Certificate<'r>>::Native>>, Self::CertificateStoreError>
    {
        self.inner
            .read()
            .map_err(|e| X509PathFinderError::Error(format!("memory error: {}", e).to_string()))?
            .try_vec()
    }

    fn insert<IT: Into<Self::Certificate>>(
        &mut self,
        certificate: IT,
    ) -> Result<bool, Self::CertificateStoreError> {
        self.inner
            .write()
            .map_err(|e| X509PathFinderError::Error(format!("memory error: {}", e).to_string()))?
            .insert(certificate)
    }

    fn append<IT: Into<C>, I: Iterator<Item = IT>>(
        &mut self,
        mut certificates: I,
    ) -> Result<(), Self::CertificateStoreError> {
        self.inner
            .write()
            .map_err(|e| X509PathFinderError::Error(format!("memory error: {}", e).to_string()))?
            .append(&mut certificates)
    }

    fn issuers(&self, subject: &C) -> Result<Vec<Self::Certificate>, Self::CertificateStoreError> {
        let mut issuers = vec![];
        for issuer_candidate in self
            .inner
            .read()
            .map_err(|e| {
                Self::CertificateStoreError::Error(format!("memory error: {}", e).to_string())
            })?
            .issuers(subject)?
        {
            if issuer_candidate.issued(subject)? {
                issuers.push(issuer_candidate.clone())
            }
        }

        Ok(issuers)
    }
}
