mod certificate;

#[cfg(test)]
mod tests;

use crate::api::{Certificate, CertificateStore, CertificateStoreError};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::vec;

use crate::provided::store::default::certificate::CertificateOrd;
use crate::X509PathFinderError;

/// Default [`CertificateStore`](crate::api::CertificateStore) implementation.
/// Not thread safe. See [`ConcurrentCertificateStore`](crate::provided::store::ConcurrentCertificateStore) for a concurrent implementation.
#[derive(Clone)]
pub struct DefaultCertificateStore<'r, C: Certificate<'r>> {
    certificates: BTreeSet<CertificateOrd<'r, C>>,
    serial: usize,
}

impl<'r, C: Certificate<'r>> DefaultCertificateStore<'r, C> {
    pub fn new() -> Self {
        Self {
            certificates: Default::default(),
            serial: 0,
        }
    }
}

impl<'r, C: Certificate<'r>> Default for DefaultCertificateStore<'r, C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'r, C: Certificate<'r>> CertificateStore<'r> for DefaultCertificateStore<'r, C>
where
    X509PathFinderError: From<<C as Certificate<'r>>::CertificateError>,
{
    type Certificate = C;
    type CertificateStoreError = X509PathFinderError;

    fn from_iter<IT: Into<Self::Certificate>, I: IntoIterator<Item = IT>>(iter: I) -> Self {
        let certificates = iter
            .into_iter()
            .enumerate()
            .map(|(i, c)| CertificateOrd::new(c, i))
            .collect::<BTreeSet<CertificateOrd<'r, C>>>();
        let serial = certificates.len();
        Self {
            certificates,
            serial,
        }
    }

    fn try_vec(
        &self,
    ) -> Result<Vec<Arc<<Self::Certificate as Certificate<'r>>::Native>>, Self::CertificateStoreError>
    {
        Ok(self
            .certificates
            .iter()
            .map(|c| c.as_ref().clone().into())
            .collect())
    }

    fn insert<IT: Into<Self::Certificate>>(
        &mut self,
        certificate: IT,
    ) -> Result<bool, Self::CertificateStoreError> {
        self.serial += 1;
        Ok(self
            .certificates
            .insert(CertificateOrd::new(certificate, self.serial)))
    }

    fn append<IT: Into<Self::Certificate>, I: Iterator<Item = IT>>(
        &mut self,
        certificates: I,
    ) -> Result<(), Self::CertificateStoreError> {
        let mut certificates = certificates
            .map(|c| {
                self.serial += 1;
                CertificateOrd::new(c, self.serial)
            })
            .collect::<BTreeSet<CertificateOrd<'r, C>>>();
        self.certificates.append(&mut certificates);
        Ok(())
    }

    fn issuers(&self, subject: &C) -> Result<Vec<Self::Certificate>, Self::CertificateStoreError> {
        let mut issuers = vec![];
        for issuer_candidate in self.certificates.iter() {
            if issuer_candidate.as_ref().issued(subject)? {
                issuers.push(issuer_candidate.as_ref().clone())
            }
        }

        Ok(issuers)
    }
}

impl CertificateStoreError for X509PathFinderError {}
