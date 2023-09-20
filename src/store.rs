use crate::certificate::Certificate;
use crate::report::CertificateOrigin;
use std::collections::{btree_set, BTreeSet};
use std::sync::Arc;

#[derive(Clone)]
pub struct CertificateStore {
    certificates: BTreeSet<Arc<Certificate>>,
    serial: usize,
}

impl CertificateStore {
    pub fn new() -> Self {
        Self {
            certificates: Default::default(),
            serial: 0,
        }
    }
    pub fn issuers(&self, subject: &Certificate) -> Vec<Arc<Certificate>> {
        self.certificates
            .iter()
            .filter_map(|c| {
                if c.issued(subject) {
                    Some(c.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn insert(&mut self, mut certificate: Certificate) -> Option<Arc<Certificate>> {
        if certificate.issued(&certificate) {
            return None;
        }
        self.serial += 1;
        certificate.set_ord(self.serial);
        let certificate = Arc::new(certificate);
        self.certificates.insert(certificate.clone());
        Some(certificate)
    }
}

impl Default for CertificateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl IntoIterator for CertificateStore {
    type Item = Arc<Certificate>;
    type IntoIter = btree_set::IntoIter<Arc<Certificate>>;

    fn into_iter(self) -> Self::IntoIter {
        self.certificates.into_iter()
    }
}

impl FromIterator<Certificate> for CertificateStore {
    fn from_iter<T: IntoIterator<Item = Certificate>>(iter: T) -> Self {
        // filter self-signed certificates
        let certificates = BTreeSet::from_iter(
            iter.into_iter()
                .filter_map(|c| (!c.issued(&c)).then_some(c))
                .enumerate()
                .map(|(i, mut c)| {
                    c.set_origin(CertificateOrigin::Store);
                    c.set_ord(i);
                    c.into()
                }),
        );
        Self {
            serial: certificates.len(),
            certificates,
        }
    }
}
