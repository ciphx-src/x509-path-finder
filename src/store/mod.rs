#[cfg(test)]
mod tests;

use crate::api::Certificate;
use std::collections::{btree_set, BTreeSet};

#[derive(Clone)]
pub struct CertificateStore {
    certificates: BTreeSet<Certificate>,
    serial: usize,
}

impl CertificateStore {
    pub fn new() -> Self {
        Self {
            certificates: Default::default(),
            serial: 0,
        }
    }
    pub fn issuers(&self, subject: &Certificate) -> Vec<&Certificate> {
        self.certificates
            .iter()
            .filter(|c| c.issued(subject))
            .collect()
    }
}

impl Default for CertificateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl IntoIterator for CertificateStore {
    type Item = Certificate;
    type IntoIter = btree_set::IntoIter<Certificate>;

    fn into_iter(self) -> Self::IntoIter {
        self.certificates.into_iter()
    }
}

impl FromIterator<Certificate> for CertificateStore {
    fn from_iter<T: IntoIterator<Item = Certificate>>(iter: T) -> Self {
        let certificates = BTreeSet::from_iter(iter.into_iter().enumerate().map(|(i, mut c)| {
            c.set_ord(i);
            c
        }));
        let serial = certificates.len();
        Self {
            certificates,
            serial,
        }
    }
}

impl Extend<Certificate> for CertificateStore {
    fn extend<T: IntoIterator<Item = Certificate>>(&mut self, iter: T) {
        self.certificates.extend(iter.into_iter().map(|mut c| {
            self.serial += 1;
            c.set_ord(self.serial);
            c
        }));
    }
}
