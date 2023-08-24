use crate::api::Certificate;
use std::cmp::Ordering;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct CertificateOrd<'r, C: Certificate<'r>> {
    inner: C,
    ord: usize,
    lifetime: PhantomData<&'r C>,
}

impl<'r, C: Certificate<'r>> CertificateOrd<'r, C> {
    pub fn new<IT: Into<C>>(inner: IT, ord: usize) -> Self {
        Self {
            inner: inner.into(),
            ord,
            lifetime: PhantomData,
        }
    }
}

impl<'r, C: Certificate<'r>> AsRef<C> for CertificateOrd<'r, C> {
    fn as_ref(&self) -> &C {
        &self.inner
    }
}

impl<'r, C: Certificate<'r>> PartialEq for CertificateOrd<'r, C> {
    fn eq(&self, other: &Self) -> bool {
        self.inner.eq(&other.inner)
    }
}

impl<'r, C: Certificate<'r>> Eq for CertificateOrd<'r, C> {}

impl<'r, C: Certificate<'r>> PartialOrd for CertificateOrd<'r, C> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<'r, C: Certificate<'r>> Ord for CertificateOrd<'r, C> {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.eq(other) {
            return Ordering::Equal;
        }

        if self.ord > other.ord {
            return Ordering::Greater;
        }

        Ordering::Less
    }
}
