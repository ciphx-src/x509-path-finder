use crate::api::Certificate;
use std::marker::PhantomData;
use std::vec;

/// Certificate path iterator
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CertificatePath<'r, C: Certificate<'r>> {
    path: Vec<C>,
    lifetime: PhantomData<&'r C>,
}

impl<'r, C: Certificate<'r>> IntoIterator for CertificatePath<'r, C> {
    type Item = <C as Certificate<'r>>::Native;
    type IntoIter = vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.path
            .into_iter()
            .map(|c| c.into())
            .collect::<Vec<<C as Certificate<'r>>::Native>>()
            .into_iter()
    }
}

impl<'a, 'r, C: Certificate<'r>> IntoIterator for &'a CertificatePath<'r, C> {
    type Item = &'a <C as Certificate<'r>>::NativeRef;
    type IntoIter = vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        let r: Vec<&<C as Certificate<'r>>::NativeRef> =
            self.path.iter().map(|c| c.as_ref()).collect();
        r.into_iter()
    }
}

impl<'r, C: Certificate<'r>> FromIterator<C> for CertificatePath<'r, C> {
    fn from_iter<T: IntoIterator<Item = C>>(iter: T) -> Self {
        Self {
            path: iter.into_iter().collect(),
            lifetime: PhantomData,
        }
    }
}
