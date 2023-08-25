use crate::api::Certificate;
use std::convert::Infallible;
use std::iter;
use std::marker::PhantomData;
use x509_client::api::X509Iterator;
#[cfg(not(test))]
use x509_client::X509Client;

/// Configure optional AIA X509Client
#[cfg(not(test))]
#[derive(Clone)]
pub enum AIA<'r, X, C>
where
    X: X509Iterator<Item = C>,
    C: Certificate<'r>,
{
    /// No AIA, supply [`NoAIA::default()`](crate::NoAIA)
    None(X),
    /// Use AIA, supply X509Client with iterator
    Client(X509Client<X>),
    #[doc(hidden)]
    _Lifetime(Infallible, PhantomData<&'r X>),
}

#[cfg(test)]
#[derive(Clone)]
pub enum AIA<'r, X, C>
where
    X: X509Iterator<Item = C>,
    C: Certificate<'r>,
{
    None(X),
    Client(PhantomData<X>),
    _Lifetime(Infallible, PhantomData<&'r X>),
}

/// Disable AIA
#[derive(Clone)]
pub struct NoAIA<'r, C: Certificate<'r>>(PhantomData<&'r C>);

impl<'r, C: Certificate<'r>> Default for NoAIA<'r, C> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<'r, C: Certificate<'r>> IntoIterator for NoAIA<'r, C> {
    type Item = C;
    type IntoIter = iter::Empty<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        iter::empty()
    }
}

impl<'r, C: Certificate<'r>> FromIterator<<Self as IntoIterator>::Item> for NoAIA<'r, C> {
    fn from_iter<T: IntoIterator<Item = <Self as IntoIterator>::Item>>(_: T) -> Self {
        Self::default()
    }
}

impl<'r, C: Certificate<'r>> X509Iterator for NoAIA<'r, C> {
    type X509IteratorError = Infallible;

    fn from_cer<T: AsRef<[u8]>>(_: T) -> Result<Self, Self::X509IteratorError> {
        Ok(Self::default())
    }

    fn from_pem<T: AsRef<[u8]>>(_: T) -> Result<Self, Self::X509IteratorError> {
        Ok(Self::default())
    }

    fn from_pkcs7<T: AsRef<[u8]>>(_: T) -> Result<Self, Self::X509IteratorError> {
        Ok(Self::default())
    }
}
