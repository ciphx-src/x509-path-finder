use crate::tests::test_certificate::certificate::TestCertificate;
use crate::tests::test_certificate::result::TestCertificateError;
use std::vec;
use x509_client::api::X509Iterator;

pub struct TestCertificateIterator<'r>(Option<TestCertificate<'r>>);

impl<'r> IntoIterator for TestCertificateIterator<'r> {
    type Item = TestCertificate<'r>;
    type IntoIter = vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0
            .map_or_else(std::vec::Vec::new, |c| vec![c])
            .into_iter()
    }
}

impl<'r> FromIterator<<Self as IntoIterator>::Item> for TestCertificateIterator<'r> {
    fn from_iter<T: IntoIterator<Item = <Self as IntoIterator>::Item>>(iter: T) -> Self {
        Self(iter.into_iter().next())
    }
}

impl<'r> X509Iterator for TestCertificateIterator<'r> {
    type X509IteratorError = TestCertificateError;

    fn from_cer<T: AsRef<[u8]>>(src: T) -> Result<Self, Self::X509IteratorError> {
        Ok(Self(Some(src.as_ref().try_into()?)))
    }

    fn from_pem<T: AsRef<[u8]>>(src: T) -> Result<Self, Self::X509IteratorError> {
        Ok(Self(Some(src.as_ref().try_into()?)))
    }

    fn from_pkcs7<T: AsRef<[u8]>>(src: T) -> Result<Self, Self::X509IteratorError> {
        Ok(Self(Some(src.as_ref().try_into()?)))
    }
}
