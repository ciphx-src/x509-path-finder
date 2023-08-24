use crate::provided::certificate::openssl::certificate::OpenSSLCertificate;
use crate::provided::openssl_common::result::{OpenSSLError, OpenSSLResult};
use std::vec;
use x509_client::api::X509Iterator;
use x509_client::provided::openssl::OpenSSLX509Iterator;

/// OpenSSL [`X509Iterator`](x509_client::api::X509Iterator) implementation
pub struct OpenSSLCertificateIterator<'r> {
    data: Vec<OpenSSLCertificate<'r>>,
}

impl<'r> IntoIterator for OpenSSLCertificateIterator<'r> {
    type Item = OpenSSLCertificate<'r>;
    type IntoIter = vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl<'r> FromIterator<<Self as IntoIterator>::Item> for OpenSSLCertificateIterator<'r> {
    fn from_iter<T: IntoIterator<Item = <Self as IntoIterator>::Item>>(iter: T) -> Self {
        Self {
            data: iter.into_iter().collect(),
        }
    }
}

impl<'r> X509Iterator for OpenSSLCertificateIterator<'r> {
    type X509IteratorError = OpenSSLError;

    fn from_cer<T: AsRef<[u8]>>(src: T) -> OpenSSLResult<Self> {
        Ok(Self::from_iter(
            OpenSSLX509Iterator::from_cer(src)?
                .into_iter()
                .map(|c| c.into()),
        ))
    }

    fn from_pem<T: AsRef<[u8]>>(src: T) -> OpenSSLResult<Self> {
        Ok(Self {
            data: OpenSSLX509Iterator::from_pem(src)?
                .into_iter()
                .map(|c| c.into())
                .collect::<Vec<OpenSSLCertificate>>(),
        })
    }

    fn from_pkcs7<T: AsRef<[u8]>>(src: T) -> OpenSSLResult<Self> {
        Ok(Self {
            data: OpenSSLX509Iterator::from_pkcs7(src)?
                .into_iter()
                .map(|c| c.into())
                .collect::<Vec<OpenSSLCertificate>>(),
        })
    }
}
