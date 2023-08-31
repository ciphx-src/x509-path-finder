use crate::provided::certificate::default::DefaultCertificate;
use crate::provided::default_common::result::DefaultCertificateError;
use cms::cert::x509::der::asn1::SetOfVec;
use cms::cert::x509::der::{Decode, Encode};
use cms::cert::x509::Certificate as X509Certificate;
use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use std::vec;
use x509_client::api::X509Iterator;

/// Default [`X509Iterator`](x509_client::api::X509Iterator) implementation
pub struct DefaultCertificateIterator<'r> {
    data: Vec<DefaultCertificate<'r>>,
}

impl<'r> IntoIterator for DefaultCertificateIterator<'r> {
    type Item = DefaultCertificate<'r>;
    type IntoIter = vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl<'r> FromIterator<<Self as IntoIterator>::Item> for DefaultCertificateIterator<'r> {
    fn from_iter<T: IntoIterator<Item = <Self as IntoIterator>::Item>>(iter: T) -> Self {
        Self {
            data: iter.into_iter().collect(),
        }
    }
}

impl<'r> X509Iterator for DefaultCertificateIterator<'r> {
    type X509IteratorError = DefaultCertificateError;

    fn from_cer<T: AsRef<[u8]>>(src: T) -> Result<Self, Self::X509IteratorError> {
        Ok(Self {
            data: vec![X509Certificate::from_der(src.as_ref())?.into()],
        })
    }

    fn from_pem<T: AsRef<[u8]>>(src: T) -> Result<Self, Self::X509IteratorError> {
        Ok(Self {
            data: X509Certificate::load_pem_chain(src.as_ref())?
                .into_iter()
                .map(|c| c.into())
                .collect(),
        })
    }

    fn from_pkcs7<T: AsRef<[u8]>>(src: T) -> Result<Self, Self::X509IteratorError> {
        let ci = ContentInfo::from_der(src.as_ref())?;
        let sd = SignedData::from_der(ci.content.to_der()?.as_slice())?;

        Ok(Self {
            data: match sd.certificates {
                None => vec![],
                Some(certificates) => SetOfVec::from(certificates)
                    .into_vec()
                    .into_iter()
                    .filter_map(|c| {
                        if let CertificateChoices::Certificate(c) = c {
                            return Some(c.into());
                        }
                        None
                    })
                    .collect::<Vec<DefaultCertificate>>(),
            },
        })
    }
}
