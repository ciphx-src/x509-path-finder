use crate::api::Certificate;
use crate::provided::openssl_common::result::{OpenSSLError, OpenSSLResult};
use openssl::nid::Nid;
use openssl::x509::{AccessDescription, X509Ref, X509VerifyResult, X509};
use std::sync::Arc;
use url::Url;

/// OpenSSL [`Certificate`](crate::api::Certificate) implementation
#[derive(Clone)]
pub struct OpenSSLCertificate<'r> {
    src: OpenSSLCertificateSource<'r>,
}

impl<'r> PartialEq for OpenSSLCertificate<'r> {
    fn eq(&self, other: &Self) -> bool {
        self.src.as_ref().eq(other.src.as_ref())
    }
}

impl<'r> Eq for OpenSSLCertificate<'r> {}

impl<'r> AsRef<X509Ref> for OpenSSLCertificate<'r> {
    fn as_ref(&self) -> &X509Ref {
        self.src.as_ref()
    }
}

impl<'r> From<OpenSSLCertificate<'r>> for X509 {
    fn from(src: OpenSSLCertificate<'r>) -> Self {
        match src.src {
            OpenSSLCertificateSource::Ref(src) => src.to_owned(),
            OpenSSLCertificateSource::Arc(src) => match Arc::try_unwrap(src) {
                Ok(src) => src,
                Err(src) => src.as_ref().clone(),
            },
        }
    }
}

impl<'r> From<OpenSSLCertificate<'r>> for Arc<X509> {
    fn from(src: OpenSSLCertificate<'r>) -> Self {
        match src.src {
            OpenSSLCertificateSource::Ref(src) => src.to_owned().into(),
            OpenSSLCertificateSource::Arc(src) => src,
        }
    }
}

impl<'r> From<X509> for OpenSSLCertificate<'r> {
    fn from(src: X509) -> Self {
        Self {
            src: OpenSSLCertificateSource::Arc(src.into()),
        }
    }
}

impl<'r> From<Arc<X509>> for OpenSSLCertificate<'r> {
    fn from(src: Arc<X509>) -> Self {
        Self {
            src: OpenSSLCertificateSource::Arc(src),
        }
    }
}

impl<'r> From<&'r X509Ref> for OpenSSLCertificate<'r> {
    fn from(src: &'r X509Ref) -> Self {
        Self {
            src: OpenSSLCertificateSource::Ref(src),
        }
    }
}

impl<'r> From<&'r X509> for OpenSSLCertificate<'r> {
    fn from(src: &'r X509) -> Self {
        Self {
            src: OpenSSLCertificateSource::Ref(src),
        }
    }
}

impl<'r> Certificate<'r> for OpenSSLCertificate<'r> {
    type Native = X509;
    type NativeRef = X509Ref;
    type CertificateError = OpenSSLError;

    fn issued(&self, subject: &Self) -> OpenSSLResult<bool> {
        Ok(
            self.as_ref().issued(subject.as_ref()) == X509VerifyResult::OK
                && subject
                    .as_ref()
                    .verify(self.as_ref().public_key()?.as_ref())?,
        )
    }

    fn aia(&self) -> Vec<Url> {
        let aia: Vec<AccessDescription> = match self.as_ref().authority_info() {
            None => return vec![],
            Some(aia) => aia.into_iter().collect(),
        };

        aia.into_iter()
            .filter_map(|description| {
                if description.method().nid().eq(&Nid::AD_CA_ISSUERS) {
                    match description.location().uri() {
                        None => None,
                        Some(uri) => Url::parse(uri).ok(),
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    fn der(&self) -> Result<Vec<u8>, Self::CertificateError> {
        Ok(self.as_ref().to_der()?)
    }
}

#[derive(Clone)]
enum OpenSSLCertificateSource<'r> {
    Ref(&'r X509Ref),
    Arc(Arc<X509>),
}

impl<'r> AsRef<X509Ref> for OpenSSLCertificateSource<'r> {
    fn as_ref(&self) -> &X509Ref {
        match self {
            Self::Ref(c) => c,
            Self::Arc(c) => c.as_ref(),
        }
    }
}
