use crate::api::Certificate;
use crate::provided::default_common::result::DefaultCertificateError;
use cms::cert::x509::der::oid::db::rfc5280::{ID_AD_CA_ISSUERS, ID_PE_AUTHORITY_INFO_ACCESS};
use cms::cert::x509::der::{Decode, Encode};
use cms::cert::x509::ext::pkix::name::GeneralName;
use cms::cert::x509::ext::pkix::AuthorityInfoAccessSyntax;
use cms::cert::x509::Certificate as X509Certificate;
use std::sync::Arc;
use url::Url;

/// Default [`Certificate`](crate::api::Certificate) implementation
#[derive(Clone)]
pub struct DefaultCertificate<'r> {
    src: DefaultCertificateSource<'r>,
}

impl<'r> PartialEq for DefaultCertificate<'r> {
    fn eq(&self, other: &Self) -> bool {
        self.src.as_ref().eq(other.src.as_ref())
    }
}

impl<'r> Eq for DefaultCertificate<'r> {}

impl<'r> AsRef<X509Certificate> for DefaultCertificate<'r> {
    fn as_ref(&self) -> &X509Certificate {
        self.src.as_ref()
    }
}

impl<'r> From<DefaultCertificate<'r>> for X509Certificate {
    fn from(src: DefaultCertificate<'r>) -> Self {
        match src.src {
            DefaultCertificateSource::Ref(src) => src.to_owned(),
            DefaultCertificateSource::Arc(src) => match Arc::try_unwrap(src) {
                Ok(src) => src,
                Err(src) => src.as_ref().clone(),
            },
        }
    }
}

impl<'r> From<DefaultCertificate<'r>> for Arc<X509Certificate> {
    fn from(src: DefaultCertificate<'r>) -> Self {
        match src.src {
            DefaultCertificateSource::Ref(src) => src.to_owned().into(),
            DefaultCertificateSource::Arc(src) => src,
        }
    }
}

impl<'r> From<X509Certificate> for DefaultCertificate<'r> {
    fn from(src: X509Certificate) -> Self {
        Self {
            src: DefaultCertificateSource::Arc(src.into()),
        }
    }
}

impl<'r> From<Arc<X509Certificate>> for DefaultCertificate<'r> {
    fn from(src: Arc<X509Certificate>) -> Self {
        Self {
            src: DefaultCertificateSource::Arc(src),
        }
    }
}

impl<'r> From<&'r X509Certificate> for DefaultCertificate<'r> {
    fn from(src: &'r X509Certificate) -> Self {
        Self {
            src: DefaultCertificateSource::Ref(src),
        }
    }
}

impl<'r> Certificate<'r> for DefaultCertificate<'r> {
    type Native = X509Certificate;
    type NativeRef = Self::Native;
    type CertificateError = DefaultCertificateError;

    fn issued(&self, subject: &Self) -> Result<bool, Self::CertificateError> {
        Ok(self.as_ref().tbs_certificate.subject.to_string()
            == subject.as_ref().tbs_certificate.issuer.to_string())
    }

    fn aia(&self) -> Vec<Url> {
        match &self.as_ref().tbs_certificate.extensions {
            None => vec![],
            Some(extensions) => extensions
                .iter()
                .filter_map(|e| {
                    if e.extn_id == ID_PE_AUTHORITY_INFO_ACCESS {
                        AuthorityInfoAccessSyntax::from_der(e.extn_value.as_ref())
                            .map_or_else(|_| None, |i| Some(i.0))
                    } else {
                        None
                    }
                })
                .flatten()
                .filter_map(|i| {
                    if i.access_method == ID_AD_CA_ISSUERS {
                        if let GeneralName::UniformResourceIdentifier(uri) = i.access_location {
                            Url::parse(uri.as_str()).ok()
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect(),
        }
    }

    fn der(&self) -> Result<Vec<u8>, Self::CertificateError> {
        Ok(self.as_ref().to_der()?)
    }
}

#[derive(Clone)]
enum DefaultCertificateSource<'r> {
    Ref(&'r X509Certificate),
    Arc(Arc<X509Certificate>),
}

impl<'r> AsRef<X509Certificate> for DefaultCertificateSource<'r> {
    fn as_ref(&self) -> &X509Certificate {
        match self {
            Self::Ref(c) => c,
            Self::Arc(c) => c.as_ref(),
        }
    }
}
