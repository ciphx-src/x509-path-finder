use der::oid::db::rfc5280::{ID_AD_CA_ISSUERS, ID_PE_AUTHORITY_INFO_ACCESS};
use der::{Decode, DecodeValue, Encode, Header, Reader};
use std::cmp::Ordering;
use std::sync::Arc;
use url::Url;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::AuthorityInfoAccessSyntax;

#[derive(Clone, Debug)]
pub struct Certificate {
    inner: Arc<CertificateInner>,
    ord: usize,
}

#[derive(Debug)]
pub struct CertificateInner {
    issuer: String,
    subject: String,
    aia: Vec<Url>,
    der: Vec<u8>,
}

impl Certificate {
    pub fn issued(&self, subject: &Self) -> bool {
        self.inner.subject == subject.inner.issuer
    }
    pub fn aia(&self) -> &[Url] {
        self.inner.aia.as_slice()
    }

    fn parse_aia(certificate: &x509_cert::Certificate) -> Vec<Url> {
        match &certificate.tbs_certificate.extensions {
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

    pub fn der(&self) -> &[u8] {
        &self.inner.der
    }

    pub fn set_ord(&mut self, ord: usize) {
        self.ord = ord;
    }
}

impl<'r> Decode<'r> for Certificate {
    fn decode<R: Reader<'r>>(reader: &mut R) -> der::Result<Self> {
        let header = Header::decode(reader)?;
        let certificate = x509_cert::Certificate::decode_value(reader, header)?;
        Ok(Self {
            inner: CertificateInner {
                issuer: certificate.tbs_certificate.issuer.to_string(),
                subject: certificate.tbs_certificate.subject.to_string(),
                aia: Self::parse_aia(&certificate),
                der: certificate.to_der()?,
            }
            .into(),
            ord: 0,
        })
    }
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        self.inner.der.eq(&other.inner.der)
    }
}

impl Eq for Certificate {}

impl PartialOrd for Certificate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Certificate {
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
