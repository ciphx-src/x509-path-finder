use der::oid::db::rfc5280::{ID_AD_CA_ISSUERS, ID_PE_AUTHORITY_INFO_ACCESS};
use der::{Decode, DecodeValue, Encode, Header, Length, Reader, Writer};
use std::cmp::Ordering;
use url::Url;
use x509_cert::certificate::CertificateInner;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::AuthorityInfoAccessSyntax;
use x509_cert::Certificate as InnerCertificate;

#[derive(Clone, Debug)]
pub struct Certificate {
    inner: InnerCertificate,
    ord: usize,
}

impl Certificate {
    /// Returns true if `self` issued `subject`.
    pub fn issued(&self, subject: &Self) -> bool {
        self.inner.tbs_certificate.subject.to_string()
            == subject.inner.tbs_certificate.issuer.to_string()
    }

    /// Returns list of any URLs found in the [Authority Information Access](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1) extension.
    pub fn aia(&self) -> Vec<Url> {
        match &self.inner.tbs_certificate.extensions {
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

    pub fn set_ord(&mut self, ord: usize) {
        self.ord = ord;
    }
}

impl Encode for Certificate {
    fn encoded_len(&self) -> der::Result<Length> {
        self.inner.encoded_len()
    }

    fn encode(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.inner.encode(encoder)
    }
}

impl<'r> Decode<'r> for Certificate {
    fn decode<R: Reader<'r>>(reader: &mut R) -> der::Result<Self> {
        let header = Header::decode(reader)?;
        let inner = InnerCertificate::decode_value(reader, header)?;
        Ok(Self { inner, ord: 0 })
    }
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        self.inner.eq(&other.inner)
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

impl From<CertificateInner> for Certificate {
    fn from(inner: CertificateInner) -> Self {
        Self { inner, ord: 0 }
    }
}

impl From<Certificate> for CertificateInner {
    fn from(src: Certificate) -> Self {
        src.inner
    }
}
