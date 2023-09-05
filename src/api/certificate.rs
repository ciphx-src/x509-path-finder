use der::oid::db::rfc5280::{ID_AD_CA_ISSUERS, ID_PE_AUTHORITY_INFO_ACCESS};
use der::{Decode, DecodeValue, Encode, Header, Length, Reader, Writer};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};
use url::Url;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::AuthorityInfoAccessSyntax;

#[derive(Clone, Debug)]
pub struct Certificate {
    inner: x509_cert::Certificate,
    issuer: String,
    subject: String,
    aia: Vec<Url>,
    ord: usize,
    hash: Vec<u8>,
}

impl Certificate {
    pub fn issued(&self, subject: &Self) -> bool {
        self.subject == subject.issuer
    }
    pub fn aia(&self) -> &[Url] {
        self.aia.as_slice()
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

    pub fn inner(&self) -> &x509_cert::Certificate {
        &self.inner
    }

    pub fn into_inner(self) -> x509_cert::Certificate {
        self.inner
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
        let inner = x509_cert::Certificate::decode_value(reader, header)?;
        Ok(inner.into())
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

impl Hash for Certificate {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash.hash(state)
    }
}

impl From<x509_cert::Certificate> for Certificate {
    fn from(inner: x509_cert::Certificate) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(inner.signature.raw_bytes());
        Self {
            issuer: inner.tbs_certificate.issuer.to_string(),
            subject: inner.tbs_certificate.subject.to_string(),
            aia: Self::parse_aia(&inner),
            inner,
            ord: 0,
            hash: hasher.finalize().to_vec(),
        }
    }
}
