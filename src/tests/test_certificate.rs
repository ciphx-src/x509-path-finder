use crate::{X509PathFinderError, X509PathFinderResult};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use url::Url;

#[derive(Clone, Debug)]
pub struct TestCertificate {
    pub inner: TestCertificateInner,
    ord: usize,
}

impl TestCertificate {
    pub fn issued(&self, subject: &Self) -> bool {
        self.inner.subject == subject.inner.issuer
    }

    pub fn aia(&self) -> Vec<Url> {
        self.inner.aia.clone()
    }

    pub fn set_ord(&mut self, ord: usize) {
        self.ord = ord;
    }
}

impl TryFrom<&Url> for TestCertificate {
    type Error = X509PathFinderError;

    fn try_from(url: &Url) -> Result<Self, Self::Error> {
        Ok(Self {
            inner: url.try_into()?,
            ord: 0,
        })
    }
}

impl TryFrom<&TestCertificate> for Url {
    type Error = X509PathFinderError;

    fn try_from(src: &TestCertificate) -> Result<Self, Self::Error> {
        (&src.inner).try_into()
    }
}

impl PartialEq for TestCertificate {
    fn eq(&self, other: &Self) -> bool {
        self.inner.eq(&other.inner)
    }
}

impl Eq for TestCertificate {}

impl PartialOrd for TestCertificate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TestCertificate {
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

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TestCertificateInner {
    pub issuer: usize,
    pub subject: usize,
    pub aia: Vec<Url>,
}

impl TryFrom<&Url> for TestCertificateInner {
    type Error = X509PathFinderError;

    fn try_from(url: &Url) -> X509PathFinderResult<Self> {
        if url.scheme() != "certificate"
            || url
                .host()
                .ok_or_else(|| {
                    X509PathFinderError::Error("invalid url: not a test certificate".to_string())
                })?
                .to_string()
                != "test"
        {
            return Err(X509PathFinderError::Error(
                "invalid url: not a test certificate".to_string(),
            ));
        }
        let (_, src) = url.query_pairs().find(|(n, _)| n == "src").ok_or_else(|| {
            X509PathFinderError::Error(
                "invalid url: test certificate missing src query parameter".to_string(),
            )
        })?;

        let src = general_purpose::URL_SAFE_NO_PAD
            .decode(src.as_ref())
            .map_err(|e| X509PathFinderError::Error(e.to_string()))?;

        serde_json::from_slice(&src).map_err(|e| X509PathFinderError::Error(e.to_string()))
    }
}

impl TryFrom<&TestCertificateInner> for Url {
    type Error = X509PathFinderError;

    fn try_from(src: &TestCertificateInner) -> X509PathFinderResult<Self> {
        let src =
            serde_json::to_string(src).map_err(|e| X509PathFinderError::Error(e.to_string()))?;
        let src = general_purpose::URL_SAFE_NO_PAD.encode::<String>(src);
        Ok(Url::parse("certificate://test")
            .map_err(|e| X509PathFinderError::Error(e.to_string()))?
            .query_pairs_mut()
            .append_pair("src", &src)
            .finish()
            .clone())
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::test_certificate::{TestCertificate, TestCertificateInner};
    use url::Url;

    #[test]
    fn test_serializer() {
        let src_certificate = TestCertificate {
            inner: TestCertificateInner {
                issuer: 0,
                subject: 1,
                aia: vec![(&TestCertificateInner {
                    issuer: 0,
                    subject: 0,
                    aia: vec![],
                })
                    .try_into()
                    .unwrap()],
            },
            ord: 0,
        };

        let certificate_as_url = Url::try_from(&src_certificate).unwrap();

        let certificate_from_url = TestCertificate::try_from(&certificate_as_url).unwrap();

        assert_eq!(src_certificate, certificate_from_url)
    }
}
