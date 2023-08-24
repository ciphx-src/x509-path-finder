use crate::api::Certificate;
use crate::tests::test_certificate::result::{TestCertificateError, TestCertificateResult};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::str::from_utf8;
use std::sync::Arc;
use url::Url;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestCertificate<'r> {
    src: TestCertificateSource<'r>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
enum TestCertificateSource<'r> {
    Owned(Arc<TestCertificateNative>),
    Ref(&'r TestCertificateNative),
}

impl<'r> AsRef<TestCertificateNative> for TestCertificateSource<'r> {
    fn as_ref(&self) -> &TestCertificateNative {
        match &self {
            Self::Owned(src) => src,
            Self::Ref(src) => src,
        }
    }
}

impl<'r> TryFrom<&[u8]> for TestCertificate<'r> {
    type Error = TestCertificateError;
    fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
        let url = from_utf8(src).map_err(|e| TestCertificateError::Error(e.to_string()))?;
        let url = Url::parse(url).map_err(|e| TestCertificateError::Error(e.to_string()))?;
        Ok(Self {
            src: TestCertificateSource::Owned(TestCertificateNative::try_from(&url)?.into()),
        })
    }
}

impl<'r> AsRef<<Self as Certificate<'r>>::NativeRef> for TestCertificate<'r> {
    fn as_ref(&self) -> &<Self as Certificate<'r>>::NativeRef {
        self.src.as_ref()
    }
}

impl<'r> From<&'r <Self as Certificate<'r>>::NativeRef> for TestCertificate<'r> {
    fn from(src: &'r <Self as Certificate<'r>>::NativeRef) -> Self {
        Self {
            src: TestCertificateSource::Ref(src),
        }
    }
}

impl<'r> From<<Self as Certificate<'r>>::Native> for TestCertificate<'r> {
    fn from(src: <Self as Certificate<'r>>::Native) -> Self {
        Self {
            src: TestCertificateSource::Owned(src.into()),
        }
    }
}

impl<'r> From<Arc<<Self as Certificate<'r>>::Native>> for TestCertificate<'r> {
    fn from(src: Arc<<Self as Certificate<'r>>::Native>) -> Self {
        Self {
            src: TestCertificateSource::Owned(src),
        }
    }
}

impl<'r> From<TestCertificate<'r>> for TestCertificateNative {
    fn from(src: TestCertificate<'r>) -> Self {
        match src.src {
            TestCertificateSource::Owned(src) => match Arc::try_unwrap(src) {
                Ok(src) => src,
                Err(src) => src.as_ref().clone(),
            },
            TestCertificateSource::Ref(src) => src.clone(),
        }
    }
}

impl<'r> From<TestCertificate<'r>> for Arc<TestCertificateNative> {
    fn from(src: TestCertificate<'r>) -> Self {
        match src.src {
            TestCertificateSource::Owned(src) => src,
            TestCertificateSource::Ref(src) => src.clone().into(),
        }
    }
}

impl<'r> Certificate<'r> for TestCertificate<'r> {
    type NativeRef = Self::Native;
    type Native = TestCertificateNative;
    type CertificateError = TestCertificateError;

    fn issued(&self, subject: &Self) -> TestCertificateResult<bool> {
        Ok(self.as_ref().subject == subject.as_ref().issuer)
    }

    fn aia(&self) -> Vec<Url> {
        self.as_ref().aia.clone()
    }

    fn der(&self) -> Result<Vec<u8>, Self::CertificateError> {
        let url = Url::try_from(self.as_ref())?;
        Ok(url.to_string().into_bytes())
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TestCertificateNative {
    pub issuer: usize,
    pub subject: usize,
    pub aia: Vec<Url>,
}

impl TestCertificateNative {
    pub fn issue(&self, mut src: Self) -> Self {
        src.issuer = self.subject;
        src
    }
}

impl TryFrom<&Url> for TestCertificateNative {
    type Error = TestCertificateError;

    fn try_from(url: &Url) -> TestCertificateResult<Self> {
        if url.scheme() != "certificate"
            || url
                .host()
                .ok_or_else(|| {
                    TestCertificateError::Error("invalid url: not a test certificate".to_string())
                })?
                .to_string()
                != "test"
        {
            return Err(TestCertificateError::Error(
                "invalid url: not a test certificate".to_string(),
            ));
        }
        let (_, src) = url.query_pairs().find(|(n, _)| n == "src").ok_or_else(|| {
            TestCertificateError::Error(
                "invalid url: test certificate missing src query parameter".to_string(),
            )
        })?;

        let src = general_purpose::URL_SAFE_NO_PAD
            .decode(src.as_ref())
            .map_err(|e| TestCertificateError::Error(e.to_string()))?;

        serde_json::from_slice(&src).map_err(|e| TestCertificateError::Error(e.to_string()))
    }
}

impl TryFrom<&TestCertificateNative> for Url {
    type Error = TestCertificateError;

    fn try_from(src: &TestCertificateNative) -> TestCertificateResult<Self> {
        let src =
            serde_json::to_string(src).map_err(|e| TestCertificateError::Error(e.to_string()))?;
        let src = general_purpose::URL_SAFE_NO_PAD.encode::<String>(src);
        Ok(Url::parse("certificate://test")
            .map_err(|e| TestCertificateError::Error(e.to_string()))?
            .query_pairs_mut()
            .append_pair("src", &src)
            .finish()
            .clone())
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::test_certificate::certificate::TestCertificateNative;
    use url::Url;

    #[test]
    fn test_serializer() {
        let src_certificate = TestCertificateNative {
            issuer: 0,
            subject: 1,
            aia: vec![(&TestCertificateNative {
                issuer: 0,
                subject: 0,
                aia: vec![],
            })
                .try_into()
                .unwrap()],
        };

        let certificate_as_url = Url::try_from(&src_certificate).unwrap();

        let certificate_from_url = TestCertificateNative::try_from(&certificate_as_url).unwrap();

        assert_eq!(src_certificate, certificate_from_url)
    }
}
