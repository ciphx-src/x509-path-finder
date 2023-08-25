use crate::api::Certificate;
use crate::api::{CertificatePathValidation, PathValidator, PathValidatorError};
use crate::report::{CertificatePath, ValidateFailure};
use crate::tests::test_certificate::certificate::TestCertificate;
use crate::X509PathFinderError;

pub struct TestPathValidator<'r> {
    roots: Vec<TestCertificate<'r>>,
}
impl<'r> TestPathValidator<'r> {
    pub fn new<I: Into<TestCertificate<'r>>>(roots: Vec<I>) -> Self {
        Self {
            roots: roots.into_iter().map(|c| c.into()).collect(),
        }
    }
}

impl<'r> PathValidator<'r> for TestPathValidator<'r> {
    type Certificate = TestCertificate<'r>;
    type PathValidatorError = X509PathFinderError;

    fn validate(
        &self,
        path: Vec<Self::Certificate>,
    ) -> Result<CertificatePathValidation<'r, Self::Certificate>, Self::PathValidatorError> {
        let leaf = match path.last() {
            None => {
                return Ok(CertificatePathValidation::NotFound(ValidateFailure {
                    path: CertificatePath::from_iter(path),
                    reason: "path is empty".to_string(),
                }))
            }
            Some(v) => v,
        };

        for root in &self.roots {
            if root.issued(leaf).unwrap() {
                return Ok(CertificatePathValidation::Found(
                    CertificatePath::from_iter(path),
                ));
            }
        }
        Ok(CertificatePathValidation::NotFound(ValidateFailure {
            path: CertificatePath::from_iter(path),
            reason: "could not find trusted path".to_string(),
        }))
    }
}

impl PathValidatorError for X509PathFinderError {}
