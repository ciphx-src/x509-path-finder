use crate::api::{Certificate, CertificatePathValidation, PathValidator, PathValidatorError};
use crate::X509PathFinderError;
use der::Decode;

pub struct TestPathValidator {
    roots: Vec<Certificate>,
}
impl TestPathValidator {
    pub fn new<I: Into<Certificate>>(roots: Vec<I>) -> Self {
        Self {
            roots: roots.into_iter().map(|c| c.into()).collect(),
        }
    }
}

impl PathValidator for TestPathValidator {
    type PathValidatorError = X509PathFinderError;

    fn validate<C: AsRef<[u8]>>(
        &self,
        path: &[C],
    ) -> Result<CertificatePathValidation, Self::PathValidatorError> {
        if path.is_empty() {
            return Ok(CertificatePathValidation::NotFound(
                "path is empty".to_string(),
            ));
        }

        let ic = path.last().expect("path confirmed non empty").as_ref();
        let ic = Certificate::from_der(ic)
            .map_err(|e| Self::PathValidatorError::Error(e.to_string()))?;

        for root in &self.roots {
            if root.issued(&ic) {
                return Ok(CertificatePathValidation::Found);
            }
        }

        Ok(CertificatePathValidation::NotFound(
            "could not find trusted path".to_string(),
        ))
    }
}

impl PathValidatorError for X509PathFinderError {}
