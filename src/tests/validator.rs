use crate::api::Certificate;
use crate::api::{CertificatePathValidation, PathValidator, PathValidatorError};
use crate::report::{CertificatePath, ValidateFailure};
use crate::X509PathFinderError;
use std::marker::PhantomData;

pub struct TestPathValidator<'r, C: Certificate<'r>> {
    roots: Vec<C>,
    lifetime: PhantomData<&'r C>,
}
impl<'r, C: Certificate<'r>> TestPathValidator<'r, C> {
    pub fn new<I: Into<C>>(roots: Vec<I>) -> Self {
        Self {
            roots: roots.into_iter().map(|c| c.into()).collect(),
            lifetime: PhantomData,
        }
    }
}

impl<'r, C: Certificate<'r>> PathValidator<'r> for TestPathValidator<'r, C> {
    type Certificate = C;
    type PathValidatorError = X509PathFinderError;

    fn validate(
        &self,
        path: Vec<C>,
    ) -> Result<CertificatePathValidation<'r, C>, Self::PathValidatorError> {
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
