use crate::api::{CertificatePathValidation, PathValidator};
use crate::provided::validator::default::result::DefaultPathValidatorError;
use x509_cert::Certificate;

pub struct TestPathValidator {
    store: Vec<Certificate>,
}
impl TestPathValidator {
    pub fn new(store: Vec<Certificate>) -> Self {
        Self { store }
    }
}

impl PathValidator for TestPathValidator {
    type PathValidatorError = DefaultPathValidatorError;

    fn validate(
        &self,
        path: Vec<&Certificate>,
    ) -> Result<CertificatePathValidation, Self::PathValidatorError> {
        if path.is_empty() {
            return Ok(CertificatePathValidation::NotFound(
                "path is empty".to_string(),
            ));
        }

        let ic = path.last().expect("path confirmed not empty");

        for root in self.store.iter() {
            if root.tbs_certificate.subject == ic.tbs_certificate.issuer {
                return Ok(CertificatePathValidation::Found);
            }
        }

        Ok(CertificatePathValidation::NotFound(
            "path not fond".to_string(),
        ))
    }
}
