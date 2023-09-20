//! Default [`PathValidator`](crate::api::PathValidator) implementations

pub mod result;

use crate::api::{CertificatePathValidation, PathValidator, PathValidatorError};
use crate::provided::validator::default::result::DefaultPathValidatorError;
use der::Encode;
use std::time::SystemTime;
use webpki::{CertRevocationList, EndEntityCert, KeyUsage, SignatureAlgorithm, Time, TrustAnchor};

/// Default [`PathValidator`](crate::api::PathValidator)
pub struct DefaultPathValidator<'a> {
    algorithms: &'a [&'a SignatureAlgorithm],
    roots: Vec<TrustAnchor<'a>>,
    usage: KeyUsage,
    crls: &'a [&'a dyn CertRevocationList],
}

impl<'a> DefaultPathValidator<'a> {
    /// Constructor takes arguments from [`verify_for_usage()`](https://docs.rs/rustls-webpki/0.101.5/webpki/struct.EndEntityCert.html#method.verify_for_usage)
    /// * `algorithms` is the list of signature algorithms that are
    ///   trusted for use in certificate signatures; the end-entity certificate's
    ///   public key is not validated against this list.
    /// * `roots` is the list of root CAs to trust
    /// * `usage` is the intended usage of the certificate, indicating what kind
    ///   of usage we're verifying the certificate for.
    /// * `crls` is the list of certificate revocation lists to check
    ///   the certificate against.
    pub fn new(
        algorithms: &'a [&'a SignatureAlgorithm],
        roots: Vec<TrustAnchor<'a>>,
        usage: KeyUsage,
        crls: &'a [&'a dyn CertRevocationList],
    ) -> Self {
        Self {
            algorithms,
            roots,
            usage,
            crls,
        }
    }
}

impl<'a> PathValidator for DefaultPathValidator<'a> {
    type PathValidatorError = DefaultPathValidatorError;

    fn validate(
        &self,
        path: Vec<&crate::Certificate>,
    ) -> Result<CertificatePathValidation, Self::PathValidatorError> {
        if path.is_empty() {
            return Ok(CertificatePathValidation::NotFound(
                "path is empty".to_string(),
            ));
        }

        let ee = path[0].to_der()?;
        let ee = EndEntityCert::try_from(ee.as_slice())?;

        let mut der_path = vec![];
        for certificate in &path[1..] {
            der_path.push(certificate.to_der()?);
        }

        match ee.verify_for_usage(
            self.algorithms,
            self.roots.as_slice(),
            der_path
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<&[u8]>>()
                .as_slice(),
            Time::try_from(SystemTime::now())
                .map_err(|e| DefaultPathValidatorError::Error(e.to_string()))?,
            self.usage,
            self.crls,
        ) {
            Ok(_) => Ok(CertificatePathValidation::Found),

            Err(f) => Ok(CertificatePathValidation::NotFound(f.to_string())),
        }
    }
}
impl PathValidatorError for DefaultPathValidatorError {}
