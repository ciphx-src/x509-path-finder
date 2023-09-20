use der::Encode;
use webpki::{KeyUsage, TrustAnchor};
use x509_path_finder::api::{CertificatePathValidation, PathValidator};
use x509_path_finder::provided::validator::default::DefaultPathValidator;
use x509_path_finder_material::generate::CertificatePathGenerator;

#[test]
fn test_validator() {
    let mut certificates = CertificatePathGenerator::generate(8, "0").unwrap();
    let root = certificates.pop().unwrap().to_der().unwrap();
    let root = TrustAnchor::try_from_cert_der(root.as_slice()).unwrap();

    let algorithms = &[&webpki::ECDSA_P256_SHA256];

    let validator = DefaultPathValidator::new(algorithms, vec![root], KeyUsage::client_auth(), &[]);
    let validate = validator.validate(certificates.iter().collect()).unwrap();
    assert_eq!(CertificatePathValidation::Found, validate);
}
