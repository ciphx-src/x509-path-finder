use der::Encode;
use rustls::{Certificate as RustlsCertificate, RootCertStore};
use x509_path_finder::api::{CertificatePathValidation, PathValidator};
use x509_path_finder::provided::validator::default::DefaultPathValidator;
use x509_path_finder_material::generate::CertificatePathGenerator;

#[test]
fn test_validator() {
    let mut certificates = CertificatePathGenerator::generate(8, "0").unwrap();
    let root = certificates.remove(certificates.len() - 1);
    let root = RustlsCertificate(root.to_der().unwrap());

    let mut store = RootCertStore::empty();
    store.add(&root).unwrap();

    let validator = DefaultPathValidator::new(store);
    let validate = validator.validate(certificates.iter().collect()).unwrap();
    assert!(matches!(validate, CertificatePathValidation::Found));
}
