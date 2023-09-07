use der::Encode;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyFlags;
use openssl::x509::X509;
use x509_path_finder::api::{CertificatePathValidation, PathValidator};
use x509_path_finder::provided::validator::openssl::OpenSSLPathValidator;
use x509_path_finder_material::generate::CertificatePathGenerator;

#[test]
fn test_validator() {
    let mut certificates = CertificatePathGenerator::generate(8, "0").unwrap();
    let root = certificates.pop().unwrap();
    let root = X509::from_der(root.to_der().unwrap().as_slice()).unwrap();

    let mut builder = X509StoreBuilder::new().unwrap();
    builder.add_cert(root).unwrap();
    builder.set_flags(X509VerifyFlags::X509_STRICT).unwrap();

    let validator = OpenSSLPathValidator::new(builder.build());
    let validate = validator.validate(certificates.iter().collect()).unwrap();
    assert_eq!(CertificatePathValidation::Found, validate);
}
