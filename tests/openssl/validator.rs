use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyFlags;
use openssl::x509::X509;
use x509_path_finder::api::{CertificatePathValidation, PathValidator};
use x509_path_finder::provided::validator::openssl::OpenSSLPathValidator;
use x509_path_finder_material::{load_certificates, load_material};

#[tokio::test]
async fn test_validator() {
    let certificates = load_certificates("kim@id.vandelaybank.com-fullchain.pem")
        .await
        .unwrap();

    let root = load_material("vandelaybank.com.cer").await.unwrap();
    let root = X509::from_der(&root).unwrap();

    let mut builder = X509StoreBuilder::new().unwrap();
    builder.add_cert(root).unwrap();
    builder.set_flags(X509VerifyFlags::X509_STRICT).unwrap();

    let validator = OpenSSLPathValidator::new(builder.build());
    let validate = validator.validate(certificates.iter().collect()).unwrap();
    assert!(matches!(validate, CertificatePathValidation::Found));
}
