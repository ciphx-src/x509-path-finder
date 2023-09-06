use rustls::{Certificate as RustlsCertificate, RootCertStore};
use x509_path_finder::api::{CertificatePathValidation, PathValidator};
use x509_path_finder::provided::validator::default::DefaultPathValidator;
use x509_path_finder_material::{load_certificates, load_material};

#[tokio::test]
async fn test_validator() {
    let certificates = load_certificates("kim@id.vandelaybank.com-fullchain.pem")
        .await
        .unwrap();

    let root = load_material("vandelaybank.com.cer").await.unwrap();
    let root = RustlsCertificate(root);

    let mut store = RootCertStore::empty();
    store.add(&root).unwrap();

    let validator = DefaultPathValidator::new(store);
    let validate = validator.validate(certificates.iter().collect()).unwrap();
    assert!(matches!(validate, CertificatePathValidation::Found));
}
