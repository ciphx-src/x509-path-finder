use rustls::{Certificate as RustlsCertificate, RootCertStore};
use x509_path_finder::api::{CertificatePathValidation, PathValidator};
use x509_path_finder::provided::validator::default::DefaultPathValidator;
use x509_path_finder_material::{load_certificates, load_material};

#[tokio::test]
async fn test_verifier() {
    let certificates = load_certificates("kim@id.vandelaybank.com-fullchain.pem")
        .await
        .unwrap();

    assert_eq!(2, certificates.len());
    assert!(&certificates[1].issued(&certificates[0]));

    let root = load_material("vandelaybank.com.cer").await.unwrap();
    let root = RustlsCertificate(root);

    let mut store = RootCertStore::empty();
    store.add(&root).unwrap();

    let verifier = DefaultPathValidator::new(store);
    let validate = verifier.validate(certificates.as_slice()).unwrap();
    assert!(matches!(validate, CertificatePathValidation::Found));
}
