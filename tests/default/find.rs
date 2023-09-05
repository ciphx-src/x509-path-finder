use rustls::{Certificate as RustlsCertificate, RootCertStore};
use std::time::Duration;
use x509_path_finder::report::CertificateOrigin;
use x509_path_finder::{X509PathFinder, X509PathFinderConfiguration};
use x509_path_finder_material::{load_certificates, load_material};

use x509_path_finder::provided::validator::default::DefaultPathValidator;

#[tokio::test]
async fn test_find() {
    let mut certificates = load_certificates("kim@id.vandelaybank.com-fullchain.pem")
        .await
        .unwrap();
    let expected = certificates.clone();
    let ee = certificates.remove(0);

    let root = load_material("vandelaybank.com.cer").await.unwrap();
    let root = RustlsCertificate(root);

    let mut store = RootCertStore::empty();
    store.add(&root).unwrap();
    let validator = DefaultPathValidator::new(store);

    let search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        aia: None,
        validator: &validator,
        certificates,
    });

    let found = search.find(ee).await.unwrap().found.unwrap();

    assert_eq!(expected, found.path);
    assert_eq!(
        vec![CertificateOrigin::Target, CertificateOrigin::Store],
        found.origin
    );
}
