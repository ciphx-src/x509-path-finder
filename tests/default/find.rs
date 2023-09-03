use rustls::{Certificate as RustlsCertificate, RootCertStore};
use std::time::Duration;
use x509_path_finder::report::CertificateOrigin;
use x509_path_finder::{X509PathFinder, X509PathFinderConfiguration};
use x509_path_finder_material::{load_certificates, load_material};

use x509_path_finder::provided::validator::default::DefaultPathValidator;

#[tokio::test]
async fn test_find() {
    let certificates = load_certificates("kim@id.vandelaybank.com-fullchain.pem")
        .await
        .unwrap();

    let root = load_material("vandelaybank.com.cer").await.unwrap();
    let root = RustlsCertificate(root);

    let mut store = RootCertStore::empty();
    store.add(&root).unwrap();
    let validator = DefaultPathValidator::new(store);

    let mut search = X509PathFinder::new(
        X509PathFinderConfiguration {
            limit: Duration::default(),
            aia: None,
            validator,
        },
        vec![certificates[1].clone()],
    );

    let found = search
        .find(certificates[0].clone())
        .await
        .unwrap()
        .found
        .unwrap();

    assert_eq!(2, found.path.len());
    assert_eq!(
        vec![CertificateOrigin::Target, CertificateOrigin::Store],
        found.origin
    );
}
