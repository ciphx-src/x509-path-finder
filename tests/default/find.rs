use der::Encode;
use rustls::{Certificate as RustlsCertificate, RootCertStore};
use std::time::Duration;
use x509_path_finder::report::CertificateOrigin;
use x509_path_finder::{X509PathFinder, X509PathFinderConfiguration};
use x509_path_finder_material::generate::CertificatePathGenerator;

use x509_path_finder::provided::validator::default::DefaultPathValidator;

#[tokio::test]
async fn test_find() {
    let mut certificates = CertificatePathGenerator::generate(8, "0").unwrap();
    let root = certificates.remove(certificates.len() - 1);
    let expected = certificates.clone();
    let ee = certificates.remove(0);

    let root = RustlsCertificate(root.to_der().unwrap());

    let mut store = RootCertStore::empty();
    store.add(&root).unwrap();
    let validator = DefaultPathValidator::new(store);

    let search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        aia: None,
        validator: &validator,
        certificates,
    });

    let report = search.find(ee).await.unwrap();
    let found = report.found.unwrap();

    assert_eq!(expected, found.path);
    assert_eq!(
        vec![
            CertificateOrigin::Target,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
        ],
        found.origin
    );
}
