use crate::api::CertificateStore;
use crate::provided::store::DefaultCertificateStore;
use crate::report::CertificateOrigin;
use crate::tests::material::load_material;
use crate::{NoAIA, X509PathFinder, X509PathFinderConfiguration, AIA};
use rustls::{Certificate as RustlsCertificate, RootCertStore};
use std::time::Duration;
use x509_cert::Certificate;

use crate::provided::validator::default::DefaultPathValidator;

#[tokio::test]
async fn test_find() {
    let certificate_data = load_material("kim@id.vandelaybank.com-fullchain.pem").await;
    let certificates = Certificate::load_pem_chain(&certificate_data).unwrap();

    let root = load_material("vandelaybank.com.cer").await;
    let root = RustlsCertificate(root);

    let mut store = RootCertStore::empty();
    store.add(&root).unwrap();
    let validator = DefaultPathValidator::new(store);

    let mut store = DefaultCertificateStore::new();
    store.insert(certificates[1].clone()).unwrap();

    let mut search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        aia: AIA::None(NoAIA::default()),
        store,
        validator,
    });

    let report = search.find(&certificates[0]).await.unwrap();

    let path = report
        .path
        .unwrap()
        .into_iter()
        .collect::<Vec<Certificate>>();

    assert_eq!(2, path.len());
    assert_eq!(
        vec![CertificateOrigin::Find, CertificateOrigin::Store],
        report.origin.unwrap()
    );
}
