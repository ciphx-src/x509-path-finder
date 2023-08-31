use crate::api::Certificate;
use crate::api::{CertificatePathValidation, PathValidator};
use crate::provided::certificate::default::{DefaultCertificate, DefaultCertificateIterator};
use crate::provided::validator::default::DefaultPathValidator;
use crate::tests::material::load_material;
use rustls::{Certificate as RustlsCertificate, RootCertStore};
use x509_client::api::X509Iterator;

#[tokio::test]
async fn test_verifier() {
    let certificate_data = load_material("kim@id.vandelaybank.com.p7c").await;
    let certificates = DefaultCertificateIterator::from_pkcs7(&certificate_data)
        .unwrap()
        .into_iter()
        .rev()
        .collect::<Vec<DefaultCertificate>>();

    assert_eq!(2, certificates.len());
    assert!(&certificates[1].issued(&certificates[0]).unwrap());

    let root = load_material("vandelaybank.com.cer").await;
    let root = RustlsCertificate(root);

    let mut store = RootCertStore::empty();
    store.add(&root).unwrap();

    let verifier = DefaultPathValidator::new(store);
    let path = verifier.validate(certificates.clone()).unwrap();

    if let CertificatePathValidation::Found(path) = path {
        let path = path.into_iter();
        assert_eq!(2, path.len());
    } else {
        panic!("validate failed")
    }
}
