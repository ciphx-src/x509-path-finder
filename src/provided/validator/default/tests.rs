use crate::api::{CertificatePathValidation, PathValidator};
use crate::provided::validator::default::DefaultPathValidator;
use crate::tests::material::load_certificates;
use crate::tests::material::load_material;
use rustls::{Certificate as RustlsCertificate, RootCertStore};

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
    let path = verifier.validate(certificates).unwrap();

    if let CertificatePathValidation::Found(path) = path {
        assert_eq!(2, path.len());
    } else {
        panic!("validate failed")
    }
}
