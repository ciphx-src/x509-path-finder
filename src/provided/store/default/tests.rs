use crate::api::{Certificate, CertificateStore};
use crate::provided::store::default::DefaultCertificateStore;
use crate::tests::material::load_certificates;
use std::iter::once;

#[tokio::test]
async fn test_ord() {
    let root = load_certificates("vandelaybank.com.cer")
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    let certificates = load_certificates("kim@id.vandelaybank.com.p7c")
        .await
        .unwrap();

    let mut expected = certificates.clone();
    expected.push(root.clone());

    let mut store = DefaultCertificateStore::from_iter(certificates);
    store.extend(once(root));

    assert_eq!(expected, store.into_iter().collect::<Vec<Certificate>>())
}

#[tokio::test]
async fn test_issuers() {
    let certificates = load_certificates("kim@id.vandelaybank.com-fullchain.pem")
        .await
        .unwrap();

    let store = DefaultCertificateStore::from_iter(certificates.clone());

    assert!(&certificates[1].issued(&certificates[0]));
    assert_eq!(vec![&certificates[1]], store.issuers(&certificates[0]))
}
