use crate::certificate::Certificate;
use crate::store::CertificateStore;
use std::rc::Rc;
use x509_path_finder_material::load_certificates;

#[tokio::test]
async fn test_ord() {
    let certificates = load_certificates("kim@id.vandelaybank.com-fullchain.pem")
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.into())
        .collect::<Vec<Certificate>>();
    let expected = certificates
        .clone()
        .into_iter()
        .map(|c| c.into())
        .collect::<Vec<Rc<Certificate>>>();

    let certificates2 = load_certificates("kim@id.vandelaybank.com.p7c")
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.into())
        .rev()
        .collect::<Vec<Certificate>>();

    let mut store = CertificateStore::from_iter(certificates.clone());
    store.insert(certificates[0].clone());
    store.insert(certificates[0].clone());
    store.insert(certificates[0].clone());
    store.insert(certificates[0].clone());
    store.insert(certificates[1].clone());
    store.insert(certificates[1].clone());
    store.insert(certificates[1].clone());

    store.insert(certificates2[0].clone());
    store.insert(certificates2[1].clone());

    assert_eq!(
        expected,
        store.into_iter().collect::<Vec<Rc<Certificate>>>()
    );

    let mut store = CertificateStore::new();
    store.insert(certificates[1].clone());
    store.insert(certificates[0].clone());
    store.insert(certificates2[0].clone());
    store.insert(certificates2[1].clone());

    assert_eq!(
        vec![expected[1].clone(), expected[0].clone()],
        store.into_iter().collect::<Vec<Rc<Certificate>>>()
    );
}

#[tokio::test]
async fn test_issuer() {
    let certificates = load_certificates("kim@id.vandelaybank.com-fullchain.pem")
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.into())
        .collect::<Vec<Certificate>>();

    let certificates2 = load_certificates("kim@id.vandelaybank.com.p7c")
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.into())
        .rev()
        .collect::<Vec<Certificate>>();

    let store = CertificateStore::from_iter(certificates.clone());
    assert_eq!(
        vec![Rc::new(certificates[1].clone())],
        store.issuers(&certificates[0])
    );
    assert_eq!(
        vec![Rc::new(certificates[1].clone())],
        store.issuers(&certificates2[0])
    );

    assert!(store.issuers(&certificates[1]).is_empty());
}
