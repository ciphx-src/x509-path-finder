use crate::certificate::Certificate;
use crate::store::CertificateStore;
use std::rc::Rc;
use x509_path_finder_material::generate::CertificatePathGenerator;

#[test]
fn test_ord() {
    let mut certificates = CertificatePathGenerator::generate(10, "issuers")
        .unwrap()
        .into_iter()
        .map(|c| c.into())
        .collect::<Vec<Certificate>>();
    certificates.remove(9);

    let expected = certificates
        .clone()
        .into_iter()
        .map(|c| c.into())
        .collect::<Vec<Rc<Certificate>>>();

    let mut store = CertificateStore::from_iter(certificates.clone());
    store.insert(certificates[0].clone());
    store.insert(certificates[0].clone());
    store.insert(certificates[0].clone());
    store.insert(certificates[0].clone());
    store.insert(certificates[1].clone());
    store.insert(certificates[1].clone());
    store.insert(certificates[1].clone());

    assert_eq!(
        expected,
        store.into_iter().collect::<Vec<Rc<Certificate>>>()
    );
}

#[test]
fn test_issuer() {
    let mut certificates = CertificatePathGenerator::generate(3, "issuers")
        .unwrap()
        .into_iter()
        .map(|c| c.into())
        .collect::<Vec<Certificate>>();
    certificates.remove(2);

    let store = CertificateStore::from_iter(certificates.clone());
    assert_eq!(
        vec![Rc::new(certificates[1].clone())],
        store.issuers(&certificates[0])
    );

    assert!(store.issuers(&certificates[1]).is_empty());
}
