use crate::api::CertificateStore;
use crate::provided::store::DefaultCertificateStore;
use crate::provided::validator::openssl::OpenSSLPathValidator;
use crate::report::CertificateOrigin;
use crate::tests::material::load_material;
use crate::{NoAIA, X509PathFinder, X509PathFinderConfiguration, AIA};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyFlags;
use openssl::x509::X509;
use std::time::Duration;

#[tokio::test]
async fn test_find() {
    let certificate_data = load_material("resource.resources.ciph.xxx-fullchain.pem").await;
    let certificates = X509::stack_from_pem(&certificate_data).unwrap();

    let root = load_material("ciph.xxx.cer").await;
    let root = X509::from_der(&root).unwrap();

    let mut builder = X509StoreBuilder::new().unwrap();
    builder.add_cert(root).unwrap();
    builder.set_flags(X509VerifyFlags::X509_STRICT).unwrap();
    let validator = OpenSSLPathValidator::new(builder.build());

    let store = DefaultCertificateStore::from_iter(certificates.clone());

    let mut search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        aia: AIA::None(NoAIA::default()),
        store,
        validator,
    });

    let report = search.find(certificates[0].as_ref()).await.unwrap();

    let path = report.path.unwrap().into_iter().collect::<Vec<X509>>();

    assert_eq!(2, path.len());
    assert_eq!(
        vec![CertificateOrigin::Find, CertificateOrigin::Store],
        report.origin.unwrap()
    );

    let report = search.find(certificates[1].as_ref()).await.unwrap();

    let path = report.path.unwrap().into_iter().collect::<Vec<X509>>();

    assert_eq!(1, path.len());
    assert_eq!(vec![CertificateOrigin::Find], report.origin.unwrap());
}
