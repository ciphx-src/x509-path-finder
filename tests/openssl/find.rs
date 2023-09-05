use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyFlags;
use openssl::x509::X509;
use std::time::Duration;
use x509_path_finder::provided::validator::openssl::OpenSSLPathValidator;
use x509_path_finder::report::CertificateOrigin;
use x509_path_finder::{X509PathFinder, X509PathFinderConfiguration};
use x509_path_finder_material::{load_certificates, load_material};

#[tokio::test]
async fn test_find() {
    let mut certificates = load_certificates("kim@id.vandelaybank.com-fullchain.pem")
        .await
        .unwrap();
    let expected = certificates.clone();
    let ee = certificates.remove(0);

    let root = load_material("vandelaybank.com.cer").await.unwrap();
    let root = X509::from_der(&root).unwrap();

    let mut builder = X509StoreBuilder::new().unwrap();
    builder.add_cert(root).unwrap();
    builder.set_flags(X509VerifyFlags::X509_STRICT).unwrap();
    let validator = OpenSSLPathValidator::new(builder.build());

    let search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        aia: None,
        validator,
        certificates,
    });

    let found = search.find(ee).await.unwrap().found.unwrap();

    assert_eq!(expected, found.path);
    assert_eq!(
        vec![CertificateOrigin::Target, CertificateOrigin::Store],
        found.origin
    );
}
