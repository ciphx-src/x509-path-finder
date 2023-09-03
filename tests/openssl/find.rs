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
    let certificates = load_certificates("kim@id.vandelaybank.com-fullchain.pem")
        .await
        .unwrap();

    let root = load_material("vandelaybank.com.cer").await.unwrap();
    let root = X509::from_der(&root).unwrap();

    let mut builder = X509StoreBuilder::new().unwrap();
    builder.add_cert(root).unwrap();
    builder.set_flags(X509VerifyFlags::X509_STRICT).unwrap();
    let validator = OpenSSLPathValidator::new(builder.build());

    let mut search = X509PathFinder::new(
        X509PathFinderConfiguration {
            limit: Duration::default(),
            aia: None,
            validator,
        },
        certificates.clone(),
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

    let found = search
        .find(certificates[1].clone())
        .await
        .unwrap()
        .found
        .unwrap();

    assert_eq!(1, found.path.len());
    assert_eq!(vec![CertificateOrigin::Target], found.origin);
}
