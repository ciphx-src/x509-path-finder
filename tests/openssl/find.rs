use der::Encode;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyFlags;
use openssl::x509::X509;
use std::time::Duration;
use x509_path_finder::provided::validator::openssl::OpenSSLPathValidator;
use x509_path_finder::report::CertificateOrigin;
use x509_path_finder::{X509PathFinder, X509PathFinderConfiguration};
use x509_path_finder_material::generate::CertificatePathGenerator;

#[tokio::test]
async fn test_find() {
    let mut certificates = CertificatePathGenerator::generate(8, "0").unwrap();
    let root = certificates.remove(certificates.len() - 1);
    let expected = certificates.clone();
    let ee = certificates.remove(0);

    let root = X509::from_der(root.to_der().unwrap().as_slice()).unwrap();

    let mut builder = X509StoreBuilder::new().unwrap();
    builder.add_cert(root).unwrap();
    builder.set_flags(X509VerifyFlags::X509_STRICT).unwrap();
    let validator = OpenSSLPathValidator::new(builder.build());

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
