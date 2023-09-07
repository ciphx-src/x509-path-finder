use crate::report::CertificateOrigin;
use crate::tests::test_validator::TestPathValidator;
use crate::{X509PathFinder, X509PathFinderConfiguration};
use std::time::Duration;
use x509_path_finder_material::generate::CertificatePathGenerator;

#[tokio::test]
async fn test_find() {
    let mut certificates = CertificatePathGenerator::generate(8, "0").unwrap();
    let root = certificates.remove(certificates.len() - 1);
    let expected = certificates.clone();
    let ee = certificates.remove(0);

    let validator = TestPathValidator::new(vec![root]);

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
