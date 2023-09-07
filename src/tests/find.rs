use crate::report::CertificateOrigin;
use crate::tests::test_validator::TestPathValidator;
use crate::{X509PathFinder, X509PathFinderConfiguration};
use std::time::Duration;
use x509_path_finder_material::generate::CertificatePathGenerator;

#[tokio::test]
async fn test_self_signed() {
    let root = CertificatePathGenerator::generate(1, "0")
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    let validator = TestPathValidator::new(vec![root.clone()]);

    let search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        aia: None,
        validator: &validator,
        certificates: vec![root.clone()],
    });

    let report = search.find(root.clone()).await.unwrap();
    let found = report.found.unwrap();

    assert_eq!(0, report.failures.len());
    assert_eq!(vec![root], found.path);
    assert_eq!(vec![CertificateOrigin::Target,], found.origin);
}

#[tokio::test]
async fn test_direct_path_no_aia() {
    let mut certificates = CertificatePathGenerator::generate(8, "0").unwrap();
    let root = certificates.pop().unwrap();
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

    assert_eq!(0, report.failures.len());
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

#[tokio::test]
async fn test_cross_first_no_aia() {
    let mut authority1_certificates = CertificatePathGenerator::generate(8, "authority1").unwrap();
    let authority1_root = authority1_certificates.pop().unwrap();
    let authority1_ee = authority1_certificates[0].clone();
    let authority1_ic = authority1_certificates[1].clone();

    let (mut authority2_certificates, mut authority2_keys) =
        CertificatePathGenerator::generate_with_keys(1, "authority2").unwrap();
    let authority2_root = authority2_certificates.pop().unwrap();
    let authority2_root_key = authority2_keys.pop().unwrap();

    let cross =
        CertificatePathGenerator::cross(&authority2_root, &authority2_root_key, &authority1_ic)
            .unwrap();

    let mut cached_certificates_cross_first = vec![cross.clone()];
    cached_certificates_cross_first.extend(authority1_certificates.clone());

    let validator = TestPathValidator::new(vec![authority1_root, authority2_root]);

    let report = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        aia: None,
        validator: &validator,
        certificates: cached_certificates_cross_first,
    })
    .find(authority1_ee.clone())
    .await
    .unwrap();

    let found = report.found.unwrap();

    assert_eq!(0, report.failures.len());
    assert_eq!(vec![authority1_ee.clone(), cross], found.path);
    assert_eq!(
        vec![CertificateOrigin::Target, CertificateOrigin::Store,],
        found.origin
    );
}

#[tokio::test]
async fn test_cross_last_no_aia() {
    let mut authority1_certificates = CertificatePathGenerator::generate(8, "authority1").unwrap();
    let authority1_root = authority1_certificates.pop().unwrap();
    let authority1_ee = authority1_certificates[0].clone();
    let authority1_ic = authority1_certificates[1].clone();

    let (mut authority2_certificates, mut authority2_keys) =
        CertificatePathGenerator::generate_with_keys(1, "authority2").unwrap();
    let authority2_root = authority2_certificates.pop().unwrap();
    let authority2_root_key = authority2_keys.pop().unwrap();

    let cross =
        CertificatePathGenerator::cross(&authority2_root, &authority2_root_key, &authority1_ic)
            .unwrap();

    let mut cached_certificates_cross_last = authority1_certificates.clone();
    cached_certificates_cross_last.push(cross.clone());

    let validator = TestPathValidator::new(vec![authority1_root, authority2_root]);

    let report = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        aia: None,
        validator: &validator,
        certificates: cached_certificates_cross_last,
    })
    .find(authority1_ee.clone())
    .await
    .unwrap();

    let found = report.found.unwrap();

    assert_eq!(0, report.failures.len());
    assert_eq!(authority1_certificates, found.path);
    assert_eq!(
        vec![
            CertificateOrigin::Target,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store
        ],
        found.origin
    );
}

#[tokio::test]
async fn test_cross_first_dead_end_no_aia() {
    let mut authority1_certificates = CertificatePathGenerator::generate(8, "authority1").unwrap();
    let authority1_root = authority1_certificates.pop().unwrap();
    let authority1_ee = authority1_certificates[0].clone();
    let authority1_ic = authority1_certificates[1].clone();

    let (mut authority2_certificates, mut authority2_keys) =
        CertificatePathGenerator::generate_with_keys(1, "authority2").unwrap();
    let authority2_root = authority2_certificates.pop().unwrap();
    let authority2_root_key = authority2_keys.pop().unwrap();

    let cross =
        CertificatePathGenerator::cross(&authority2_root, &authority2_root_key, &authority1_ic)
            .unwrap();

    let mut cached_certificates_cross_first = vec![cross.clone()];
    cached_certificates_cross_first.extend(authority1_certificates.clone());

    let validator = TestPathValidator::new(vec![authority1_root]);

    let report = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        aia: None,
        validator: &validator,
        certificates: cached_certificates_cross_first,
    })
    .find(authority1_ee.clone())
    .await
    .unwrap();

    let found = report.found.unwrap();

    assert_eq!(1, report.failures.len());
    assert_eq!(authority1_certificates, found.path);
    assert_eq!(
        vec![
            CertificateOrigin::Target,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store
        ],
        found.origin
    );
}
