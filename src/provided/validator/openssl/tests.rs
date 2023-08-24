use crate::api::Certificate;
use crate::api::{CertificatePathValidation, PathValidator};
use crate::provided::certificate::openssl::OpenSSLCertificate;
use crate::provided::certificate::openssl::OpenSSLCertificateIterator;
use crate::provided::validator::openssl::OpenSSLPathValidator;
use crate::tests::material::load_material;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyFlags;
use openssl::x509::X509;
use x509_client::api::X509Iterator;

#[tokio::test]
async fn test_verifier() {
    let certificate_data = load_material("resource.resources.ciph.xxx.p7c").await;
    let certificates = OpenSSLCertificateIterator::from_pkcs7(&certificate_data)
        .unwrap()
        .into_iter()
        .rev()
        .collect::<Vec<OpenSSLCertificate>>();

    assert_eq!(2, certificates.len());
    assert!(&certificates[1].issued(&certificates[0]).unwrap());

    let root = load_material("ciph.xxx.cer").await;
    let root = X509::from_der(&root).unwrap();

    let mut builder = X509StoreBuilder::new().unwrap();
    builder.add_cert(root).unwrap();
    builder.set_flags(X509VerifyFlags::X509_STRICT).unwrap();

    let verifier = OpenSSLPathValidator::new(builder.build());
    let path = verifier.validate(certificates.clone()).unwrap();

    if let CertificatePathValidation::Found(path) = path {
        let path = path.into_iter().collect::<Vec<X509>>();
        assert_eq!(2, path.len());
    } else {
        panic!("validate failed")
    }
}
