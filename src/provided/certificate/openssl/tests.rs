use crate::api::Certificate;
use crate::provided::certificate::openssl::certificate::OpenSSLCertificate;
use crate::provided::certificate::openssl::iter::OpenSSLCertificateIterator;
use crate::tests::material::load_material;
use x509_client::api::X509Iterator;

#[tokio::test]
async fn test_cer_iter() {
    let certificate_data = load_material("resource.resources.ciph.xxx.cer").await;
    let iter = OpenSSLCertificateIterator::from_cer(&certificate_data)
        .unwrap()
        .into_iter();
    assert_eq!(1, iter.len());
}

#[tokio::test]
async fn test_pem_iter() {
    let certificate_data = load_material("resource.resources.ciph.xxx.pem").await;
    let iter = OpenSSLCertificateIterator::from_pem(&certificate_data)
        .unwrap()
        .into_iter();
    assert_eq!(1, iter.len());

    let certificate_data = load_material("resource.resources.ciph.xxx-fullchain.pem").await;
    let iter = OpenSSLCertificateIterator::from_pem(&certificate_data)
        .unwrap()
        .into_iter();
    assert_eq!(2, iter.len());

    let iter = OpenSSLCertificateIterator::from_pem(vec![])
        .unwrap()
        .into_iter();
    assert_eq!(0, iter.len());
}

#[tokio::test]
async fn test_pkcs7_iter() {
    let certificate_data = load_material("resource.resources.ciph.xxx.p7c").await;
    let iter = OpenSSLCertificateIterator::from_pkcs7(&certificate_data)
        .unwrap()
        .into_iter();
    assert_eq!(2, iter.len());
}

#[tokio::test]
async fn test_certificate_issued() {
    let certificate_data = load_material("resource.resources.ciph.xxx.p7c").await;
    let certificates = OpenSSLCertificateIterator::from_pkcs7(&certificate_data)
        .unwrap()
        .into_iter()
        .rev()
        .collect::<Vec<OpenSSLCertificate>>();

    assert!(&certificates[1].issued(&certificates[0]).unwrap());
}
