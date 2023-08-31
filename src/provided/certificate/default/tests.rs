use crate::api::Certificate;
use crate::provided::certificate::default::{DefaultCertificate, DefaultCertificateIterator};
use crate::tests::material::load_material;
use url::Url;
use x509_client::api::X509Iterator;
use x509_client::provided::default::DefaultX509Iterator;

#[tokio::test]
async fn test_cer_iter() {
    let certificate_data = load_material("kim@id.vandelaybank.com.cer").await;
    let iter = DefaultCertificateIterator::from_cer(&certificate_data)
        .unwrap()
        .into_iter();
    assert_eq!(1, iter.len());
}

#[tokio::test]
async fn test_pem_iter() {
    let certificate_data = load_material("kim@id.vandelaybank.com.pem").await;
    let iter = DefaultCertificateIterator::from_pem(&certificate_data)
        .unwrap()
        .into_iter();
    assert_eq!(1, iter.len());

    let certificate_data = load_material("kim@id.vandelaybank.com-fullchain.pem").await;
    let iter = DefaultCertificateIterator::from_pem(&certificate_data)
        .unwrap()
        .into_iter();
    assert_eq!(2, iter.len());
}

#[tokio::test]
async fn test_pkcs7_iter() {
    let certificate_data = load_material("kim@id.vandelaybank.com.p7c").await;
    let iter = DefaultCertificateIterator::from_pkcs7(&certificate_data)
        .unwrap()
        .into_iter();
    assert_eq!(2, iter.len());
}

#[tokio::test]
async fn test_certificate_aia() {
    let certificate_data = load_material("kim@id.vandelaybank.com.cer").await;
    let certificate = DefaultCertificateIterator::from_cer(&certificate_data)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    assert_eq!(
        &vec![Url::parse(
            "https://identity.vandelaybank.com:4443/certificates/id.vandelaybank.com.cer"
        )
        .unwrap(),],
        &certificate.aia()
    );
}

#[tokio::test]
async fn test_certificate_issued() {
    let certificate_data = load_material("kim@id.vandelaybank.com.p7c").await;
    let certificates = DefaultX509Iterator::from_pkcs7(certificate_data)
        .unwrap()
        .into_iter()
        .rev()
        .map(|c| c.into())
        .collect::<Vec<DefaultCertificate>>();

    assert!(&certificates[1].issued(&certificates[0]).unwrap());
}
