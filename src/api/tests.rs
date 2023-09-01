use crate::tests::material::load_certificates;
use url::Url;

#[tokio::test]
async fn test_issuers() {
    let certificates = load_certificates("kim@id.vandelaybank.com-fullchain.pem")
        .await
        .unwrap();

    assert!(&certificates[1].issued(&certificates[0]));
}

#[tokio::test]
async fn test_aia() {
    let certificates = load_certificates("kim@id.vandelaybank.com.cer")
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    assert_eq!(
        vec![Url::parse(
            "https://identity.vandelaybank.com:4443/certificates/id.vandelaybank.com.cer"
        )
        .unwrap(),],
        certificates.aia()
    )
}
