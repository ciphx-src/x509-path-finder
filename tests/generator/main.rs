use der::Encode;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyFlags;
use openssl::x509::{X509StoreContext, X509};
use x509_path_finder_material::generate::CertificatePathGenerator;

#[test]
fn generate() {
    let mut certificates = CertificatePathGenerator::generate(10, "0").unwrap();
    let root = certificates.remove(certificates.len() - 1);
    let root = X509::from_der(root.to_der().unwrap().as_slice()).unwrap();

    let ee = certificates.remove(0);
    let ee = X509::from_der(ee.to_der().unwrap().as_slice()).unwrap();

    let mut builder = X509StoreBuilder::new().unwrap();
    builder.add_cert(root).unwrap();
    builder.set_flags(X509VerifyFlags::X509_STRICT).unwrap();
    let store = builder.build();

    let mut openssl_path = Stack::new().unwrap();
    for certificate in certificates {
        openssl_path
            .push(X509::from_der(&certificate.to_der().unwrap()).unwrap())
            .unwrap();
    }

    let mut context = X509StoreContext::new().unwrap();
    let verified = context
        .init(
            store.as_ref(),
            ee.as_ref(),
            openssl_path.as_ref(),
            |context| Ok(context.verify_cert().unwrap()),
        )
        .unwrap();
    assert!(verified);
}
