use crate::api::CertificateStore;
use crate::provided::store::default::DefaultCertificateStore;
use crate::tests::test_certificate::certificate::{TestCertificate, TestCertificateNative};
use std::sync::Arc;

#[test]
fn test_ord() {
    let mut store =
        DefaultCertificateStore::<TestCertificate>::from_iter(build_certificates().into_iter());

    store
        .insert(TestCertificateNative {
            issuer: 0,
            subject: 0,
            aia: vec![],
        })
        .unwrap();

    store
        .insert(TestCertificateNative {
            issuer: 200,
            subject: 200,
            aia: vec![],
        })
        .unwrap();

    store
        .insert(TestCertificateNative {
            issuer: 200,
            subject: 201,
            aia: vec![],
        })
        .unwrap();

    let mut expected = build_certificates();
    expected.append(&mut vec![
        TestCertificateNative {
            issuer: 200,
            subject: 200,
            aia: vec![],
        },
        TestCertificateNative {
            issuer: 200,
            subject: 201,
            aia: vec![],
        },
    ]);
    let expected = expected
        .into_iter()
        .map(|c| c.into())
        .collect::<Vec<Arc<TestCertificateNative>>>();

    assert_eq!(expected, store.try_vec().unwrap())
}

#[test]
fn test_issuers() {
    let store =
        DefaultCertificateStore::<TestCertificate>::from_iter(build_certificates().into_iter());

    assert_eq!(
        vec![TestCertificate::from(TestCertificateNative {
            issuer: 0,
            subject: 0,
            aia: vec![],
        })],
        store
            .issuers(&TestCertificate::from(TestCertificateNative {
                issuer: 0,
                subject: 1,
                aia: vec![],
            }))
            .unwrap()
    );

    assert_eq!(
        vec![
            TestCertificate::from(TestCertificateNative {
                issuer: 100,
                subject: 100,
                aia: vec![],
            }),
            TestCertificate::from(TestCertificateNative {
                issuer: 1000,
                subject: 100,
                aia: vec![],
            })
        ],
        store
            .issuers(&TestCertificate::from(TestCertificateNative {
                issuer: 100,
                subject: 101,
                aia: vec![],
            }))
            .unwrap()
    );
}

fn build_certificates() -> Vec<TestCertificateNative> {
    vec![
        TestCertificateNative {
            issuer: 0,
            subject: 0,
            aia: vec![],
        },
        TestCertificateNative {
            issuer: 0,
            subject: 1,
            aia: vec![],
        },
        TestCertificateNative {
            issuer: 0,
            subject: 2,
            aia: vec![],
        },
        TestCertificateNative {
            issuer: 100,
            subject: 100,
            aia: vec![],
        },
        TestCertificateNative {
            issuer: 100,
            subject: 101,
            aia: vec![],
        },
        TestCertificateNative {
            issuer: 100,
            subject: 102,
            aia: vec![],
        },
        TestCertificateNative {
            issuer: 1000,
            subject: 100,
            aia: vec![],
        },
    ]
}
