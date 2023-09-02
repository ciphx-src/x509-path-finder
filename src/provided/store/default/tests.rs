use crate::api::{Certificate, CertificateStore, TestCertificateInner};
use crate::provided::store::default::DefaultCertificateStore;

#[test]
fn test_ord() {
    let mut store = DefaultCertificateStore::from_iter(build_certificates().into_iter());

    store.extend(vec![
        Certificate {
            inner: TestCertificateInner {
                issuer: 0,
                subject: 0,
                aia: vec![],
            },
            ord: 0,
        },
        Certificate {
            inner: TestCertificateInner {
                issuer: 200,
                subject: 200,
                aia: vec![],
            },
            ord: 0,
        },
        Certificate {
            inner: TestCertificateInner {
                issuer: 200,
                subject: 201,
                aia: vec![],
            },
            ord: 0,
        },
    ]);

    let mut expected = build_certificates();
    expected.append(&mut vec![
        Certificate {
            inner: TestCertificateInner {
                issuer: 200,
                subject: 200,
                aia: vec![],
            },
            ord: 0,
        },
        Certificate {
            inner: TestCertificateInner {
                issuer: 200,
                subject: 201,
                aia: vec![],
            },
            ord: 0,
        },
    ]);

    assert_eq!(expected, store.into_iter().collect::<Vec<Certificate>>())
}

#[test]
fn test_issuers() {
    let store = DefaultCertificateStore::from_iter(build_certificates().into_iter());

    assert_eq!(
        vec![&Certificate {
            inner: TestCertificateInner {
                issuer: 0,
                subject: 0,
                aia: vec![],
            },
            ord: 0,
        },],
        store.issuers(&Certificate {
            inner: TestCertificateInner {
                issuer: 0,
                subject: 1,
                aia: vec![],
            },
            ord: 0,
        })
    );

    assert_eq!(
        vec![
            &Certificate {
                inner: TestCertificateInner {
                    issuer: 100,
                    subject: 100,
                    aia: vec![],
                },
                ord: 0,
            },
            &Certificate {
                inner: TestCertificateInner {
                    issuer: 1000,
                    subject: 100,
                    aia: vec![],
                },
                ord: 0,
            },
        ],
        store.issuers(&Certificate {
            inner: TestCertificateInner {
                issuer: 100,
                subject: 101,
                aia: vec![],
            },
            ord: 0,
        })
    );
}

fn build_certificates() -> Vec<Certificate> {
    vec![
        Certificate {
            inner: TestCertificateInner {
                issuer: 0,
                subject: 0,
                aia: vec![],
            },
            ord: 0,
        },
        Certificate {
            inner: TestCertificateInner {
                issuer: 0,
                subject: 1,
                aia: vec![],
            },
            ord: 0,
        },
        Certificate {
            inner: TestCertificateInner {
                issuer: 0,
                subject: 2,
                aia: vec![],
            },
            ord: 0,
        },
        Certificate {
            inner: TestCertificateInner {
                issuer: 100,
                subject: 100,
                aia: vec![],
            },
            ord: 0,
        },
        Certificate {
            inner: TestCertificateInner {
                issuer: 100,
                subject: 101,
                aia: vec![],
            },
            ord: 0,
        },
        Certificate {
            inner: TestCertificateInner {
                issuer: 100,
                subject: 102,
                aia: vec![],
            },
            ord: 0,
        },
        Certificate {
            inner: TestCertificateInner {
                issuer: 1000,
                subject: 100,
                aia: vec![],
            },
            ord: 0,
        },
    ]
}
