use crate::api::{Certificate, TestCertificateInner};
use crate::provided::store::DefaultCertificateStore;
use crate::report::CertificateOrigin;
use crate::tests::validator::TestPathValidator;
use crate::{X509PathFinder, X509PathFinderConfiguration};
use std::sync::RwLock;
use std::time::Duration;

#[tokio::test]
async fn test_first_path_found_no_aia() {
    let store = DefaultCertificateStore::from_iter(build_certificates());

    let mut search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        aia: None,
        store: RwLock::new(store).into(),
        validator: TestPathValidator::new(vec![Certificate {
            inner: TestCertificateInner {
                issuer: 0,
                subject: 0,
                aia: vec![],
            },
            ord: 0,
        }]),
    });

    let report = search
        .find(Certificate {
            inner: TestCertificateInner {
                issuer: 3,
                subject: 4,
                aia: vec![],
            },
            ord: 0,
        })
        .await
        .unwrap();

    let path = report
        .path
        .unwrap()
        .into_iter()
        .collect::<Vec<Certificate>>();

    let expected_path = vec![
        Certificate {
            inner: TestCertificateInner {
                issuer: 3,
                subject: 4,
                aia: vec![],
            },
            ord: 0,
        },
        Certificate {
            inner: TestCertificateInner {
                issuer: 2,
                subject: 3,
                aia: vec![],
            },
            ord: 0,
        },
        Certificate {
            inner: TestCertificateInner {
                issuer: 1,
                subject: 2,
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
    ];

    assert_eq!(expected_path, path);
    assert_eq!(
        vec![
            CertificateOrigin::Find,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
            CertificateOrigin::Store,
        ],
        report.origin.unwrap()
    );
}

#[tokio::test]
async fn test_first_path_end_no_aia() {
    let store = DefaultCertificateStore::from_iter(build_certificates());

    let mut search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        aia: None,
        store: RwLock::new(store).into(),
        validator: TestPathValidator::new(vec![Certificate {
            inner: TestCertificateInner {
                issuer: 100,
                subject: 100,
                aia: vec![],
            },
            ord: 0,
        }]),
    });

    let report = search
        .find(Certificate {
            inner: TestCertificateInner {
                issuer: 3,
                subject: 4,
                aia: vec![],
            },
            ord: 0,
        })
        .await
        .unwrap();

    let path = report
        .path
        .unwrap()
        .into_iter()
        .collect::<Vec<Certificate>>();

    let expected_path = vec![
        Certificate {
            inner: TestCertificateInner {
                issuer: 3,
                subject: 4,
                aia: vec![],
            },
            ord: 0,
        },
        Certificate {
            inner: TestCertificateInner {
                issuer: 100,
                subject: 3,
                aia: vec![],
            },
            ord: 0,
        },
    ];

    assert_eq!(expected_path, path);
    assert_eq!(
        vec![CertificateOrigin::Find, CertificateOrigin::Store,],
        report.origin.unwrap()
    );
}

fn build_certificates() -> Vec<Certificate> {
    vec![
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
                issuer: 1,
                subject: 2,
                aia: vec![],
            },
            ord: 0,
        },
        Certificate {
            inner: TestCertificateInner {
                issuer: 2,
                subject: 3,
                aia: vec![],
            },
            ord: 0,
        },
        Certificate {
            inner: TestCertificateInner {
                issuer: 100,
                subject: 3,
                aia: vec![],
            },
            ord: 0,
        },
    ]
}

#[tokio::test]
async fn test_only_aia() {
    let store = DefaultCertificateStore::default();

    let root = Certificate {
        inner: TestCertificateInner {
            issuer: 0,
            subject: 0,
            aia: vec![],
        },
        ord: 0,
    };

    let c1 = Certificate {
        inner: TestCertificateInner {
            issuer: 0,
            subject: 1,
            aia: vec![],
        },
        ord: 0,
    };

    let mut c2 = Certificate {
        inner: TestCertificateInner {
            issuer: 1,
            subject: 2,
            aia: vec![],
        },
        ord: 0,
    };

    let mut c3 = Certificate {
        inner: TestCertificateInner {
            issuer: 2,
            subject: 3,
            aia: vec![],
        },
        ord: 0,
    };
    let mut c4 = Certificate {
        inner: TestCertificateInner {
            issuer: 3,
            subject: 4,
            aia: vec![],
        },
        ord: 0,
    };

    c2.inner.aia.push((&c1).try_into().unwrap());
    c3.inner.aia.push((&c2).try_into().unwrap());
    c4.inner.aia.push((&c3).try_into().unwrap());

    let mut search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        aia: Some(()),
        store: RwLock::new(store).into(),
        validator: TestPathValidator::new(vec![root]),
    });

    let report = search.find(c4.clone()).await.unwrap();

    let path = report
        .path
        .unwrap()
        .into_iter()
        .collect::<Vec<Certificate>>();

    assert_eq!(vec![c4.clone(), c3.clone(), c2.clone(), c1.clone()], path);
    assert_eq!(
        vec![
            CertificateOrigin::Find,
            CertificateOrigin::Url(c4.inner.aia[0].clone().into()),
            CertificateOrigin::Url(c3.inner.aia[0].clone().into()),
            CertificateOrigin::Url(c2.inner.aia[0].clone().into())
        ],
        report.origin.unwrap()
    );
}

#[tokio::test]
async fn test_bridge_aia() {
    let store = DefaultCertificateStore::default();

    let root = Certificate {
        inner: TestCertificateInner {
            issuer: 0,
            subject: 0,
            aia: vec![],
        },
        ord: 0,
    };

    let c1 = Certificate {
        inner: TestCertificateInner {
            issuer: 0,
            subject: 1,
            aia: vec![],
        },
        ord: 0,
    };

    let mut c2 = Certificate {
        inner: TestCertificateInner {
            issuer: 1,
            subject: 2,
            aia: vec![],
        },
        ord: 0,
    };

    let mut c3 = Certificate {
        inner: TestCertificateInner {
            issuer: 2,
            subject: 3,
            aia: vec![],
        },
        ord: 0,
    };

    let mut c4 = Certificate {
        inner: TestCertificateInner {
            issuer: 3,
            subject: 4,
            aia: vec![],
        },
        ord: 0,
    };

    c2.inner.aia.push((&c1).try_into().unwrap());
    c3.inner.aia.push((&c2).try_into().unwrap());
    c4.inner.aia.push((&c3).try_into().unwrap());

    let bridge_authority = Certificate {
        inner: TestCertificateInner {
            issuer: 100,
            subject: 100,
            aia: vec![],
        },
        ord: 0,
    };

    let bridge = Certificate {
        inner: TestCertificateInner {
            issuer: 100,
            subject: 3,
            aia: vec![],
        },
        ord: 0,
    };

    let mut search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Default::default(),
        aia: Some(()),
        store: RwLock::new(store).into(),
        validator: TestPathValidator::new(vec![root.clone()]),
    });

    let report = search.find(c4.clone()).await.unwrap();

    let path = report
        .path
        .unwrap()
        .into_iter()
        .collect::<Vec<Certificate>>();

    assert_eq!(vec![c4.clone(), c3.clone(), c2.clone(), c1.clone()], path);

    assert_eq!(
        vec![
            CertificateOrigin::Find,
            CertificateOrigin::Url(c4.inner.aia[0].clone().into()),
            CertificateOrigin::Url(c3.inner.aia[0].clone().into()),
            CertificateOrigin::Url(c2.inner.aia[0].clone().into())
        ],
        report.origin.unwrap()
    );

    let store = DefaultCertificateStore::from_iter(vec![bridge.clone()]);

    let mut search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Default::default(),
        aia: Some(()),
        store: RwLock::new(store).into(),
        validator: TestPathValidator::new(vec![bridge_authority]),
    });

    let report = search.find(c4.clone()).await.unwrap();

    let path = report
        .path
        .unwrap()
        .into_iter()
        .collect::<Vec<Certificate>>();

    assert_eq!(vec![c4, bridge], path);
    assert_eq!(
        vec![CertificateOrigin::Find, CertificateOrigin::Store],
        report.origin.unwrap()
    );
}
