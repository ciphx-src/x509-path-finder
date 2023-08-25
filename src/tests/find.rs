use crate::api::CertificateStore;
use crate::provided::store::DefaultCertificateStore;
use crate::report::CertificateOrigin;
use crate::tests::test_certificate::certificate::TestCertificateNative;
use crate::tests::test_certificate::iter::TestCertificateIterator;
use crate::tests::validator::TestPathValidator;
use crate::{NoAIA, X509PathFinder, X509PathFinderConfiguration, AIA};
use std::marker::PhantomData;
use std::time::Duration;

#[tokio::test]
async fn test_first_path_found_no_aia() {
    let store = DefaultCertificateStore::from_iter(build_certificates());

    let mut search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        aia: AIA::None(NoAIA::default()),
        store,
        validator: TestPathValidator::new(vec![TestCertificateNative {
            issuer: 0,
            subject: 0,
            aia: vec![],
        }]),
    });

    let report = search
        .find(TestCertificateNative {
            issuer: 3,
            subject: 4,
            aia: vec![],
        })
        .await
        .unwrap();

    let path = report
        .path
        .unwrap()
        .into_iter()
        .collect::<Vec<TestCertificateNative>>();

    let expected_path = vec![
        TestCertificateNative {
            issuer: 3,
            subject: 4,
            aia: vec![],
        },
        TestCertificateNative {
            issuer: 2,
            subject: 3,
            aia: vec![],
        },
        TestCertificateNative {
            issuer: 1,
            subject: 2,
            aia: vec![],
        },
        TestCertificateNative {
            issuer: 0,
            subject: 1,
            aia: vec![],
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

    let validator = TestPathValidator::new(vec![TestCertificateNative {
        issuer: 100,
        subject: 100,
        aia: vec![],
    }]);

    let mut search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        aia: AIA::None(NoAIA::default()),
        store,
        validator,
    });

    let report = search
        .find(TestCertificateNative {
            issuer: 3,
            subject: 4,
            aia: vec![],
        })
        .await
        .unwrap();

    let path = report
        .path
        .unwrap()
        .into_iter()
        .collect::<Vec<TestCertificateNative>>();

    let expected_path = vec![
        TestCertificateNative {
            issuer: 3,
            subject: 4,
            aia: vec![],
        },
        TestCertificateNative {
            issuer: 100,
            subject: 3,
            aia: vec![],
        },
    ];

    assert_eq!(expected_path, path);
    assert_eq!(
        vec![CertificateOrigin::Find, CertificateOrigin::Store,],
        report.origin.unwrap()
    );
}

fn build_certificates() -> Vec<TestCertificateNative> {
    vec![
        TestCertificateNative {
            issuer: 0,
            subject: 1,
            aia: vec![],
        },
        TestCertificateNative {
            issuer: 1,
            subject: 2,
            aia: vec![],
        },
        TestCertificateNative {
            issuer: 2,
            subject: 3,
            aia: vec![],
        },
        TestCertificateNative {
            issuer: 100,
            subject: 3,
            aia: vec![],
        },
    ]
}

#[tokio::test]
async fn test_only_aia() {
    let store = DefaultCertificateStore::default();

    let root = TestCertificateNative {
        issuer: 0,
        subject: 0,
        aia: vec![],
    };

    let c1 = TestCertificateNative {
        issuer: 0,
        subject: 1,
        aia: vec![],
    };

    let mut c2 = TestCertificateNative {
        issuer: 1,
        subject: 2,
        aia: vec![],
    };
    let mut c3 = TestCertificateNative {
        issuer: 2,
        subject: 3,
        aia: vec![],
    };
    let mut c4 = TestCertificateNative {
        issuer: 3,
        subject: 4,
        aia: vec![],
    };

    c2.aia.push((&c1).try_into().unwrap());
    c3.aia.push((&c2).try_into().unwrap());
    c4.aia.push((&c3).try_into().unwrap());

    let mut search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        aia: AIA::Client(PhantomData::<TestCertificateIterator>),
        store,
        validator: TestPathValidator::new(vec![&root]),
    });

    let report = search.find(&c4).await.unwrap();

    let path = report
        .path
        .unwrap()
        .into_iter()
        .collect::<Vec<TestCertificateNative>>();

    assert_eq!(vec![c4.clone(), c3.clone(), c2.clone(), c1.clone()], path);
    assert_eq!(
        vec![
            CertificateOrigin::Find,
            CertificateOrigin::Url(c4.aia[0].clone().into()),
            CertificateOrigin::Url(c3.aia[0].clone().into()),
            CertificateOrigin::Url(c2.aia[0].clone().into())
        ],
        report.origin.unwrap()
    );
}

#[tokio::test]
async fn test_bridge_aia() {
    let store = DefaultCertificateStore::default();

    let root = TestCertificateNative {
        issuer: 0,
        subject: 0,
        aia: vec![],
    };

    let c1 = TestCertificateNative {
        issuer: 0,
        subject: 1,
        aia: vec![],
    };

    let mut c2 = TestCertificateNative {
        issuer: 1,
        subject: 2,
        aia: vec![],
    };
    let mut c3 = TestCertificateNative {
        issuer: 2,
        subject: 3,
        aia: vec![],
    };
    let mut c4 = TestCertificateNative {
        issuer: 3,
        subject: 4,
        aia: vec![],
    };

    c2.aia.push((&c1).try_into().unwrap());
    c3.aia.push((&c2).try_into().unwrap());
    c4.aia.push((&c3).try_into().unwrap());

    let bridge_authority = TestCertificateNative {
        issuer: 100,
        subject: 100,
        aia: vec![],
    };

    let bridge = TestCertificateNative {
        issuer: 100,
        subject: 3,
        aia: vec![],
    };

    let mut search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Default::default(),
        aia: AIA::Client(PhantomData::<TestCertificateIterator>),
        store: store.clone(),
        validator: TestPathValidator::new(vec![root.clone()]),
    });

    let report = search.find(c4.clone()).await.unwrap();

    let path = report
        .path
        .unwrap()
        .into_iter()
        .collect::<Vec<TestCertificateNative>>();

    assert_eq!(vec![c4.clone(), c3.clone(), c2.clone(), c1.clone()], path);

    assert_eq!(
        vec![
            CertificateOrigin::Find,
            CertificateOrigin::Url(c4.aia[0].clone().into()),
            CertificateOrigin::Url(c3.aia[0].clone().into()),
            CertificateOrigin::Url(c2.aia[0].clone().into())
        ],
        report.origin.unwrap()
    );

    let store = DefaultCertificateStore::from_iter(vec![bridge.clone()]);

    let mut search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Default::default(),
        aia: AIA::Client(PhantomData::<TestCertificateIterator>),
        store: store.clone(),
        validator: TestPathValidator::new(vec![bridge_authority]),
    });

    let report = search.find(c4.clone()).await.unwrap();

    let path = report
        .path
        .unwrap()
        .into_iter()
        .collect::<Vec<TestCertificateNative>>();

    assert_eq!(vec![c4, bridge], path);
    assert_eq!(
        vec![CertificateOrigin::Find, CertificateOrigin::Store],
        report.origin.unwrap()
    );
}
