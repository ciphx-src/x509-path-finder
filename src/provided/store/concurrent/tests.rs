use crate::api::CertificateStore;
use crate::provided::store::concurrent::ConcurrentCertificateStore;
use crate::tests::test_certificate::certificate::{TestCertificate, TestCertificateNative};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tokio::{join, spawn};

#[tokio::test]
async fn test_send() {
    let mut store = ConcurrentCertificateStore::<TestCertificate>::default();

    spawn(async move {
        store
            .insert(TestCertificateNative {
                issuer: 0,
                subject: 0,
                aia: vec![],
            })
            .unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn test_concurrency() {
    let mut store = ConcurrentCertificateStore::<TestCertificate>::default();
    let mut store2 = store.clone();
    let store3 = store.clone();
    let store4 = store.clone();

    join!(
        async {
            store
                .insert(TestCertificateNative {
                    issuer: 0,
                    subject: 0,
                    aia: vec![],
                })
                .unwrap();
        },
        async {
            sleep(Duration::from_millis(10)).await;
            store2
                .insert(TestCertificateNative {
                    issuer: 100,
                    subject: 100,
                    aia: vec![],
                })
                .unwrap();
        },
    );

    assert_eq!(
        vec![
            Arc::new(TestCertificateNative {
                issuer: 0,
                subject: 0,
                aia: vec![],
            }),
            TestCertificateNative {
                issuer: 100,
                subject: 100,
                aia: vec![],
            }
            .into()
        ],
        store3.try_vec().unwrap()
    );

    drop(store);
    drop(store2);
    drop(store3);

    Arc::into_inner(store4.into_inner())
        .unwrap()
        .into_inner()
        .unwrap();
}
