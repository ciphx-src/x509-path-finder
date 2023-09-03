// use crate::api::{Certificate, TestCertificateInner};
// use crate::report::CertificateOrigin;
// use crate::tests::validator::TestPathValidator;
// use crate::{X509PathFinder, X509PathFinderConfiguration};
// use std::time::Duration;
//
// #[tokio::test]
// async fn test_first_path_found_no_aia() {
//     let mut search = X509PathFinder::start(
//         X509PathFinderConfiguration {
//             limit: Duration::default(),
//             aia: None,
//             validator: TestPathValidator::new(vec![Certificate {
//                 inner: TestCertificateInner {
//                     issuer: 0,
//                     subject: 0,
//                     aia: vec![],
//                 },
//                 ord: 0,
//             }]),
//         },
//         build_certificates(),
//     );
//
//     let report = search
//         .find(Certificate {
//             inner: TestCertificateInner {
//                 issuer: 3,
//                 subject: 4,
//                 aia: vec![],
//             },
//             ord: 0,
//         })
//         .await
//         .unwrap();
//
//     let found = report.found.unwrap();
//
//     let expected_path = vec![
//         Certificate {
//             inner: TestCertificateInner {
//                 issuer: 3,
//                 subject: 4,
//                 aia: vec![],
//             },
//             ord: 0,
//         },
//         Certificate {
//             inner: TestCertificateInner {
//                 issuer: 2,
//                 subject: 3,
//                 aia: vec![],
//             },
//             ord: 0,
//         },
//         Certificate {
//             inner: TestCertificateInner {
//                 issuer: 1,
//                 subject: 2,
//                 aia: vec![],
//             },
//             ord: 0,
//         },
//         Certificate {
//             inner: TestCertificateInner {
//                 issuer: 0,
//                 subject: 1,
//                 aia: vec![],
//             },
//             ord: 0,
//         },
//     ];
//
//     assert_eq!(expected_path, found.path);
//     assert_eq!(
//         vec![
//             CertificateOrigin::Target,
//             CertificateOrigin::Store,
//             CertificateOrigin::Store,
//             CertificateOrigin::Store,
//         ],
//         found.origin
//     );
// }
//
// #[tokio::test]
// async fn test_first_path_end_no_aia() {
//     let mut search = X509PathFinder::start(
//         X509PathFinderConfiguration {
//             limit: Duration::default(),
//             aia: None,
//             validator: TestPathValidator::new(vec![Certificate {
//                 inner: TestCertificateInner {
//                     issuer: 100,
//                     subject: 100,
//                     aia: vec![],
//                 },
//                 ord: 0,
//             }]),
//         },
//         build_certificates(),
//     );
//
//     let report = search
//         .find(Certificate {
//             inner: TestCertificateInner {
//                 issuer: 3,
//                 subject: 4,
//                 aia: vec![],
//             },
//             ord: 0,
//         })
//         .await
//         .unwrap();
//
//     let found = report.found.unwrap();
//
//     let expected_path = vec![
//         Certificate {
//             inner: TestCertificateInner {
//                 issuer: 3,
//                 subject: 4,
//                 aia: vec![],
//             },
//             ord: 0,
//         },
//         Certificate {
//             inner: TestCertificateInner {
//                 issuer: 100,
//                 subject: 3,
//                 aia: vec![],
//             },
//             ord: 0,
//         },
//     ];
//
//     assert_eq!(expected_path, found.path);
//     assert_eq!(
//         vec![CertificateOrigin::Target, CertificateOrigin::Store,],
//         found.origin
//     );
// }
//
// fn build_certificates() -> Vec<Certificate> {
//     vec![
//         Certificate {
//             inner: TestCertificateInner {
//                 issuer: 0,
//                 subject: 1,
//                 aia: vec![],
//             },
//             ord: 0,
//         },
//         Certificate {
//             inner: TestCertificateInner {
//                 issuer: 1,
//                 subject: 2,
//                 aia: vec![],
//             },
//             ord: 0,
//         },
//         Certificate {
//             inner: TestCertificateInner {
//                 issuer: 2,
//                 subject: 3,
//                 aia: vec![],
//             },
//             ord: 0,
//         },
//         Certificate {
//             inner: TestCertificateInner {
//                 issuer: 100,
//                 subject: 3,
//                 aia: vec![],
//             },
//             ord: 0,
//         },
//     ]
// }
//
// #[tokio::test]
// async fn test_only_aia() {
//     let root = Certificate {
//         inner: TestCertificateInner {
//             issuer: 0,
//             subject: 0,
//             aia: vec![],
//         },
//         ord: 0,
//     };
//
//     let c1 = Certificate {
//         inner: TestCertificateInner {
//             issuer: 0,
//             subject: 1,
//             aia: vec![],
//         },
//         ord: 0,
//     };
//
//     let mut c2 = Certificate {
//         inner: TestCertificateInner {
//             issuer: 1,
//             subject: 2,
//             aia: vec![],
//         },
//         ord: 0,
//     };
//
//     let mut c3 = Certificate {
//         inner: TestCertificateInner {
//             issuer: 2,
//             subject: 3,
//             aia: vec![],
//         },
//         ord: 0,
//     };
//     let mut c4 = Certificate {
//         inner: TestCertificateInner {
//             issuer: 3,
//             subject: 4,
//             aia: vec![],
//         },
//         ord: 0,
//     };
//
//     c2.inner.aia.push((&c1).try_into().unwrap());
//     c3.inner.aia.push((&c2).try_into().unwrap());
//     c4.inner.aia.push((&c3).try_into().unwrap());
//
//     let mut search = X509PathFinder::start(
//         X509PathFinderConfiguration {
//             limit: Duration::default(),
//             aia: Some(()),
//             validator: TestPathValidator::new(vec![root]),
//         },
//         vec![],
//     );
//
//     let report = search.find(c4.clone()).await.unwrap();
//
//     let found = report.found.unwrap();
//
//     assert_eq!(
//         vec![c4.clone(), c3.clone(), c2.clone(), c1.clone()],
//         found.path
//     );
//     assert_eq!(
//         vec![
//             CertificateOrigin::Target,
//             CertificateOrigin::Url(c4.inner.aia[0].clone().into()),
//             CertificateOrigin::Url(c3.inner.aia[0].clone().into()),
//             CertificateOrigin::Url(c2.inner.aia[0].clone().into())
//         ],
//         found.origin
//     );
// }
//
// #[tokio::test]
// async fn test_bridge_aia() {
//     let root = Certificate {
//         inner: TestCertificateInner {
//             issuer: 0,
//             subject: 0,
//             aia: vec![],
//         },
//         ord: 0,
//     };
//
//     let c1 = Certificate {
//         inner: TestCertificateInner {
//             issuer: 0,
//             subject: 1,
//             aia: vec![],
//         },
//         ord: 0,
//     };
//
//     let mut c2 = Certificate {
//         inner: TestCertificateInner {
//             issuer: 1,
//             subject: 2,
//             aia: vec![],
//         },
//         ord: 0,
//     };
//
//     let mut c3 = Certificate {
//         inner: TestCertificateInner {
//             issuer: 2,
//             subject: 3,
//             aia: vec![],
//         },
//         ord: 0,
//     };
//
//     let mut c4 = Certificate {
//         inner: TestCertificateInner {
//             issuer: 3,
//             subject: 4,
//             aia: vec![],
//         },
//         ord: 0,
//     };
//
//     c2.inner.aia.push((&c1).try_into().unwrap());
//     c3.inner.aia.push((&c2).try_into().unwrap());
//     c4.inner.aia.push((&c3).try_into().unwrap());
//
//     let bridge_authority = Certificate {
//         inner: TestCertificateInner {
//             issuer: 100,
//             subject: 100,
//             aia: vec![],
//         },
//         ord: 0,
//     };
//
//     let bridge = Certificate {
//         inner: TestCertificateInner {
//             issuer: 100,
//             subject: 3,
//             aia: vec![],
//         },
//         ord: 0,
//     };
//
//     let mut search = X509PathFinder::start(
//         X509PathFinderConfiguration {
//             limit: Default::default(),
//             aia: Some(()),
//             validator: TestPathValidator::new(vec![root.clone()]),
//         },
//         vec![],
//     );
//
//     let report = search.find(c4.clone()).await.unwrap();
//
//     let found = report.found.unwrap();
//
//     assert_eq!(
//         vec![c4.clone(), c3.clone(), c2.clone(), c1.clone()],
//         found.path
//     );
//
//     assert_eq!(
//         vec![
//             CertificateOrigin::Target,
//             CertificateOrigin::Url(c4.inner.aia[0].clone().into()),
//             CertificateOrigin::Url(c3.inner.aia[0].clone().into()),
//             CertificateOrigin::Url(c2.inner.aia[0].clone().into())
//         ],
//         found.origin
//     );
//
//     let mut search = X509PathFinder::start(
//         X509PathFinderConfiguration {
//             limit: Default::default(),
//             aia: Some(()),
//             validator: TestPathValidator::new(vec![bridge_authority]),
//         },
//         vec![bridge.clone()],
//     );
//
//     let report = search.find(c4.clone()).await.unwrap();
//
//     let found = report.found.unwrap();
//
//     assert_eq!(vec![c4, bridge], found.path);
//     assert_eq!(
//         vec![CertificateOrigin::Target, CertificateOrigin::Store],
//         found.origin
//     );
// }
