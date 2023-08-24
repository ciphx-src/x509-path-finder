# X509 Path Finder

X509 Path Finder is a depth-first search certificate path validator for Rust.

![CI Status](https://github.com/merlincinematic/x509-path-finder/actions/workflows/ci.yaml/badge.svg)

## Synopsis

X509 Path Finder rejects the notion of a single "certificate chain." Instead, it searches for the first match out of infinity. Once it finds a path it can validate, the search halts and the path is returned to the caller.

The complexity of the path search is constrained by three factors:

1. Number of certificates preloaded into its local store
2. Number of certificates it can find and download by following [AIA](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1) URLs
3. An arbitrary time limit

When evaluating a path candidate for validation, X509 Path Finder is implementation-agnostic. Once it finds a path that has terminated, it presents it to be validated by a backend authority. If the authority validates the path, the search halts.

Validators can be implemented with one method. To get users started, X509 Path Finder ships with an OpenSSL [validator](crate::provided::validator::openssl::OpenSSLPathValidator).

## Usage

By default, you'll need to implement your own [PathValidator](crate::api::PathValidator).

````text
[dependencies]
x509_path_finder = { version = "0.2"] }
````

Or, enable the `openssl` feature for access to the provided [OpenSSLPathValidator](crate::provided::validator::openssl::OpenSSLPathValidator) validator.

````text
[dependencies]
x509_path_finder = { version = "0.2", features = ["openssl"] }
````


### Example

```` rust
use x509_path_finder::api::CertificateStore;
use x509_path_finder::provided::certificate::openssl::OpenSSLCertificateIterator;
use x509_path_finder::provided::store::DefaultCertificateStore;
use x509_path_finder::provided::validator::openssl::OpenSSLPathValidator;
use x509_path_finder::report::CertificateOrigin;
use x509_path_finder::{X509ClientType, X509PathFinder, X509PathFinderConfiguration};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyFlags;
use openssl::x509::X509;
use std::marker::PhantomData;
use std::time::Duration;

#[tokio::test]
async fn test() { 
    // load certificates with OpenSSL
    let certificates = X509::stack_from_pem(load_certificate())?;
    let root = X509::from_der(load_root())?;

    // create store, load in certificates
    let store = DefaultCertificateStore::from_iter(certificates);
    
    // create OpenSSL store
    let mut builder = X509StoreBuilder::new()?;
    builder.add_cert(root)?;
    builder.set_flags(X509VerifyFlags::X509_STRICT)?;
    
    // Instantiate validator with OpenSSL store
    let validator = OpenSSLPathValidator::new(builder.build());
    
    // Instantiate finder with store and validator
    let mut finder = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        client: X509ClientType::None(PhantomData::<OpenSSLCertificateIterator>),
        store,
        validator,
    });
    
    // Find a path, starting with first certificate
    let report = finder.find(certificates[0].as_ref()).await?;
    let path = report.path?.into_iter().collect::<Vec<X509>>();
    assert_eq!(2, path.len());

    // Find a path, starting with second certificate
    let report = search.find(certificates[1].as_ref()).await?;
    let path = report.path?.into_iter().collect::<Vec<X509>>();
    assert_eq!(1, path.len());
}


````

### Configuration


The  [`X509PathFinderConfiguration`](crate::X509PathFinderConfiguration) struct has the following fields.

* `limit`: limit runtime of path search. Actual limit will be N * HTTP timeout. See `Reqwest` docs for setting HTTP connection timeout.
* `client`: Optional client to find additional certificates by parsing URLs from [Authority Information Access](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1) extensions
* `store` - [`CertificateStore`](crate::api::CertificateStore) implementation
* `validator`: [`PathValidator`](crate::api::PathValidator) implementation

### Finding Paths

Call [`X509PathFinder::find`](crate::X509PathFinder::find) to start the search.

The returning [`Report`](crate::report::Report) contains the following fields:

* `path`: on validate success, `Option::Some` holds [`CertificatePath`](crate::report::CertificatePath) iterator.
* `origin`: on validate success, `Option::Some` holds a list of [`CertificateOrigin`](crate::report::CertificateOrigin) values
* `duration`: duration of path search 
* `failures`: any validation failures reported by [`PathValidator`](crate::api::PathValidator) implementation are held in [`ValidateFailure`](crate::report::ValidateFailure)

#### CertificatePath
[`CertificatePath`](crate::report::CertificatePath) is an iterator over a list of certificates.

#### CertificateOrigin
[`CertificateOrigin`](crate::report::CertificateOrigin) is an enum that describes the origin of each certificate. Can be one of:

1. `Find`: the initial certificate when calling [`X509PathFinder::find`](crate::X509PathFinder::find).
2. `Store`: certificate was found in the store
3. `Url`: certificate was downloaded from a URL (AIA)

#### ValidateFailure

[`ValidateFailure`](crate::report::ValidateFailure) stores any validation failures. Validation failures can occur even though a valid certificate path was eventually found. `ValidateFailure` contains the following fields:

1. `path`: the [`CertificatePath`](crate::report::CertificatePath) of where the validation error occurred
2. `reason`: human-readable reason for the failure

## API

X509 Path Finder can be extended with three traits:

* [`Certificate`](crate::api::Certificate) - model-agnostic representation of an X509 certificate. Implement this trait to add more certificates models
* [`CertificateStore`](crate::api::CertificateStore) - certificate store API. Implement this trait to make stores with different persistence strategies 
* [`PathValidator`](crate::api::PathValidator) - path validator API. Implement this trait to use different backend authorities to validate certificate paths.

### Implementations

The following API implementations are provided with the X509 Path Finder crate:

#### Certificate

* [OpenSSLCertificate](crate::provided::certificate::openssl::OpenSSLCertificate) - OpenSSL X509 certificate representation

#### CertificateStore

* [DefaultCertificateStore](crate::provided::store::DefaultCertificateStore) - Default implementation. Not thread safe.
* [ConcurrentCertificateStore](crate::provided::store::ConcurrentCertificateStore) - Wraps default implementation in a RwLock. Can be cloned and sent across threads.

#### PathValidator

* [OpenSSLPathValidator](crate::provided::validator::openssl::OpenSSLPathValidator)- validates path with OpenSSL

## TODO

* [RustCrypto-based](https://github.com/RustCrypto) implementations for  [`Certificate`](crate::api::Certificate) and  [`PathValidator`](crate::api::PathValidator) 
* Parallel downloading of AIA URLs
* Defunk the [`X509PathFinderConfiguration::client`](crate::X509PathFinderConfiguration::client) field
