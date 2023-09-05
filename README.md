# X509 Path Finder

X509 Path Finder is a [depth-first search](https://en.wikipedia.org/wiki/Depth-first_search) certificate path validator for Rust.

![CI Status](https://github.com/merlincinematic/x509-path-finder/actions/workflows/ci.yaml/badge.svg)

![Depth-first search](https://github.com/merlincinematic/x509-path-finder/raw/master/doc/find.png)

## Synopsis

X509 Path Finder rejects the notion of a single "certificate chain." Instead, it searches for the first match out of infinity. Once it finds a path it can validate, the search halts and the path is returned to the caller.

The complexity of the path search is constrained by three factors:

1. Number of certificates preloaded into its local store
2. Number of certificates it can find and download by following [AIA](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1) URLs
3. An arbitrary time limit

When evaluating a path candidate for validation, X509 Path Finder is implementation-agnostic. Once it finds a path that has terminated, it presents it to be validated by a backend authority. If the authority validates the path, the search halts.

X509 Path Finder provides two validators:

1. [DefaultPathValidator](crate::provided::validator::default::DefaultPathValidator) - implemented with [RustCrypto](https://github.com/RustCrypto) and [Rustls](https://github.com/rustls/rustls), available by default.
2. [OpenSSLPathValidator](crate::provided::validator::openssl::OpenSSLPathValidator) - implemented with [Rust OpenSSL](https://docs.rs/openssl/latest/openssl/), available with the `openssl` feature flag

## Usage

By default, the provided [DefaultPathValidator](crate::provided::validator::default::DefaultPathValidator) validator is available.

````text
[dependencies]
x509_path_finder = { version = "0.3"] }
````

Enable the `openssl` feature for access to the provided [OpenSSLPathValidator](crate::provided::validator::openssl::OpenSSLPathValidator) validator.

````text
[dependencies]
x509_path_finder = { version = "0.3", features = ["openssl"] }
````


### Example

```` rust no_run
use rustls::{Certificate as RustlsCertificate, RootCertStore};
use std::time::Duration;
use x509_path_finder::report::CertificateOrigin;
use x509_path_finder::{X509PathFinder, X509PathFinderConfiguration};
use x509_path_finder::provided::validator::default::DefaultPathValidator;

async fn test_find(root: Vec<u8>, cross: Vec<x509_path_finder::Certificate>, ee: x509_path_finder::Certificate) -> Result<(), x509_path_finder::X509PathFinderError> {

    // create Rustls store
    let mut store = RootCertStore::empty();
    
    // add root certificate to store
    let root = RustlsCertificate(root);
    store.add(&root).unwrap();
    
    // instantiate default validator
    let validator = DefaultPathValidator::new(store);

    // instantiate the finder
    let search = X509PathFinder::new(X509PathFinderConfiguration {
        limit: Duration::default(),
        aia: None,
        validator,
        certificates: cross
    });

    // execute the search
    let found = search.find(ee).await?.found.unwrap();

    // path has two certificates
    assert_eq!(2, found.path.len());
    
    Ok(())
}

````

### Configuration


The  [`X509PathFinderConfiguration`](crate::X509PathFinderConfiguration) struct has the following fields.

* `limit`: limit runtime of path search. Actual limit will be N * HTTP timeout. See [` reqwest::ClientBuilder::timeout`](https://docs.rs/reqwest/0.11.20/reqwest/struct.ClientBuilder.html#method.timeout) for setting HTTP connection timeout.
* `aia`: optional [`x509_client::X509ClientConfiguration`](https://docs.rs/x509-client/2.0.1/x509_client/struct.X509ClientConfiguration.html) to enable [Authority Information Access](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1) extensions. 
* `validator`: [`PathValidator`](crate::api::PathValidator) implementation
* `certificates` : additional bridge and cross signed-certificates to use for path finding

#### Resource Management

Because X509 Path Builder can consume AIA URLs from the web, a call to [`X509PathFinder::find`](crate::X509PathFinder::find) could in theory run forever, or be coerced into downloading vast amounts of data. Configuration options for managing X509 Path Finder resources:

* Set the `limit` duration to non-zero for  [`X509PathFinderConfiguration::limit`](crate::X509PathFinderConfiguration::limit)
* Set the [` reqwest::ClientBuilder::timeout`](https://docs.rs/reqwest/0.11.20/reqwest/struct.ClientBuilder.html#method.timeout) to a more aggressive value
* Limit the certificate download size by setting [`x509_client::X509ClientConfiguration::limit`](https://docs.rs/x509-client/2.0.1/x509_client/struct.X509ClientConfiguration.html#structfield.limit) to a non-zero value
* Disable AIA

### Finding Paths

Call [`X509PathFinder::find`](crate::X509PathFinder::find) to find a path. Supply the target end-entity to start working from [Certificate](`crate::Certificate`) from. The search will work backward toward the root certificate.

The returning [`Report`](crate::report::Report) contains the following fields:

* `found`: on path find success, contains [`Found`](crate::report::Found)
* `duration`: duration of path search
* `failures`: any validation failures reported by [`PathValidator`](crate::api::PathValidator) implementations are held in [`ValidationFailure`](crate::report::ValidationFailure)

#### Found

The [`Found`](crate::report::Found) struct contains following fields:

* path - the discovered path, a vec of [`Certificate`](crate::Certificate)
* origin - the path [`CertificateOrigin`](crate::report::CertificateOrigin) 

#### CertificateOrigin
[`CertificateOrigin`](crate::report::CertificateOrigin) is an enum that describes the origin of each certificate. Can be one of:

1. `Target`: the initial certificate when calling [`X509PathFinder::find`](crate::X509PathFinder::find).
2. `Store`: certificate was found in the store
3. `Url`: certificate was downloaded from a URL (AIA)

#### ValidateFailure

[`ValidationFailure`](crate::report::ValidationFailure) stores any validation failures. Validation failures can occur even though a valid certificate path was eventually found. `ValidateFailure` contains the following fields:

1. `origin`: the [`CertificateOrigin`](crate::report::CertificateOrigin) of where the validation error occurred
2. `reason`: human-readable reason for the failure

## API

The X509 [`PathValidator`](crate::api::PathValidator) API can be implemented to use different backend authorities to validate certificate paths and add business logic.

### Implementations

* [DefaultPathValidator](crate::provided::validator::default::DefaultPathValidator)- validates path with [Rustls](https://github.com/rustls/rustls)
* [OpenSSLPathValidator](crate::provided::validator::openssl::OpenSSLPathValidator)- validates path with [OpenSSL](https://docs.rs/openssl/latest/openssl/)

## TODO

* Integration tests