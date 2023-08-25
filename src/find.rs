use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::vec;

use url::Url;
use x509_client::api::X509Iterator;
use x509_client::{X509ClientError, X509ClientResult};

use crate::api::{Certificate, CertificatePathValidation, CertificateStore, PathValidator};
use crate::edge::{Edge, EdgeDisposition, Edges};
use crate::report::{CertificateOrigin, Report};
use crate::{X509PathFinderError, X509PathFinderResult, AIA};

/// [`X509PathFinder`](crate::X509PathFinder) configuration
#[derive(Clone)]
pub struct X509PathFinderConfiguration<'r, X, S, C, V>
where
    X: X509Iterator<Item = C>,
    S: CertificateStore<'r, Certificate = C>,
    C: Certificate<'r>,
    V: PathValidator<'r, Certificate = C>,
{
    /// limit runtime of path search. Actual limit will be N * HTTP timeout. See `Reqwest` docs for setting HTTP connection timeout.
    pub limit: Duration,
    /// Optional client to find additional certificates by parsing URLs from [Authority Information Access](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1) extensions
    pub aia: AIA<'r, X, C>,
    /// [`CertificateStore`](crate::api::CertificateStore) implementation
    pub store: S,
    /// [`PathValidator`](crate::api::PathValidator) implementation
    pub validator: V,
}

/// X509 Path Finder
#[derive(Clone)]
pub struct X509PathFinder<'r, X, S, C, V>
where
    X: X509Iterator<Item = C>,
    S: CertificateStore<'r, Certificate = C>,
    C: Certificate<'r>,
    V: PathValidator<'r, Certificate = C>,
{
    config: X509PathFinderConfiguration<'r, X, S, C, V>,
}

impl<'r, X, S, C, V> X509PathFinder<'r, X, S, C, V>
where
    X: X509Iterator<Item = C>,
    S: CertificateStore<'r, Certificate = C>,
    C: Certificate<'r>,
    V: PathValidator<'r, Certificate = C>,
    X509ClientError: From<X::X509IteratorError>,
    X509PathFinderError: From<<V as PathValidator<'r>>::PathValidatorError>,
    X509PathFinderError: From<<C as Certificate<'r>>::CertificateError>,
    X509PathFinderError: From<<S as CertificateStore<'r>>::CertificateStoreError>,
{
    /// Instantiate new X509PathFinder with configuration
    pub fn new(config: X509PathFinderConfiguration<'r, X, S, C, V>) -> Self {
        X509PathFinder { config }
    }

    /// Find certificate path, returning [`Report`](crate::report::Report)
    pub async fn find<IT: Into<C>>(
        &mut self,
        certificate: IT,
    ) -> X509PathFinderResult<Report<'r, C>> {
        let mut edges = Edges::new(certificate.into());

        let start = Instant::now();

        let mut failures = vec![];

        while let Some(edge) = edges.next() {
            if self.config.limit != Duration::ZERO && Instant::now() - start > self.config.limit {
                return Err(X509PathFinderError::Error("limit exceeded".to_string()));
            }
            if let Some((path, origin)) = self.validate(&edge).await? {
                match path {
                    CertificatePathValidation::Found(path) => {
                        return Ok(Report {
                            path: Some(path),
                            origin: Some(origin),
                            duration: Instant::now() - start,
                            failures,
                        });
                    }
                    CertificatePathValidation::NotFound(f) => {
                        failures.push(f);
                    }
                }
            }

            if edges.visited(&edge) {
                continue;
            }

            edges.visit(&edge);

            let next = self.next(&mut edges, edge).await?;

            edges.extend(next);
        }

        Ok(Report {
            path: None,
            origin: None,
            duration: Instant::now() - start,
            failures,
        })
    }

    async fn validate(
        &self,
        edge: &Edge<'r, C>,
    ) -> X509PathFinderResult<Option<(CertificatePathValidation<'r, C>, Vec<CertificateOrigin>)>>
    {
        if !edge.end() {
            return Ok(None);
        }

        let mut path = VecDeque::new();
        let mut origin = VecDeque::new();

        let mut next_parent = edge.parent();
        while let Some(parent) = next_parent {
            if let EdgeDisposition::Certificate(certificate, certificate_origin) =
                &(parent.disposition())
            {
                path.push_front(certificate.clone());
                origin.push_front(certificate_origin.clone());
            }
            next_parent = parent.parent();
        }

        Ok(Some((
            self.config.validator.validate(path.into())?,
            origin.into(),
        )))
    }

    async fn next(
        &mut self,
        edges: &mut Edges<'r, C>,
        edge: Edge<'r, C>,
    ) -> X509PathFinderResult<Vec<Edge<'r, C>>> {
        match edge.disposition() {
            // edge is leaf certificate, search for issuer candidates
            EdgeDisposition::Certificate(edge_certificate, _) => {
                let mut store_candidates = self.next_store(edges, &edge, edge_certificate)?;

                // return issuer candidates from store or try aia
                if !store_candidates.is_empty() {
                    let aia_urls = edge_certificate.aia();
                    let mut aia_edges = aia_urls
                        .into_iter()
                        .map(|u| {
                            edges.edge_from_url(Some(edge.clone()), u, edge_certificate.clone())
                        })
                        .collect::<Vec<Edge<C>>>();
                    store_candidates.append(&mut aia_edges);
                    Ok(store_candidates)
                } else {
                    Ok(self.next_aia(edges, &edge, edge_certificate))
                }
            }
            // edge is url, download certificates, search for issuer candidates
            EdgeDisposition::Url(url, edge_certificate) => Ok(self
                .next_url(edges, &edge, edge_certificate, url.clone())
                .await?),
            // edge is end, stop search
            EdgeDisposition::End(_) => Ok(vec![]),
        }
    }

    // return non self-signed issuer candidates from store
    fn next_store(
        &mut self,
        edges: &mut Edges<'r, C>,
        parent_edge: &Edge<'r, C>,
        parent_certificate: &C,
    ) -> X509PathFinderResult<Vec<Edge<'r, C>>> {
        let mut candidates = vec![];
        for candidate in self.config.store.issuers(parent_certificate)? {
            // filter out self-signed
            if !candidate.issued(&candidate)? {
                candidates.push(edges.edge_from_certificate(
                    Some(parent_edge.clone()),
                    candidate,
                    CertificateOrigin::Store,
                ));
            }
        }
        Ok(candidates)
    }

    // download certificates, insert into store, return non self-signed issuer candidates
    async fn next_url(
        &mut self,
        edges: &mut Edges<'r, C>,
        parent_edge: &Edge<'r, C>,
        parent_certificate: &C,
        url: Arc<Url>,
    ) -> X509PathFinderResult<Vec<Edge<'r, C>>> {
        let mut candidates = vec![];
        for candidate in self
            .get_all(url.as_ref())
            .await
            .unwrap_or_else(|_| X::from_iter(vec![]))
        {
            self.config.store.insert(candidate.clone())?;

            // filtering out self-signed
            if candidate.issued(&candidate)? {
                continue;
            }

            // url is issuer, return as certificate edge
            if candidate.issued(parent_certificate)? {
                candidates.push(edges.edge_from_certificate(
                    parent_edge.parent().clone(),
                    candidate,
                    CertificateOrigin::Url(url.clone()),
                ));
            }
        }

        // no issuer candidates, return end edge
        if candidates.is_empty() {
            candidates.push(edges.edge_from_end(parent_edge.parent().clone()));
        }
        Ok(candidates)
    }

    // if aia enabled, return aia edges
    fn next_aia(
        &mut self,
        edges: &mut Edges<'r, C>,
        parent_edge: &Edge<'r, C>,
        parent_certificate: &C,
    ) -> Vec<Edge<'r, C>> {
        // aia disabled, return end edge
        if let AIA::None(_) = &self.config.aia {
            return vec![edges.edge_from_end(Some(parent_edge.clone()))];
        }

        let aia_urls = parent_certificate.aia();

        // no aia urls found, return end edge
        if aia_urls.is_empty() {
            return vec![edges.edge_from_end(Some(parent_edge.clone()))];
        }

        aia_urls
            .into_iter()
            .map(|u| edges.edge_from_url(Some(parent_edge.clone()), u, parent_certificate.clone()))
            .collect()
    }

    /// Consume finder, return configuration
    pub fn into_config(self) -> X509PathFinderConfiguration<'r, X, S, C, V> {
        self.config
    }

    #[cfg(not(test))]
    async fn get_all(&self, url: &Url) -> X509ClientResult<X> {
        if let AIA::Client(client) = &self.config.aia {
            client.get_all(url).await
        } else {
            Ok(X::from_iter(vec![]))
        }
    }

    #[cfg(test)]
    async fn get_all(&self, url: &Url) -> X509ClientResult<X> {
        Ok(X::from_cer(url.to_string().as_bytes())?)
    }
}
