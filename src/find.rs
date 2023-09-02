use std::iter::once;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use std::vec;

use url::Url;

#[cfg(not(test))]
use {
    x509_client::provided::default::DefaultX509Iterator,
    x509_client::{X509Client, X509ClientResult},
};

use crate::api::{Certificate, CertificatePathValidation, CertificateStore, PathValidator};
use crate::edge::{Edge, EdgeDisposition, Edges};
use crate::report::{CertificateOrigin, Found, Report};
use crate::{X509PathFinderError, X509PathFinderResult};

/// [`X509PathFinder`](crate::X509PathFinder) configuration
pub struct X509PathFinderConfiguration<S, V>
where
    S: CertificateStore,
    V: PathValidator,
{
    /// limit runtime of path search. Actual limit will be N * HTTP timeout. See `Reqwest` docs for setting HTTP connection timeout.
    pub limit: Duration,
    /// Optional client to find additional certificates by parsing URLs from [Authority Information Access](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1) extensions
    #[cfg(not(test))]
    pub aia: Option<X509Client<DefaultX509Iterator>>,
    #[cfg(test)]
    pub aia: Option<()>,
    /// [`CertificateStore`](crate::api::CertificateStore) implementation
    pub store: Arc<RwLock<S>>,
    /// [`PathValidator`](crate::api::PathValidator) implementation
    pub validator: V,
}

/// X509 Path Finder
pub struct X509PathFinder<S, V>
where
    S: CertificateStore,
    V: PathValidator,
{
    config: X509PathFinderConfiguration<S, V>,
}

impl<S, V> X509PathFinder<S, V>
where
    S: CertificateStore,
    V: PathValidator,
    X509PathFinderError: From<<V as PathValidator>::PathValidatorError>,
{
    /// Instantiate new X509PathFinder with configuration
    pub fn new(config: X509PathFinderConfiguration<S, V>) -> Self {
        X509PathFinder { config }
    }

    /// Find certificate path, returning [`Report`](crate::report::Report)
    pub async fn find(&mut self, target: Certificate) -> X509PathFinderResult<Report> {
        let mut edges = Edges::new(target);

        let start = Instant::now();

        let mut failures = vec![];

        while let Some(edge) = edges.next() {
            if self.config.limit != Duration::ZERO && Instant::now() - start > self.config.limit {
                return Err(X509PathFinderError::Error("limit exceeded".to_string()));
            }
            if edge.end() {
                let (path, origin) = edges.path(&edge);
                match self.config.validator.validate(path.clone())? {
                    CertificatePathValidation::Found => {
                        return Ok(Report {
                            found: Some(Found { path, origin }),
                            duration: Instant::now() - start,
                            failures,
                        });
                    }
                    CertificatePathValidation::NotFound(v) => {
                        failures.push(v);
                    }
                }
            }

            if edges.visited(&edge) {
                continue;
            }

            edges.visit(&edge);

            let next = self.next(&mut edges, &edge).await?;

            edges.extend(edge, next);
        }

        Ok(Report {
            found: None,
            duration: Instant::now() - start,
            failures,
        })
    }

    async fn next(&mut self, edges: &mut Edges, edge: &Edge) -> X509PathFinderResult<Vec<Edge>> {
        match edge.disposition() {
            // edge is leaf certificate, search for issuer candidates
            EdgeDisposition::Certificate(edge_certificate, _) => {
                let mut store_candidates = self.next_store(edges, edge_certificate)?;

                // return issuer candidates from store or try aia
                if !store_candidates.is_empty() {
                    // append any aia edges
                    let aia_urls = edge_certificate.aia();
                    let mut aia_edges = aia_urls
                        .into_iter()
                        .map(|u| edges.edge_from_url(u, edge_certificate.clone()))
                        .collect::<Vec<Edge>>();
                    store_candidates.append(&mut aia_edges);
                    Ok(store_candidates)
                } else {
                    Ok(self.next_aia(edges, edge_certificate))
                }
            }
            // edge is url, download certificates, search for issuer candidates
            EdgeDisposition::Url(url, edge_certificate) => {
                Ok(self.next_url(edges, edge_certificate, url.clone()).await?)
            }
            // edge is end, stop search
            EdgeDisposition::End => Ok(vec![]),
        }
    }

    // return non self-signed issuer candidates from store
    fn next_store(
        &mut self,
        edges: &mut Edges,
        parent_certificate: &Certificate,
    ) -> X509PathFinderResult<Vec<Edge>> {
        let mut candidates = vec![];
        for candidate in self
            .config
            .store
            .read()
            .map_err(|e| X509PathFinderError::Error(e.to_string()))?
            .issuers(parent_certificate)
        {
            // filter out self-signed
            if !candidate.issued(candidate) {
                candidates
                    .push(edges.edge_from_certificate(candidate.clone(), CertificateOrigin::Store));
            }
        }
        Ok(candidates)
    }

    // download certificates, insert into store, return non self-signed issuer candidates
    async fn next_url(
        &mut self,
        edges: &mut Edges,
        parent_certificate: &Certificate,
        url: Arc<Url>,
    ) -> X509PathFinderResult<Vec<Edge>> {
        let mut candidates = vec![];
        for candidate in self.get_all(url.as_ref()).await.unwrap_or_else(|_| vec![]) {
            self.config
                .store
                .write()
                .map_err(|e| X509PathFinderError::Error(e.to_string()))?
                .extend(once(candidate.clone()));

            // filtering out self-signed
            if candidate.issued(&candidate) {
                continue;
            }

            // url is issuer, return as certificate edge
            if candidate.issued(parent_certificate) {
                candidates.push(
                    edges.edge_from_certificate(candidate, CertificateOrigin::Url(url.clone())),
                );
            }
        }

        // no issuer candidates, return end edge
        if candidates.is_empty() {
            candidates.push(edges.edge_from_end());
        }
        Ok(candidates)
    }

    // if aia enabled, return aia edges
    fn next_aia(&mut self, edges: &mut Edges, parent_certificate: &Certificate) -> Vec<Edge> {
        // aia disabled, return end edge
        if self.config.aia.is_none() {
            return vec![edges.edge_from_end()];
        }

        let aia_urls = parent_certificate.aia();

        // no aia urls found, return end edge
        if aia_urls.is_empty() {
            return vec![edges.edge_from_end()];
        }

        aia_urls
            .into_iter()
            .map(|u| edges.edge_from_url(u, parent_certificate.clone()))
            .collect()
    }

    /// Consume finder, return configuration
    pub fn into_config(self) -> X509PathFinderConfiguration<S, V> {
        self.config
    }

    #[cfg(not(test))]
    async fn get_all(&self, url: &Url) -> X509ClientResult<Vec<Certificate>> {
        if let Some(client) = &self.config.aia {
            Ok(client
                .get_all(url)
                .await?
                .into_iter()
                .map(|c| c.into())
                .collect())
        } else {
            Ok(vec![])
        }
    }

    #[cfg(test)]
    async fn get_all(&self, url: &Url) -> X509PathFinderResult<Vec<Certificate>> {
        Ok(vec![url.try_into().map_err(|_| {
            X509PathFinderError::Error("failure parsing test certificate into string".to_string())
        })?])
    }
}
