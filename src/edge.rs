use std::collections::HashSet;
use std::sync::Arc;

use crate::api::Certificate;
use crate::report::CertificateOrigin;
use url::Url;

#[derive(Clone)]
pub enum EdgeDisposition {
    Certificate(Arc<Certificate>, CertificateOrigin),
    Url(Arc<Url>, Arc<Certificate>),
    End,
}

#[derive(Clone)]
pub struct Edges {
    serial: usize,
    visited: HashSet<usize>,
    edges: Vec<Edge>,
}

impl Edges {
    pub fn new(certificate: Arc<Certificate>) -> Self {
        Self {
            serial: 0,
            visited: HashSet::new(),
            edges: vec![Edge::new(
                0,
                None,
                EdgeDisposition::Certificate(certificate, CertificateOrigin::Find),
            )],
        }
    }

    pub fn next(&mut self) -> Option<Edge> {
        self.edges.pop()
    }

    pub fn extend<I: IntoIterator<Item = Edge>>(&mut self, edges: I) {
        self.edges.extend(edges)
    }

    pub fn edge_from_certificate(
        &mut self,
        parent: Option<Edge>,
        certificate: Arc<Certificate>,
        origin: CertificateOrigin,
    ) -> Edge {
        self.serial += 1;
        Edge::new(
            self.serial,
            parent,
            EdgeDisposition::Certificate(certificate, origin),
        )
    }
    pub fn edge_from_url(
        &mut self,
        parent: Option<Edge>,
        url: Url,
        holder: Arc<Certificate>,
    ) -> Edge {
        self.serial += 1;
        Edge::new(
            self.serial,
            parent,
            EdgeDisposition::Url(url.into(), holder),
        )
    }

    pub fn edge_from_end(&mut self, parent: Option<Edge>) -> Edge {
        self.serial += 1;
        Edge::new(self.serial, parent, EdgeDisposition::End)
    }

    pub fn visit(&mut self, edge: &Edge) {
        self.visited.insert(edge.serial);
    }

    pub fn visited(&self, edge: &Edge) -> bool {
        self.visited.contains(&edge.serial)
    }
}

#[derive(Clone)]
pub struct Edge {
    parent: Box<Option<Edge>>,
    disposition: EdgeDisposition,
    serial: usize,
}

impl Edge {
    fn new(serial: usize, parent: Option<Edge>, disposition: EdgeDisposition) -> Self {
        Self {
            parent: parent.into(),
            disposition,
            serial,
        }
    }

    pub fn parent(&self) -> Option<Edge> {
        self.parent.as_ref().clone()
    }

    pub fn end(&self) -> bool {
        matches!(self.disposition, EdgeDisposition::End)
    }

    pub fn disposition(&self) -> &EdgeDisposition {
        &self.disposition
    }
}
