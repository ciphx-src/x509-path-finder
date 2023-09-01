use std::collections::HashSet;
use std::sync::Arc;

use crate::api::Certificate;
use crate::report::CertificateOrigin;
use url::Url;

#[derive(Clone)]
pub enum EdgeDisposition<'r> {
    Certificate(&'r Certificate, CertificateOrigin),
    Url(Arc<Url>, &'r Certificate),
    End,
}

#[derive(Clone)]
pub struct Edges<'r> {
    serial: usize,
    visited: HashSet<usize>,
    edges: Vec<Edge<'r>>,
}

impl<'r> Edges<'r> {
    pub fn new(certificate: &'r Certificate) -> Self {
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

    pub fn extend<I: IntoIterator<Item = Edge<'r>>>(&mut self, edges: I) {
        self.edges.extend(edges)
    }

    pub fn edge_from_certificate(
        &mut self,
        parent: Option<Edge<'r>>,
        certificate: &'r Certificate,
        origin: CertificateOrigin,
    ) -> Edge<'r> {
        self.serial += 1;
        Edge::new(
            self.serial,
            parent,
            EdgeDisposition::Certificate(certificate, origin),
        )
    }
    pub fn edge_from_url(
        &mut self,
        parent: Option<Edge<'r>>,
        url: Url,
        holder: &'r Certificate,
    ) -> Edge {
        self.serial += 1;
        Edge::new(
            self.serial,
            parent,
            EdgeDisposition::Url(url.into(), holder),
        )
    }

    pub fn edge_from_end(&mut self, parent: Option<Edge<'r>>) -> Edge {
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
pub struct Edge<'r> {
    parent: Box<Option<Edge<'r>>>,
    disposition: EdgeDisposition<'r>,
    serial: usize,
}

impl<'r> Edge<'r> {
    fn new(serial: usize, parent: Option<Edge<'r>>, disposition: EdgeDisposition<'r>) -> Self {
        Self {
            parent: parent.into(),
            disposition,
            serial,
        }
    }

    pub fn parent(&self) -> Option<Edge<'r>> {
        self.parent.as_ref().clone()
    }

    pub fn end(&self) -> bool {
        matches!(self.disposition, EdgeDisposition::End)
    }

    pub fn disposition(&self) -> &EdgeDisposition {
        &self.disposition
    }
}
