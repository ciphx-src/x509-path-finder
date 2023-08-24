use std::collections::HashSet;
use std::marker::PhantomData;
use std::sync::Arc;

use crate::api::Certificate;
use crate::report::CertificateOrigin;
use url::Url;

#[derive(Clone)]
pub enum EdgeDisposition<'r, C: Certificate<'r>> {
    Certificate(C, CertificateOrigin),
    Url(Arc<Url>, C),
    End(PhantomData<&'r C>),
}

#[derive(Clone)]
pub struct Edges<'r, C: Certificate<'r>> {
    serial: usize,
    visited: HashSet<usize>,
    edges: Vec<Edge<'r, C>>,
}

impl<'r, C: Certificate<'r>> Edges<'r, C> {
    pub fn new(certificate: C) -> Self {
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

    pub fn next(&mut self) -> Option<Edge<'r, C>> {
        self.edges.pop()
    }

    pub fn extend<I: IntoIterator<Item = Edge<'r, C>>>(&mut self, edges: I) {
        self.edges.extend(edges)
    }

    pub fn edge_from_certificate(
        &mut self,
        parent: Option<Edge<'r, C>>,
        certificate: C,
        origin: CertificateOrigin,
    ) -> Edge<'r, C> {
        self.serial += 1;
        Edge::new(
            self.serial,
            parent,
            EdgeDisposition::Certificate(certificate, origin),
        )
    }
    pub fn edge_from_url(
        &mut self,
        parent: Option<Edge<'r, C>>,
        url: Url,
        holder: C,
    ) -> Edge<'r, C> {
        self.serial += 1;
        Edge::new(
            self.serial,
            parent,
            EdgeDisposition::Url(url.into(), holder),
        )
    }

    pub fn edge_from_end(&mut self, parent: Option<Edge<'r, C>>) -> Edge<'r, C> {
        self.serial += 1;
        Edge::new(self.serial, parent, EdgeDisposition::End(PhantomData))
    }

    pub fn visit(&mut self, edge: &Edge<'r, C>) {
        self.visited.insert(edge.serial);
    }

    pub fn visited(&self, edge: &Edge<'r, C>) -> bool {
        self.visited.contains(&edge.serial)
    }
}

#[derive(Clone)]
pub struct Edge<'r, C: Certificate<'r>> {
    parent: Box<Option<Edge<'r, C>>>,
    disposition: EdgeDisposition<'r, C>,
    serial: usize,
}

impl<'r, C: Certificate<'r>> Edge<'r, C> {
    fn new(
        serial: usize,
        parent: Option<Edge<'r, C>>,
        disposition: EdgeDisposition<'r, C>,
    ) -> Self {
        Self {
            parent: parent.into(),
            disposition,
            serial,
        }
    }

    pub fn parent(&self) -> Option<Edge<'r, C>> {
        self.parent.as_ref().clone()
    }

    pub fn end(&self) -> bool {
        matches!(self.disposition, EdgeDisposition::End(_))
    }

    pub fn disposition(&self) -> &EdgeDisposition<'r, C> {
        &self.disposition
    }
}
