use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::api::Certificate;
use crate::report::CertificateOrigin;
use url::Url;

#[derive(Clone)]
pub enum EdgeDisposition {
    Certificate(Certificate, CertificateOrigin),
    Url(Arc<Url>, Certificate),
    End,
}

#[derive(Clone)]
pub struct Edges {
    serial: usize,
    visited: HashSet<usize>,
    parents: HashMap<Edge, Edge>,
    edges: Vec<Edge>,
}

impl Edges {
    pub fn new(certificate: Certificate) -> Self {
        Self {
            serial: 0,
            visited: HashSet::new(),
            parents: HashMap::new(),
            edges: vec![Edge::new(
                0,
                EdgeDisposition::Certificate(certificate, CertificateOrigin::Target),
            )],
        }
    }

    pub fn next(&mut self) -> Option<Edge> {
        self.edges.pop()
    }

    pub fn extend(&mut self, parent: Edge, edges: Vec<Edge>) {
        for child in edges.clone().into_iter() {
            self.parents.insert(child, parent.clone());
        }
        self.edges.extend(edges)
    }

    pub fn path(&self, target: &Edge) -> (Vec<Vec<u8>>, Vec<CertificateOrigin>) {
        let mut path = vec![];
        let mut path_origin = vec![];

        let mut current_edge = Some(target);
        while let Some(edge) = current_edge {
            if let EdgeDisposition::Certificate(certificate, origin) = edge.disposition() {
                path.push(certificate.der().to_vec());
                path_origin.push(origin.clone());
            }
            current_edge = self.parents.get(edge);
        }
        path.reverse();
        path_origin.reverse();
        (path, path_origin)
    }

    pub fn edge_from_certificate(
        &mut self,
        certificate: Certificate,
        origin: CertificateOrigin,
    ) -> Edge {
        self.serial += 1;
        Edge::new(
            self.serial,
            EdgeDisposition::Certificate(certificate, origin),
        )
    }
    pub fn edge_from_url(&mut self, url: Url, holder: Certificate) -> Edge {
        self.serial += 1;
        Edge::new(self.serial, EdgeDisposition::Url(url.into(), holder))
    }

    pub fn edge_from_end(&mut self) -> Edge {
        self.serial += 1;
        Edge::new(self.serial, EdgeDisposition::End)
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
    disposition: EdgeDisposition,
    serial: usize,
}

impl Edge {
    fn new(serial: usize, disposition: EdgeDisposition) -> Self {
        Self {
            disposition,
            serial,
        }
    }

    pub fn end(&self) -> bool {
        matches!(self.disposition, EdgeDisposition::End)
    }

    pub fn disposition(&self) -> &EdgeDisposition {
        &self.disposition
    }
}

impl PartialEq for Edge {
    fn eq(&self, other: &Self) -> bool {
        self.serial == other.serial
    }
}

impl Eq for Edge {}

impl Hash for Edge {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.serial.hash(state)
    }
}
