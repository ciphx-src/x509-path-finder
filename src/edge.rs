use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::sync::Arc;

use crate::certificate::Certificate;
use crate::report::CertificateOrigin;
use url::Url;

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Edge {
    Certificate(Arc<Certificate>),
    Url(Arc<Url>, Arc<Certificate>),
    End,
}

#[derive(Clone)]
pub struct Edges {
    visited: HashSet<Edge>,
    parents: HashMap<Edge, Edge>,
    edges: Vec<Edge>,
}

impl Edges {
    pub fn new() -> Self {
        Self {
            visited: HashSet::new(),
            parents: HashMap::new(),
            edges: vec![],
        }
    }

    pub fn start(&mut self, mut certificate: Certificate) {
        certificate.set_origin(CertificateOrigin::Target);
        self.edges.push(Edge::Certificate(certificate.into()))
    }

    pub fn next(&mut self) -> Option<Edge> {
        self.edges.pop()
    }

    // extend edge queue while preventing duplicates in path
    pub fn extend(&mut self, parent: Edge, edges: Vec<Edge>) {
        let path_set = self.path_set(&parent);

        for child in edges.into_iter() {
            // valid X509 paths can only use a certificate once
            if let Edge::Certificate(child) = &child {
                if path_set.contains(child) {
                    continue;
                }
            }
            self.edges.push(child.clone());
            self.parents.insert(child, parent.clone());
        }
    }

    fn path_set(&self, target: &Edge) -> HashSet<Arc<Certificate>> {
        let mut path = HashSet::new();

        let mut current_edge = Some(target);
        while let Some(edge) = current_edge {
            if let Edge::Certificate(certificate) = edge {
                path.insert(certificate.clone());
            }
            current_edge = self.parents.get(edge);
        }

        path
    }

    pub fn path(&self, target: &Edge) -> (Vec<Arc<crate::Certificate>>, Vec<CertificateOrigin>) {
        let mut path = vec![];
        let mut path_origin = vec![];

        let mut current_edge = Some(target);
        while let Some(edge) = current_edge {
            if let Edge::Certificate(certificate) = &edge {
                path.push(certificate.inner().clone());
                path_origin.push(certificate.origin().clone());
            }
            current_edge = self.parents.get(edge);
        }
        path.reverse();
        path_origin.reverse();
        (path, path_origin)
    }

    pub fn visit(&mut self, edge: Edge) {
        self.visited.insert(edge);
    }

    pub fn visited(&self, edge: &Edge) -> bool {
        self.visited.contains(edge)
    }
}
