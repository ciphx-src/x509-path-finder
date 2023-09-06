use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::rc::Rc;

use crate::certificate::Certificate;
use crate::report::CertificateOrigin;
use url::Url;

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Edge {
    Certificate(Rc<Certificate>),
    Url(Url, Rc<Certificate>),
    End,
}

#[derive(Clone)]
pub struct Edges {
    visited: HashSet<Rc<Edge>>,
    parents: HashMap<Rc<Edge>, Rc<Edge>>,
    edges: Vec<Rc<Edge>>,
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
        self.edges
            .push(Edge::Certificate(certificate.into()).into())
    }

    pub fn next(&mut self) -> Option<Rc<Edge>> {
        self.edges.pop()
    }

    // extend edge queue while preventing duplicates in path
    pub fn extend(&mut self, parent: Rc<Edge>, edges: Vec<Rc<Edge>>) {
        let path_set = self.path_set(&parent);

        for child in edges.into_iter() {
            // valid X509 paths can only use a certificate once
            if let Edge::Certificate(child) = child.as_ref() {
                if path_set.contains(child) {
                    continue;
                }
            }
            self.edges.push(child.clone());
            self.parents.insert(child, parent.clone());
        }
    }

    fn path_set(&self, target: &Rc<Edge>) -> HashSet<Rc<Certificate>> {
        let mut path = HashSet::new();

        let mut current_edge = Some(target);
        while let Some(edge) = current_edge {
            if let Edge::Certificate(certificate) = edge.as_ref() {
                path.insert(certificate.clone());
            }
            current_edge = self.parents.get(edge);
        }

        path
    }

    pub fn path(&self, target: &Rc<Edge>) -> (Vec<Rc<Certificate>>, Vec<CertificateOrigin>) {
        let mut path = vec![];
        let mut path_origin = vec![];

        let mut current_edge = Some(target);
        while let Some(edge) = current_edge {
            if let Edge::Certificate(certificate) = edge.as_ref() {
                path.push(certificate.clone());
                path_origin.push(certificate.origin().clone());
            }
            current_edge = self.parents.get(edge);
        }
        path.reverse();
        path_origin.reverse();
        (path, path_origin)
    }

    pub fn visit(&mut self, edge: Rc<Edge>) {
        self.visited.insert(edge);
    }

    pub fn visited(&self, edge: &Edge) -> bool {
        self.visited.contains(edge)
    }
}
