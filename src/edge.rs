use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::rc::Rc;

use crate::certificate::Certificate;
use crate::report::CertificateOrigin;
use url::Url;

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Edge {
    Certificate(Rc<Certificate>, CertificateOrigin),
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

    pub fn start(&mut self, certificate: Certificate) {
        self.edges
            .push(Edge::Certificate(certificate.into(), CertificateOrigin::Target).into())
    }

    pub fn next(&mut self) -> Option<Rc<Edge>> {
        self.edges.pop()
    }

    pub fn extend(&mut self, parent: Rc<Edge>, edges: Vec<Rc<Edge>>) {
        for child in edges.into_iter() {
            self.edges.push(child.clone());
            self.parents.insert(child, parent.clone());
        }
    }

    pub fn path(&self, target: &Rc<Edge>) -> (Vec<Rc<Certificate>>, Vec<CertificateOrigin>) {
        let mut path = vec![];
        let mut path_origin = vec![];

        let mut current_edge = Some(target);
        while let Some(edge) = current_edge {
            if let Edge::Certificate(certificate, origin) = edge.as_ref() {
                path.push(certificate.clone());
                path_origin.push(origin.clone());
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
