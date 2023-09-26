use std::collections::BTreeMap;
use crate::ast::source::Source;

pub struct Schema {
    pub(crate) sources: BTreeMap<usize, Source>,
    pub(crate) references: SchemaReferences,
}

pub(crate) struct SchemaReferences {
    pub(crate) builtin_sources: Vec<usize>,
    pub(crate) main_source: Option<usize>,
    pub(crate) connector: Option<Vec<usize>>,
    pub(crate) server: Option<Vec<usize>>,
    pub(crate) entities: Vec<Vec<usize>>,
    pub(crate) clients: Vec<Vec<usize>>,
    pub(crate) enums: Vec<Vec<usize>>,
    pub(crate) models: Vec<Vec<usize>>,
    pub(crate) data_sets: Vec<Vec<usize>>,
    pub(crate) debug: Option<Vec<usize>>,
    pub(crate) test: Option<Vec<usize>>,
    pub(crate) namespaces: Vec<Vec<usize>>,
}

impl SchemaReferences {

    pub(crate) fn new() -> Self {
        Self {
            builtin_sources: vec![],
            main_source: None,
            connector: None,
            server: None,
            entities: vec![],
            clients: vec![],
            enums: vec![],
            models: vec![],
            data_sets: vec![],
            debug: None,
            test: None,
            namespaces: vec![],
        }
    }
}