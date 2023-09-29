use std::collections::BTreeMap;
use crate::ast::config::Config;
use crate::ast::source::Source;

pub struct Schema {
    pub(crate) sources: BTreeMap<usize, Source>,
    pub(crate) references: SchemaReferences,
}

impl Schema {

    pub(crate) fn sources(&self) -> Vec<&Source> {
        self.sources.values().collect()
    }
}

pub(crate) struct SchemaReferences {
    pub(crate) builtin_sources: Vec<usize>,
    pub(crate) main_source: Option<usize>,
    pub(crate) configs: Vec<Vec<usize>>,
    pub(crate) server: Option<Vec<usize>>,
    pub(crate) debug: Option<Vec<usize>>,
    pub(crate) test: Option<Vec<usize>>,
    pub(crate) connectors: Vec<Vec<usize>>,
    pub(crate) entities: Vec<Vec<usize>>,
    pub(crate) clients: Vec<Vec<usize>>,
    pub(crate) enums: Vec<Vec<usize>>,
    pub(crate) models: Vec<Vec<usize>>,
    pub(crate) data_sets: Vec<Vec<usize>>,
    pub(crate) interfaces: Vec<Vec<usize>>,
    pub(crate) namespaces: Vec<Vec<usize>>,
}

impl SchemaReferences {

    pub(crate) fn new() -> Self {
        Self {
            builtin_sources: vec![],
            main_source: None,
            connectors: vec![],
            configs: vec![],
            server: None,
            entities: vec![],
            clients: vec![],
            enums: vec![],
            models: vec![],
            data_sets: vec![],
            debug: None,
            test: None,
            interfaces: vec![],
            namespaces: vec![],
        }
    }

    pub(crate) fn add_config(&mut self, config: &Config) {
        self.configs.push(config.path.clone());
        if config.keyword.is_client() {
            self.clients.push(config.path.clone());
        } else if config.keyword.is_connector() {
            self.connectors.push(config.path.clone());
        } else if config.keyword.is_server() {
            self.server = Some(config.path.clone());
        } else if config.keyword.is_entity() {
            self.entities.push(config.path.clone());
        } else if config.keyword.is_test() {
            self.test = Some(config.path.clone());
        } else if config.keyword.is_debug() {
            self.debug = Some(config.path.clone());
        }
    }
}