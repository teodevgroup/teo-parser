use std::collections::BTreeMap;
use crate::ast::config::Config;
use crate::ast::config_declaration::ConfigDeclaration;
use crate::ast::source::Source;
use crate::ast::top::Top;

pub struct Schema {
    pub(crate) sources: BTreeMap<usize, Source>,
    pub(crate) references: SchemaReferences,
}

impl Schema {

    pub(crate) fn sources(&self) -> Vec<&Source> {
        self.sources.values().collect()
    }

    pub(crate) fn source(&self, id: usize) -> Option<&Source> {
        self.sources.get(&id)
    }

    pub(crate) fn source_at_path(&self, path: &str) -> Option<&Source> {
        self.sources().iter().find_map(|s| if s.file_path.as_str() == path { Some(*s) } else { None })
    }

    pub(crate) fn builtin_sources(&self) -> Vec<&Source> {
        self.references.builtin_sources.iter().map(|id| self.source(*id).unwrap()).collect()
    }

    pub(crate) fn config_declarations(&self) -> Vec<&ConfigDeclaration> {
        self.references.config_declarations.iter().map(|path| self.find_top_by_path(path).unwrap().as_config_declaration().unwrap()).collect()
    }

    pub(crate) fn find_config_declaration_by_name(&self, name: &str) -> Option<&ConfigDeclaration> {
        for config_declarations in self.config_declarations() {
            if config_declarations.identifier.name() == name {
                return Some(config_declarations)
            }
        }
        None
    }

    pub(crate) fn find_top_by_path(&self, path: &Vec<usize>) -> Option<&Top> {
        if path.len() < 2 {
            return None;
        }
        if let Some(source) = self.source(*path.get(0).unwrap()) {
            source.find_top_by_path(path)
        } else {
            None
        }
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
    pub(crate) config_declarations: Vec<Vec<usize>>,
    pub(crate) decorator_declarations: Vec<Vec<usize>>,
    pub(crate) pipeline_item_declarations: Vec<Vec<usize>>,
    pub(crate) middlewares: Vec<Vec<usize>>,
    pub(crate) handler_groups: Vec<Vec<usize>>,
    pub(crate) struct_declarations: Vec<Vec<usize>>,
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
            config_declarations: vec![],
            decorator_declarations: vec![],
            pipeline_item_declarations: vec![],
            middlewares: vec![],
            handler_groups: vec![],
            struct_declarations: vec![],
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