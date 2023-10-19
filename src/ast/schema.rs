use std::collections::BTreeMap;
use crate::ast::availability::Availability;
use crate::ast::config::Config;
use crate::ast::config_declaration::ConfigDeclaration;
use crate::ast::data_set::DataSet;
use crate::ast::decorator_declaration::DecoratorDeclaration;
use crate::ast::handler::HandlerGroupDeclaration;
use crate::ast::interface::InterfaceDeclaration;
use crate::ast::middleware::MiddlewareDeclaration;
use crate::ast::model::Model;
use crate::ast::namespace::Namespace;
use crate::ast::pipeline_item_declaration::PipelineItemDeclaration;
use crate::ast::r#enum::Enum;
use crate::ast::source::Source;
use crate::ast::struct_declaration::StructDeclaration;
use crate::ast::top::Top;

pub struct Schema {
    pub(crate) sources: BTreeMap<usize, Source>,
    pub(crate) references: SchemaReferences,
}

impl Schema {

    pub fn main_source(&self) -> &Source {
        self.source(self.references.main_source.unwrap()).unwrap()
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

    pub(crate) fn find_config_declaration_by_name(&self, name: &str, availability: Availability) -> Option<&ConfigDeclaration> {
        for config_declaration in self.config_declarations() {
            if config_declaration.identifier.name() == name && config_declaration.define_availability.contains(availability) {
                return Some(config_declaration)
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

    // Public APIs

    pub fn sources(&self) -> Vec<&Source> {
        self.sources.values().collect()
    }

    pub fn configs(&self) -> Vec<&Config> {
        self.references.config_declarations.iter().map(|path| self.find_top_by_path(path).unwrap().as_config().unwrap()).collect()
    }

    pub fn server(&self) -> Option<&Config> {
        self.references.server.as_ref().map(|path| self.find_top_by_path(path).unwrap().as_config().unwrap())
    }

    pub fn debug(&self) -> Option<&Config> {
        self.references.debug.as_ref().map(|path| self.find_top_by_path(path).unwrap().as_config().unwrap())
    }

    pub fn test(&self) -> Option<&Config> {
        self.references.test.as_ref().map(|path| self.find_top_by_path(path).unwrap().as_config().unwrap())
    }

    pub fn connectors(&self) -> Vec<&Config> {
        self.references.connectors.iter().map(|path| self.find_top_by_path(path).unwrap().as_config().unwrap()).collect()
    }

    pub fn entities(&self) -> Vec<&Config> {
        self.references.entities.iter().map(|path| self.find_top_by_path(path).unwrap().as_config().unwrap()).collect()
    }

    pub fn clients(&self) -> Vec<&Config> {
        self.references.clients.iter().map(|path| self.find_top_by_path(path).unwrap().as_config().unwrap()).collect()
    }

    pub fn enums(&self) -> Vec<&Enum> {
        self.references.enums.iter().map(|path| self.find_top_by_path(path).unwrap().as_enum().unwrap()).collect()
    }

    pub fn models(&self) -> Vec<&Model> {
        self.references.models.iter().map(|path| self.find_top_by_path(path).unwrap().as_model().unwrap()).collect()
    }

    pub fn data_sets(&self) -> Vec<&DataSet> {
        self.references.data_sets.iter().map(|path| self.find_top_by_path(path).unwrap().as_data_set().unwrap()).collect()
    }

    pub fn interfaces(&self) -> Vec<&InterfaceDeclaration> {
        self.references.interfaces.iter().map(|path| self.find_top_by_path(path).unwrap().as_interface_declaration().unwrap()).collect()
    }

    pub fn namespaces(&self) -> Vec<&Namespace> {
        self.references.namespaces.iter().map(|path| self.find_top_by_path(path).unwrap().as_namespace().unwrap()).collect()
    }

    pub fn config_declarations(&self) -> Vec<&ConfigDeclaration> {
        self.references.config_declarations.iter().map(|path| self.find_top_by_path(path).unwrap().as_config_declaration().unwrap()).collect()
    }

    pub fn decorator_declarations(&self) -> Vec<&DecoratorDeclaration> {
        self.references.decorator_declarations.iter().map(|path| self.find_top_by_path(path).unwrap().as_decorator_declaration().unwrap()).collect()
    }

    pub fn pipeline_item_declarations(&self) -> Vec<&PipelineItemDeclaration> {
        self.references.pipeline_item_declarations.iter().map(|path| self.find_top_by_path(path).unwrap().as_pipeline_item_declaration().unwrap()).collect()
    }

    pub fn middleware_declarations(&self) -> Vec<&MiddlewareDeclaration> {
        self.references.middlewares.iter().map(|path| self.find_top_by_path(path).unwrap().as_middleware_declaration().unwrap()).collect()
    }

    pub fn handler_group_declarations(&self) -> Vec<&HandlerGroupDeclaration> {
        self.references.handler_groups.iter().map(|path| self.find_top_by_path(path).unwrap().as_handler_group_declaration().unwrap()).collect()
    }

    pub fn struct_declarations(&self) -> Vec<&StructDeclaration> {
        self.references.struct_declarations.iter().map(|path| self.find_top_by_path(path).unwrap().as_struct_declaration().unwrap()).collect()
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