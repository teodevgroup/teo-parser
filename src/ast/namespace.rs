use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug};
use std::sync::Arc;
use maplit::btreeset;
use crate::ast::handler::HandlerGroupDeclaration;
use crate::ast::availability::Availability;
use crate::ast::comment::Comment;
use crate::ast::config::Config;
use crate::ast::constant::Constant;
use crate::ast::data_set::DataSet;
use crate::ast::identifier::Identifier;
use crate::ast::interface::InterfaceDeclaration;
use crate::ast::middleware::MiddlewareDeclaration;
use crate::ast::model::Model;
use crate::ast::r#enum::Enum;
use crate::ast::span::Span;
use crate::ast::top::Top;

#[derive(Debug)]
pub struct Namespace {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub comment: Option<Comment>,
    pub(crate) identifier: Identifier,
    pub(crate) tops: BTreeMap<usize, Top>,
    pub(crate) references: NamespaceReferences,
}

impl Namespace {

    pub fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub fn str_path(&self) -> Vec<&str> {
        self.string_path.iter().map(AsRef::as_ref).collect()
    }

    pub(crate) fn parent_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(1).rev().map(AsRef::as_ref).collect()
    }

    pub(crate) fn tops(&self) -> Vec<&Top> {
        self.tops.values().collect()
    }

    pub(crate) fn get_connector(&self) -> Option<&Config> {
        self.references.connector.map(|id| self.tops.get(&id).unwrap().as_config().unwrap())
    }

    fn get_enum(&self, id: usize) -> Option<&Enum> {
        self.tops.get(&id).unwrap().as_enum()
    }

    fn get_model(&self, id: usize) -> Option<&Model> {
        self.tops.get(&id).unwrap().as_model()
    }

    pub(crate) fn get_namespace(&self, id: usize) -> Option<&Namespace> {
        self.tops.get(&id).unwrap().as_namespace()
    }

    fn get_data_set(&self, id: usize) -> Option<&DataSet> {
        self.tops.get(&id).unwrap().as_data_set()
    }

    fn get_handler_group(&self, id: usize) -> Option<&HandlerGroupDeclaration> {
        self.tops.get(&id).unwrap().as_handler_group_declaration()
    }

    pub(crate) fn models(&self) -> Vec<&Model> {
        self.references.models.iter().map(|m| self.get_model(*m).unwrap()).collect()
    }

    pub(crate) fn enums(&self) -> Vec<&Enum> {
        self.references.enums.iter().map(|m| self.get_enum(*m).unwrap()).collect()
    }

    pub(crate) fn handler_groups(&self) -> Vec<&HandlerGroupDeclaration> {
        self.references.namespaces.iter().map(|m| self.get_handler_group(*m).unwrap()).collect()
    }

    pub(crate) fn namespaces(&self) -> Vec<&Namespace> {
        self.references.namespaces.iter().map(|m| self.get_namespace(*m).unwrap()).collect()
    }

    pub(crate) fn data_sets(&self) -> Vec<&DataSet> {
        self.references.data_sets.iter().map(|m| self.get_data_set(*m).unwrap()).collect()
    }

    pub(crate) fn find_top_by_name(&self, name: &str, filter: &Arc<dyn Fn(&Top) -> bool>, availability: Availability) -> Option<&Top> {
        self.tops().iter().find(|t| {
            if let Some(n) = t.name() {
                (n == name) && filter(t) && t.available_test(availability)
            } else {
                false
            }
        }).map(|t| *t)
    }

    pub(crate) fn find_top_by_id(&self, id: usize) -> Option<&Top> {
        self.tops.get(&id)
    }

    pub(crate) fn find_top_by_string_path(&self, path: &Vec<&str>, filter: &Arc<dyn Fn(&Top) -> bool>, availability: Availability) -> Option<&Top> {
        if path.len() == 1 {
            self.find_top_by_name(path.get(0).unwrap(), filter, availability)
        } else {
            let mut path_for_ns = path.clone();
            path_for_ns.remove(path_for_ns.len() - 1);
            let child_ns = self.find_child_namespace_by_string_path(&path_for_ns);
            return if let Some(child_ns) = child_ns {
                child_ns.find_top_by_name(path.last().unwrap(), filter, availability)
            } else {
                None
            }
        }
    }

    pub(crate) fn find_child_namespace_by_string_path(&self, path: &Vec<&str>) -> Option<&Namespace> {
        let mut retval = self;
        for name in path {
            if let Some(child) = retval.namespaces().iter().find(|n| n.identifier.name() == *name) {
                retval = child
            } else {
                return None
            }
        }
        Some(retval)
    }
}

#[derive(Debug)]
pub(crate) struct NamespaceReferences {
    pub(crate) constants: BTreeSet<usize>,
    pub(crate) connector: Option<usize>,
    pub(crate) configs: BTreeSet<usize>,
    pub(crate) enums: BTreeSet<usize>,
    pub(crate) models: BTreeSet<usize>,
    pub(crate) data_sets: BTreeSet<usize>,
    pub(crate) interfaces: BTreeSet<usize>,
    pub(crate) namespaces: BTreeSet<usize>,
    pub(crate) config_declarations: BTreeSet<usize>,
    pub(crate) decorator_declarations: BTreeSet<usize>,
    pub(crate) pipeline_item_declarations: BTreeSet<usize>,
    pub(crate) middlewares: BTreeSet<usize>,
    pub(crate) handler_groups: BTreeSet<usize>,
    pub(crate) struct_declarations: BTreeSet<usize>,
}

impl NamespaceReferences {

    pub(crate) fn new() -> Self {
        Self {
            constants: btreeset!{},
            connector: None,
            configs: btreeset!{},
            enums: btreeset!{},
            models: btreeset!{},
            data_sets: btreeset!{},
            interfaces: btreeset!{},
            namespaces: btreeset!{},
            config_declarations: btreeset!{},
            decorator_declarations: btreeset!{},
            pipeline_item_declarations: btreeset!{},
            middlewares: btreeset!{},
            handler_groups: btreeset!{},
            struct_declarations: btreeset!{},
        }
    }
}