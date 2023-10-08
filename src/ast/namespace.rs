use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug};
use std::sync::Arc;
use maplit::btreeset;
use crate::ast::action::ActionGroupDeclaration;
use crate::ast::comment::Comment;
use crate::ast::config::Config;
use crate::ast::constant::Constant;
use crate::ast::data_set::DataSet;
use crate::ast::identifier::Identifier;
use crate::ast::interface::InterfaceDeclaration;
use crate::ast::middleware::Middleware;
use crate::ast::model::Model;
use crate::ast::r#enum::Enum;
use crate::ast::span::Span;
use crate::ast::top::Top;

#[derive(Debug)]
pub(crate) struct Namespace {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) parent_path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub(crate) parent_string_path: Vec<String>,
    pub(crate) comment: Option<Comment>,
    pub(crate) identifier: Identifier,
    pub(crate) tops: BTreeMap<usize, Top>,
    pub(crate) references: NamespaceReferences,
}

impl Namespace {

    pub(crate) fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub(crate) fn str_path(&self) -> Vec<&str> {
        self.string_path.iter().map(|s| s.as_str()).collect()
    }

    pub(crate) fn tops(&self) -> Vec<&Top> {
        self.tops.values().collect()
    }

    pub(crate) fn get_constant(&self, id: usize) -> &Constant {
        self.tops.get(&id).unwrap().as_constant().unwrap()
    }

    pub(crate) fn get_enum(&self, id: usize) -> &Enum {
        self.tops.get(&id).unwrap().as_enum().unwrap()
    }

    pub(crate) fn get_model(&self, id: usize) -> &Model {
        self.tops.get(&id).unwrap().as_model().unwrap()
    }

    pub(crate) fn get_namespace(&self, id: usize) -> Option<&Namespace> {
        self.tops.get(&id).unwrap().as_namespace()
    }

    pub(crate) fn get_config(&self, id: usize) -> &Config {
        self.tops.get(&id).unwrap().as_config().unwrap()
    }

    pub(crate) fn get_data_set(&self, id: usize) -> &DataSet {
        self.tops.get(&id).unwrap().as_data_set().unwrap()
    }

    pub(crate) fn get_middleware(&self, id: usize) -> &Middleware {
        self.tops.get(&id).unwrap().as_middleware().unwrap()
    }

    pub(crate) fn get_action_group(&self, id: usize) -> &ActionGroupDeclaration {
        self.tops.get(&id).unwrap().as_action_group().unwrap()
    }

    pub(crate) fn get_interface(&self, id: usize) -> &InterfaceDeclaration {
        self.tops.get(&id).unwrap().as_interface().unwrap()
    }

    pub(crate) fn models(&self) -> Vec<&Model> {
        self.references.models.iter().map(|m| self.get_model(*m)).collect()
    }

    pub(crate) fn enums(&self) -> Vec<&Enum> {
        self.references.enums.iter().map(|m| self.get_enum(*m)).collect()
    }

    pub(crate) fn action_groups(&self) -> Vec<&ActionGroupDeclaration> {
        self.references.namespaces.iter().map(|m| self.get_action_group(*m)).collect()
    }

    pub(crate) fn namespaces(&self) -> Vec<&Namespace> {
        self.references.namespaces.iter().map(|m| self.get_namespace(*m).unwrap()).collect()
    }

    pub(crate) fn data_sets(&self) -> Vec<&DataSet> {
        self.references.data_sets.iter().map(|m| self.get_data_set(*m)).collect()
    }

    pub(crate) fn find_top_by_name(&self, name: &str, filter: &Arc<dyn Fn(&Top) -> bool>) -> Option<&Top> {
        self.tops().iter().find(|t| {
            if let Some(n) = t.name() {
                (n == name) && filter(t)
            } else {
                false
            }
        }).map(|t| *t)
    }

    pub(crate) fn find_top_by_id(&self, id: usize) -> Option<&Top> {
        self.tops.get(&id)
    }

    pub(crate) fn find_top_by_string_path(&self, path: &Vec<&str>, filter: &Arc<dyn Fn(&Top) -> bool>) -> Option<&Top> {
        if path.len() == 1 {
            self.find_top_by_name(path.get(0).unwrap(), filter)
        } else {
            let mut path_for_ns = path.clone();
            path_for_ns.remove(path_for_ns.len() - 1);
            let child_ns = self.find_child_namespace_by_string_path(&path_for_ns);
            return if let Some(child_ns) = child_ns {
                child_ns.find_top_by_name(path.last().unwrap(), filter)
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
    pub(crate) action_groups: BTreeSet<usize>,
}

impl NamespaceReferences {

    pub(crate) fn new() -> Self {
        Self {
            constants: btreeset!{},
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
            action_groups: btreeset!{},
        }
    }
}