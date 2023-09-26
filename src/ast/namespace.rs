use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug};
use maplit::btreeset;
use crate::ast::action::ActionGroupDeclaration;
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
    pub(crate) path: Vec<usize>,
    pub(crate) parent_path: Vec<usize>,
    pub(crate) span: Span,
    pub(crate) identifier: Identifier,
    pub(crate) tops: BTreeMap<usize, Top>,
    pub(crate) references: NamespaceReferences,
}

impl Namespace {

    pub(crate) fn new(
        path: Vec<usize>,
        parent_path: Vec<usize>,
        span: Span,
        identifier: Identifier,
        tops: BTreeMap<usize, Top>,
        references: NamespaceReferences,
    ) -> Self {
        Self {
            path,
            parent_path,
            span,
            identifier,
            tops,
            references,
        }
    }

    pub(crate) fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
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

    pub(crate) fn get_namespace(&self, id: usize) -> &Namespace {
        self.tops.get(&id).unwrap().as_namespace().unwrap()
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
        self.references.namespaces.iter().map(|m| self.get_namespace(*m)).collect()
    }

    pub(crate) fn data_sets(&self) -> Vec<&DataSet> {
        self.references.data_sets.iter().map(|m| self.get_data_set(*m)).collect()
    }

    pub(crate) fn get_model_by_name(&self, name: &str) -> Option<&Model> {
        self.models().iter().find(|m| m.identifier.name.as_str() == name).map(|r| *r)
    }

    pub(crate) fn get_enum_by_name(&self, name: &str) -> Option<&Enum> {
        self.enums().iter().find(|m| m.identifier.name.as_str() == name).map(|r| *r)
    }

    pub(crate) fn get_namespace_by_path(&self, path: Vec<&str>) -> Option<&Namespace> {
        let mut retval = self;
        for item in path {
            if let Some(child) = retval.namespaces().iter().find(|n| n.identifier.name.as_str() == item) {
                retval = child
            } else {
                return None
            }
        }
        Some(retval)
    }

    pub(crate) fn get_model_by_path(&self, path: Vec<&str>) -> Option<&Model> {
        if path.len() == 1 {
            self.get_model_by_name(path.get(0).unwrap())
        } else {
            let mut path_for_ns = path.clone();
            path_for_ns.remove(path_for_ns.len() - 1);
            let child_ns = self.get_namespace_by_path(path_for_ns.clone());
            return if let Some(child_ns) = child_ns {
                child_ns.get_model_by_name(path_for_ns.last().unwrap())
            } else {
                None
            }
        }
    }

    pub(crate) fn get_enum_by_path(&self, path: Vec<&str>) -> Option<&Enum> {
        if path.len() == 1 {
            self.get_enum_by_name(path.get(0).unwrap())
        } else {
            let mut path_for_ns = path.clone();
            path_for_ns.remove(path_for_ns.len() - 1);
            let child_ns = self.get_namespace_by_path(path_for_ns.clone());
            return if let Some(child_ns) = child_ns {
                child_ns.get_enum_by_name(path_for_ns.last().unwrap())
            } else {
                None
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct NamespaceReferences {
    pub(crate) constants: BTreeSet<usize>,
    pub(crate) enums: BTreeSet<usize>,
    pub(crate) models: BTreeSet<usize>,
    pub(crate) namespaces: BTreeSet<usize>,
    pub(crate) data_sets: BTreeSet<usize>,
}

impl NamespaceReferences {

    pub(crate) fn new() -> Self {
        Self {
            constants: btreeset!{},
            enums: btreeset!{},
            models: btreeset!{},
            namespaces: btreeset!{},
            data_sets: btreeset!{},
        }
    }
}