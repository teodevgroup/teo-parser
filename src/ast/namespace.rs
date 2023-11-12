use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug};
use std::sync::Arc;
use maplit::btreeset;
use crate::ast::handler::HandlerGroupDeclaration;
use crate::availability::Availability;
use crate::ast::config::Config;
use crate::ast::data_set::DataSet;
use crate::ast::model::Model;
use crate::ast::r#enum::Enum;
use crate::ast::top::Top;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn, node_optional_child_fn};
use crate::ast::node::Node;

declare_container_node!(Namespace, named,
    pub(crate) comment: Option<usize>,
    pub(crate) identifier: usize,
    pub(crate) references: NamespaceReferences,
);

impl_container_node_defaults!(Namespace, named);

impl Namespace {

    node_child_fn!(identifier, Identifier);

    node_optional_child_fn!(comment, Comment);

    pub fn parent_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(1).rev().map(AsRef::as_ref).collect()
    }

    pub fn get_connector(&self) -> Option<&Config> {
        self.references.connector.map(|id| self.children.get(&id).unwrap().as_config().unwrap())
    }

    fn get_enum(&self, id: usize) -> Option<&Enum> {
        self.children.get(&id).unwrap().as_enum()
    }

    fn get_model(&self, id: usize) -> Option<&Model> {
        self.children.get(&id).unwrap().as_model()
    }

    pub fn get_namespace(&self, id: usize) -> Option<&Namespace> {
        self.children.get(&id).unwrap().as_namespace()
    }

    fn get_data_set(&self, id: usize) -> Option<&DataSet> {
        self.children.get(&id).unwrap().as_data_set()
    }

    fn get_handler_group(&self, id: usize) -> Option<&HandlerGroupDeclaration> {
        self.children.get(&id).unwrap().as_handler_group_declaration()
    }

    pub fn models(&self) -> Vec<&Model> {
        self.references.models.iter().map(|m| self.get_model(*m).unwrap()).collect()
    }

    pub fn enums(&self) -> Vec<&Enum> {
        self.references.enums.iter().map(|m| self.get_enum(*m).unwrap()).collect()
    }

    pub fn handler_groups(&self) -> Vec<&HandlerGroupDeclaration> {
        self.references.namespaces.iter().map(|m| self.get_handler_group(*m).unwrap()).collect()
    }

    pub fn namespaces(&self) -> Vec<&Namespace> {
        self.references.namespaces.iter().map(|m| self.get_namespace(*m).unwrap()).collect()
    }

    pub fn data_sets(&self) -> Vec<&DataSet> {
        self.references.data_sets.iter().map(|m| self.get_data_set(*m).unwrap()).collect()
    }

    pub fn find_top_by_name(&self, name: &str, filter: &Arc<dyn Fn(&Top) -> bool>, availability: Availability) -> Option<&Top> {
        self.tops().iter().find(|t| {
            if let Some(n) = t.name() {
                (n == name) && filter(t) && t.available_test(availability)
            } else {
                false
            }
        }).map(|t| *t)
    }

    pub fn find_top_by_id(&self, id: usize) -> Option<&Node> {
        self.children.get(&id)
    }

    pub fn find_top_by_string_path(&self, path: &Vec<&str>, filter: &Arc<dyn Fn(&Top) -> bool>, availability: Availability) -> Option<&Top> {
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

    pub fn find_child_namespace_by_string_path(&self, path: &Vec<&str>) -> Option<&Namespace> {
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
pub struct NamespaceReferences {
    pub constants: BTreeSet<usize>,
    pub connector: Option<usize>,
    pub configs: BTreeSet<usize>,
    pub enums: BTreeSet<usize>,
    pub models: BTreeSet<usize>,
    pub data_sets: BTreeSet<usize>,
    pub interfaces: BTreeSet<usize>,
    pub namespaces: BTreeSet<usize>,
    pub config_declarations: BTreeSet<usize>,
    pub decorator_declarations: BTreeSet<usize>,
    pub pipeline_item_declarations: BTreeSet<usize>,
    pub middlewares: BTreeSet<usize>,
    pub handler_groups: BTreeSet<usize>,
    pub struct_declarations: BTreeSet<usize>,
    pub use_middlewares_block: Option<usize>,
}

impl NamespaceReferences {

    pub fn new() -> Self {
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
            use_middlewares_block: None,
        }
    }
}