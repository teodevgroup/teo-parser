use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use maplit::btreeset;
use crate::ast::availability::Availability;
use crate::ast::config::Config;
use crate::ast::import::Import;
use crate::ast::namespace::Namespace;
use crate::ast::top::Top;

#[derive(Debug)]
pub struct Source {
    pub id: usize,
    pub builtin: bool,
    pub file_path: String,
    pub tops: BTreeMap<usize, Top>,
    pub references: SourceReferences,
}

impl Source {

    pub fn new(id: usize, builtin: bool, file_path: String, tops: BTreeMap<usize, Top>, references: SourceReferences) -> Self {
        Self {
            id,
            builtin,
            file_path,
            tops,
            references,
        }
    }

    pub fn tops(&self) -> Vec<&Top> {
        self.tops.values().collect()
    }

    pub fn imports(&self) -> Vec<&Import> {
        self.references.imports.iter().map(|id| self.tops.get(id).unwrap().as_import().unwrap()).collect()
    }

    pub fn namespaces(&self) -> Vec<&Namespace> {
        self.references.namespaces.iter().map(|m| self.get_namespace(*m).unwrap()).collect()
    }

    pub fn get_connector(&self) -> Option<&Config> {
        self.references.connector.map(|id| self.tops.get(&id).unwrap().as_config().unwrap())
    }

    pub fn get_namespace(&self, id: usize) -> Option<&Namespace> {
        self.tops.get(&id).unwrap().as_namespace()
    }

    pub fn find_top_by_id(&self, id: usize) -> Option<&Top> {
        self.tops.get(&id)
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

    pub fn find_top_by_path(&self, path: &Vec<usize>) -> Option<&Top> {
        if *path.first().unwrap() != self.id {
            return None;
        }
        if path.len() < 2 {
            return None;
        } else if path.len() == 2 {
            self.find_top_by_id(*path.get(1).unwrap())
        } else {
            let mut path_for_ns = path.clone();
            path_for_ns.remove(path_for_ns.len() - 1);
            let child_ns = self.find_child_namespace_by_path(&path_for_ns);
            if let Some(child_ns) = child_ns {
                child_ns.find_top_by_id(*path.last().unwrap())
            } else {
                None
            }
        }
    }

    pub fn find_top_by_string_path(&self, path: &Vec<&str>, filter: &Arc<dyn Fn(&Top) -> bool>, availability: Availability) -> Option<&Top> {
        if path.len() == 1 {
            self.find_top_by_name(path.get(0).unwrap(), filter, availability)
        } else {
            let mut path_for_ns = path.clone();
            path_for_ns.remove(path_for_ns.len() - 1);
            let child_ns = self.find_child_namespace_by_string_path(&path_for_ns);
            if let Some(child_ns) = child_ns {
                child_ns.find_top_by_name(path.last().unwrap(), filter, availability)
            } else {
                None
            }
        }
    }

    pub fn parent_namespace_for_namespace(&self, namespace: &Namespace) -> Option<&Namespace> {
        self.find_child_namespace_by_string_path(&namespace.parent_str_path())
    }

    pub fn find_child_namespace_by_path(&self, path: &Vec<usize>) -> Option<&Namespace> {
        if *path.first().unwrap() != self.id {
            return None;
        }
        let mut ns = self.get_namespace(*path.get(1).unwrap());
        for (index, item) in path.iter().enumerate() {
            if index > 1 {
                if let Some(ns_ref) = ns {
                    ns = ns_ref.get_namespace(*item);
                } else {
                    return None;
                }
            }
        }
        ns
    }

    pub fn find_child_namespace_by_string_path(&self, path: &Vec<&str>) -> Option<&Namespace> {
        if path.len() == 0 { return None }
        let mut ns = self.namespaces().iter().find(|n| n.identifier.name() == *path.get(0).unwrap()).map(|r| *r);
        for (index, item) in path.iter().enumerate() {
            if index > 0 {
                if let Some(ns_ref) = ns {
                    ns = ns_ref.namespaces().iter().find(|n| n.identifier.name() == *item).map(|r| *r);
                } else {
                    return None;
                }
            }
        }
        ns
    }
}

#[derive(Debug)]
pub struct SourceReferences {
    pub imports: BTreeSet<usize>,
    pub connector: Option<usize>,
    pub constants: BTreeSet<usize>,
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
    pub use_middlewares_block: Option<usize>,
}

impl SourceReferences {

    pub fn new() -> Self {
        Self {
            imports: btreeset!{},
            connector: None,
            constants: btreeset!{},
            configs: btreeset!{},
            enums: btreeset!{},
            models: btreeset!{},
            namespaces: btreeset!{},
            interfaces: btreeset!{},
            data_sets: btreeset!{},
            config_declarations: btreeset!{},
            decorator_declarations: btreeset!{},
            pipeline_item_declarations: btreeset!{},
            middlewares: btreeset!{},
            handler_groups: btreeset!{},
            use_middlewares_block: None,
        }
    }
}