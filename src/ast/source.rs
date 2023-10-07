use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use maplit::btreeset;
use crate::ast::import::Import;
use crate::ast::namespace::Namespace;
use crate::ast::top::Top;
use crate::definition::definition::Definition;
use crate::definition::definition_context::DefinitionContext;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum SourceType {
    Builtin,
    Normal,
}

pub(crate) struct Source {
    pub(crate) id: usize,
    pub(crate) r#type: SourceType,
    pub(crate) file_path: String,
    pub(crate) tops: BTreeMap<usize, Top>,
    pub(crate) references: SourceReferences,
}

impl Source {

    pub(crate) fn new(id: usize, r#type: SourceType, file_path: String, tops: BTreeMap<usize, Top>, references: SourceReferences) -> Self {
        Self {
            id,
            r#type,
            file_path,
            tops,
            references,
        }
    }

    pub(crate) fn tops(&self) -> Vec<&Top> {
        self.tops.values().collect()
    }

    pub(crate) fn imports(&self) -> Vec<&Import> {
        self.references.imports.iter().map(|id| self.tops.get(id).unwrap().as_import().unwrap()).collect()
    }

    pub(crate) fn namespaces(&self) -> Vec<&Namespace> {
        self.references.namespaces.iter().map(|m| self.get_namespace(*m).unwrap()).collect()
    }

    pub(crate) fn get_namespace(&self, id: usize) -> Option<&Namespace> {
        self.tops.get(&id).unwrap().as_namespace()
    }

    pub(crate) fn find_top_by_id(&self, id: usize) -> Option<&Top> {
        self.tops.get(&id)
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

    pub(crate) fn find_top_by_path(&self, path: &Vec<usize>) -> Option<&Top> {
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

    pub(crate) fn find_top_by_string_path(&self, path: &Vec<&str>, filter: &Arc<dyn Fn(&Top) -> bool>) -> Option<&Top> {
        if path.len() == 1 {
            self.find_top_by_name(path.get(0).unwrap(), filter)
        } else {
            let mut path_for_ns = path.clone();
            path_for_ns.remove(path_for_ns.len() - 1);
            let child_ns = self.find_child_namespace_by_string_path(&path_for_ns);
            if let Some(child_ns) = child_ns {
                child_ns.find_top_by_name(path.last().unwrap(), filter)
            } else {
                None
            }
        }
    }

    pub(crate) fn find_child_namespace_by_path(&self, path: &Vec<usize>) -> Option<&Namespace> {
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

    pub(crate) fn find_child_namespace_by_string_path(&self, path: &Vec<&str>) -> Option<&Namespace> {
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

    pub(crate) fn jump_to_definition(&self, context: &DefinitionContext, line_col: (usize, usize)) -> Vec<Definition> {
        for top in self.tops() {
            if top.span().contains_line_col(line_col) {
                return top.jump_to_definition(context, line_col);
            }
        }
        vec![]
    }
}

pub(crate) struct SourceReferences {
    pub(crate) imports: BTreeSet<usize>,
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

impl SourceReferences {

    pub(crate) fn new() -> Self {
        Self {
            imports: btreeset!{},
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
            action_groups: btreeset!{},
        }
    }
}