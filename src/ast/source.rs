use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::AtomicBool;
use maplit::btreeset;
use crate::ast::import::Import;
use crate::ast::top::Top;

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
    pub(crate) resolved_1: AtomicBool,
    pub(crate) resolved_2: AtomicBool,
    pub(crate) resolved_3: AtomicBool,
}

impl Source {

    pub(crate) fn new(id: usize, r#type: SourceType, file_path: String, tops: BTreeMap<usize, Top>, references: SourceReferences) -> Self {
        Self {
            id,
            r#type,
            file_path,
            tops,
            references,
            resolved_1: AtomicBool::new(false),
            resolved_2: AtomicBool::new(false),
            resolved_3: AtomicBool::new(false),
        }
    }

    pub(crate) fn tops(&self) -> Vec<&Top> {
        self.tops.values().collect()
    }

    pub(crate) fn imports(&self) -> Vec<&Import> {
        self.references.imports.iter().map(|id| self.tops.get(id).unwrap().as_import().unwrap()).collect()
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
        }
    }
}