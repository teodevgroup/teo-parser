use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::AtomicBool;
use maplit::btreeset;
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
}

pub(crate) struct SourceReferences {
    pub(crate) imports: BTreeSet<usize>,
    pub(crate) constants: BTreeSet<usize>,
    pub(crate) enums: BTreeSet<usize>,
    pub(crate) models: BTreeSet<usize>,
    pub(crate) namespaces: BTreeSet<usize>,
    pub(crate) data_sets: BTreeSet<usize>,
}

impl SourceReferences {

    pub(crate) fn new() -> Self {
        Self {
            imports: btreeset!{},
            constants: btreeset!{},
            enums: btreeset!{},
            models: btreeset!{},
            namespaces: btreeset!{},
            data_sets: btreeset!{},
        }
    }
}