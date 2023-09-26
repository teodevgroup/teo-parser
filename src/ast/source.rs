use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::AtomicBool;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum SourceType {
    Builtin,
    Main,
    Normal,
}

pub(crate) struct Source {
    id: usize,
    r#type: SourceType,
    file_path: String,
    //tops: BTreeMap<usize, Top>,
    references: SourceReferences,
    resolved_1: AtomicBool,
    resolved_2: AtomicBool,
    resolved_3: AtomicBool,
}

pub(crate) struct SourceReferences {
    pub(crate) imports: BTreeSet<usize>,
    pub(crate) constants: BTreeSet<usize>,
    pub(crate) enums: BTreeSet<usize>,
    pub(crate) models: BTreeSet<usize>,
    pub(crate) namespaces: BTreeSet<usize>,
    pub(crate) data_sets: BTreeSet<usize>,
}