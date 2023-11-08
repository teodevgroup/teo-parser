use std::collections::{BTreeMap, BTreeSet};
use indexmap::IndexMap;
use indexmap::map::{IntoIter, Iter, IterMut, Keys};
use serde::Serialize;
use crate::r#type::Type;

#[derive(Debug, Serialize, Clone)]
pub struct SynthesizedShape {
    map: IndexMap<String, Type>,
}

impl SynthesizedShape {

    pub fn new(map: IndexMap<String, Type>) -> Self {
        Self { map }
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn into_iter(self) -> IntoIter<String, Type> {
        self.map.into_iter()
    }

    pub fn iter(&self) -> Iter<String, Type> {
        self.map.iter()
    }

    pub fn iter_mut(&mut self) -> IterMut<String, Type> { self.map.iter_mut() }

    pub fn get(&self, key: &str) -> Option<&Type> {
        self.map.get(key)
    }

    pub fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    pub fn keys(&self) -> Keys<String, Type> {
        self.map.keys()
    }

    pub fn extend<I: IntoIterator<Item = (String, Type)>>(&mut self, iterable: I) {
        self.map.extend(iterable)
    }

    pub fn replace_generics(&self, map: &BTreeMap<String, Type>) -> Self {
        Self {
            map: self.map.iter().map(|(k, i)| (k.clone(), if let Some(t) = i.as_type() {
                t.replace_generics(map)
            } else {
                i.clone()
            })).collect()
        }
    }
}
