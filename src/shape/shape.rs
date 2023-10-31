use std::collections::{BTreeMap, BTreeSet};
use indexmap::IndexMap;
use indexmap::map::{IntoIter, Iter, Keys};
use serde::Serialize;
use crate::shape::input::Input;
use crate::r#type::Type;

#[derive(Debug, Serialize, Clone)]
pub struct Shape {
    map: IndexMap<String, Input>,
}

impl Shape {

    pub fn new(map: IndexMap<String, Input>) -> Self {
        Self { map }
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn into_iter(self) -> IntoIter<String, Input> {
        self.map.into_iter()
    }

    pub fn iter(&self) -> Iter<String, Input> {
        self.map.iter()
    }

    pub fn get(&self, key: &str) -> Option<&Input> {
        self.map.get(key)
    }

    pub fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    pub fn keys(&self) -> Keys<String, Input> {
        self.map.keys()
    }

    pub fn extend<I: IntoIterator<Item = (String, Input)>>(&mut self, iterable: I) {
        self.map.extend(iterable)
    }

    pub fn replace_generics(&self, map: &BTreeMap<String, Type>) -> Self {
        Self {
            map: self.map.iter().map(|(k, i)| (k.clone(), if let Some(t) = i.as_type() {
                Input::Type(t.replace_generics(map))
            } else {
                i.clone()
            })).collect()
        }
    }
}
