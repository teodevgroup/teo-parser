use std::collections::{BTreeMap, BTreeSet};
use indexmap::IndexMap;
use indexmap::map::{IntoIter, Iter, IterMut, Keys};
use serde::Serialize;
use crate::r#type::Type;

#[derive(Debug, Serialize, Clone)]
pub struct SynthesizedShape {
    generics: Vec<String>,
    fields: IndexMap<String, Type>,
}

impl SynthesizedShape {

    pub fn new(map: IndexMap<String, Type>) -> Self {
        Self { fields: map, generics: vec![] }
    }

    pub fn generics(&self) -> &Vec<String> {
        &self.generics
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    pub fn into_iter(self) -> IntoIter<String, Type> {
        self.fields.into_iter()
    }

    pub fn iter(&self) -> Iter<String, Type> {
        self.fields.iter()
    }

    pub fn iter_mut(&mut self) -> IterMut<String, Type> { self.fields.iter_mut() }

    pub fn get(&self, key: &str) -> Option<&Type> {
        self.fields.get(key)
    }

    pub fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    pub fn keys(&self) -> Keys<String, Type> {
        self.fields.keys()
    }

    pub fn extend<I: IntoIterator<Item = (String, Type)>>(&mut self, iterable: I) {
        self.fields.extend(iterable)
    }

    pub fn replace_generics(&self, map: &BTreeMap<String, Type>) -> Self {
        Self {
            generics: vec![],
            fields: self.fields.iter().map(|(k, i)| (k.clone(), if let Some(t) = i.as_type() {
                t.replace_generics(map)
            } else {
                i.clone()
            })).collect()
        }
    }
}
