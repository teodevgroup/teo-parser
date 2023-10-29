use indexmap::IndexMap;
use indexmap::map::{Iter, Keys};
use serde::Serialize;
use crate::r#type::Type;
use crate::shape::input::Input;

#[derive(Debug, Serialize)]
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
}
