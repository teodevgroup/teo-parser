use std::collections::{BTreeMap, BTreeSet};
use std::collections::btree_map::{IntoIter, Iter, IterMut, Keys};
use std::fmt::{Display, Formatter};
use indexmap::IndexMap;
use itertools::Itertools;
use maplit::btreemap;
use serde::Serialize;
use crate::ast::schema::Schema;
use crate::r#type::keyword::Keyword;
use crate::r#type::Type;
use crate::resolver::resolve_interface_shapes::calculate_generics_map;
use crate::traits::resolved::Resolve;

#[derive(Debug, Serialize, Clone, PartialEq, Eq, Hash)]
pub struct SynthesizedShape {
    generics: Vec<String>,
    keys: Vec<String>,
    fields: BTreeMap<String, Type>,
}

impl SynthesizedShape {

    pub fn new(map: IndexMap<String, Type>) -> Self {
        Self {
            keys: map.keys().cloned().collect(),
            fields: map.into_iter().collect(),
            generics: vec![]
        }
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
        let my_generics: BTreeSet<String> = self.generics.clone().into_iter().collect();
        let map_generics: BTreeSet<String> = map.keys().cloned().collect();
        let generics = my_generics.difference(&map_generics).cloned().collect();
        Self {
            generics,
            keys: self.keys.clone(),
            fields: self.fields.iter().map(|(k, t)| (k.clone(), t.replace_generics(map))).collect()
        }
    }

    pub fn replace_keywords(&self, map: &BTreeMap<Keyword, Type>) -> Self {
        Self {
            generics: self.generics.clone(),
            keys: self.keys.clone(),
            fields: self.fields.iter().map(|(k, t)| (k.clone(), t.replace_keywords(map))).collect()
        }
    }

    pub fn contains_generics(&self) -> bool {
        !self.generics.is_empty()
    }

    pub fn contains_keywords(&self) -> bool {
        self.fields.values().any(|v| v.contains_keywords())
    }

    pub fn can_coerce_to(&self, other: &Type, schema: &Schema) -> bool {
        if let Some(field_type) = other.as_dictionary() {
            for (_, v) in self.iter() {
                if !field_type.test(v) {
                    return false;
                }
            }
            true
        } else if let Some((reference, types)) = other.as_interface_object() {
            let interface_declaration = schema.find_top_by_path(reference.path()).unwrap().as_interface_declaration().unwrap();
            let shape = interface_declaration.resolved().shape().replace_generics(&calculate_generics_map(interface_declaration.generics_declaration(), types));
            self.can_coerce_to_shape(&shape)
        } else if let Some(synthesized_shape) = other.as_synthesized_shape() {
            self.can_coerce_to_shape(synthesized_shape)
        } else if let Some(synthesized_shape_reference) = other.as_synthesized_shape_reference() {
            if let Some(t) = synthesized_shape_reference.fetch_synthesized_definition(schema) {
                self.can_coerce_to(t, schema)
            } else {
                false
            }
        } else {
            false
        }
    }

    fn can_coerce_to_shape(&self, shape: &SynthesizedShape) -> bool {
        if self.all_keys().difference(&shape.all_keys()).count() > 0 {
            return false;
        }
        for (k, v) in shape.iter() {
            if !v.is_optional() && self.get(k).is_none() {
                return false;
            }
            if let Some(self_v) = self.get(k) {
                if !v.test(self_v) {
                    return false;
                }
            }
        }
        true
    }

    pub fn test(&self, other: &SynthesizedShape) -> bool {
        let self_keys: BTreeSet<String> = self.fields.keys().cloned().collect();
        let other_keys: BTreeSet<String> = other.keys().cloned().collect();
        if other_keys.difference(&self_keys).count() > 0 {
            return false;
        }
        let mut map: BTreeMap<String, Type> = btreemap! {};
        for other_key in &other_keys {
            let self_type = self.fields.get(other_key).unwrap().replace_generics(&map);
            let other_type = other.fields.get(other_key).unwrap();
            if !self_type.test(other_type) {
                return false
            }
            if self_type.is_generic_item() {
                map.insert(self_type.as_generic_item().unwrap().to_string(), other_type.clone());
            }
        }
        true
    }

    pub fn required_keys(&self) -> BTreeSet<&str> {
        self.iter().filter_map(|(k, v)| if !v.is_optional() { Some(k.as_str()) } else { None }).collect()
    }

    pub fn all_keys(&self) -> BTreeSet<&str> {
        self.keys().into_iter().map(|k| k.as_str()).collect()
    }
}

impl Display for SynthesizedShape {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if !self.generics.is_empty() {
            f.write_str("<")?;
            f.write_str(&self.generics.join(", "))?;
            f.write_str(">")?;
        }
        f.write_str("{")?;
        f.write_str(&self.fields.iter().map(|(k, t)| format!("{}: {}", k, t)).join(", "))?;
        f.write_str("}")
    }
}