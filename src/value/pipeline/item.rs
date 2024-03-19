use std::collections::BTreeMap;
use crate::value::Value;
use super::super::super::r#type::reference::Reference;

#[derive(Debug, Eq, PartialEq)]
pub struct Item {
    pub reference: Reference,
    pub args: BTreeMap<String, Value>
}