use std::collections::BTreeMap;
use serde::Serialize;
use crate::value::Value;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InterfaceEnumVariant {
    pub value: String,
    pub args: BTreeMap<String, Value>,
}

impl InterfaceEnumVariant {

    pub fn into_string(self) -> String {
        self.value
    }

    pub fn to_string(&self) -> String {
        self.value.clone()
    }

    pub fn normal_not(&self) -> bool {
        false
    }
}