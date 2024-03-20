use std::collections::BTreeMap;
use std::fmt::{Display, Formatter, Write};
use serde::Serialize;
use crate::value::Value;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InterfaceEnumVariant {
    pub value: String,
    pub args: Option<BTreeMap<String, Value>>,
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

impl Display for InterfaceEnumVariant {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(".")?;
        f.write_str(self.value.as_str())?;
        if let Some(args) = &self.args {
            f.write_str("(...args)")?;
        }
        Ok(())
    }
}