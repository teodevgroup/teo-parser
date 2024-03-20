use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use crate::value::Value;
use super::super::super::r#type::reference::Reference;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Item {
    pub reference: Reference,
    pub args: BTreeMap<String, Value>
}

impl Display for Item {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reference.str_path().join("."))?;
        if !self.args.is_empty() {
            f.write_str("(...args)")?;
        }
        Ok(())
    }
}