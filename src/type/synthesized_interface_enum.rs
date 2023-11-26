use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use itertools::Itertools;
use serde::Serialize;
use crate::ast::doc_comment::DocComment;
use crate::r#type::Type;

#[derive(Debug, Serialize, Clone, PartialEq, Eq, Hash)]
pub struct SynthesizedInterfaceEnum {
    pub keys: Vec<String>,
    pub members: BTreeMap<String, SynthesizedInterfaceEnumMember>
}

impl SynthesizedInterfaceEnum {

    pub fn new(members: Vec<SynthesizedInterfaceEnumMember>) -> Self {
        Self {
            keys: members.iter().map(|m| m.name.clone()).collect(),
            members: members.iter().map(|m| (m.name.clone(), m.clone())).collect()
        }
    }

}

#[derive(Debug, Serialize, Clone, PartialEq, Eq, Hash)]
pub struct SynthesizedInterfaceEnumMember {
    pub name: String,
    pub arg_keys: Vec<String>,
    pub args: BTreeMap<String, Type>,
    pub comment: Option<DocComment>,
}

impl Display for SynthesizedInterfaceEnumMember {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let args = if self.args.is_empty() {
            "".to_owned()
        } else {
            format!("({})", self.args.iter().map(|(k, v)| format!("{k}: {v}")).join(", "))
        };
        f.write_str(&format!(".{}{}", self.name, args))

    }
}

impl Display for SynthesizedInterfaceEnum {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.members.values().map(|a| format!("{}", a)).join(" | "))
    }
}
