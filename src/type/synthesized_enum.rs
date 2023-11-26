use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use indexmap::IndexMap;
use itertools::Itertools;
use serde::Serialize;
use crate::ast::doc_comment::DocComment;

#[derive(Debug, Serialize, Clone, PartialEq, Eq, Hash)]
pub struct SynthesizedEnum {
    pub keys: Vec<String>,
    pub members: BTreeMap<String, SynthesizedEnumMember>
}

impl SynthesizedEnum {

    pub fn new(members: Vec<SynthesizedEnumMember>) -> Self {
        Self {
            keys: members.iter().map(|m| m.name.clone()).collect(),
            members: members.iter().map(|m| (m.name.clone(), m.clone())).collect()
        }
    }

}

#[derive(Debug, Serialize, Clone, PartialEq, Eq, Hash)]
pub struct SynthesizedEnumMember {
    pub name: String,
    pub comment: Option<DocComment>,
}

impl Display for SynthesizedEnum {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.members.keys().map(|a| format!(".{}", a)).join(" | "))
    }
}
