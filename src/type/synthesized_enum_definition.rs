use std::fmt::{Display, Formatter};
use indexmap::IndexMap;
use itertools::Itertools;
use serde::Serialize;
use crate::ast::comment::Comment;

#[derive(Debug, Serialize, Clone)]
pub struct SynthesizedEnumDefinition {
    pub members: IndexMap<String, SynthesizedEnumMember>
}

impl SynthesizedEnumDefinition {

    pub fn new(members: Vec<SynthesizedEnumMember>) -> Self {
        Self {
            members: members.iter().map(|m| (m.name.clone(), m.clone())).collect()
        }
    }

}

#[derive(Debug, Serialize, Clone)]
pub struct SynthesizedEnumMember {
    pub name: String,
    pub comment: Option<Comment>,
}

impl Display for SynthesizedEnumDefinition {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.members.keys().map(|a| format!("\"{}\"", a)).join(" | "))
    }
}
