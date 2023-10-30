use indexmap::IndexMap;
use serde::Serialize;
use crate::ast::comment::Comment;

#[derive(Debug, Serialize, Clone)]
pub struct SynthesizedEnum {
    pub members: IndexMap<String, SynthesizedEnumMember>
}

impl SynthesizedEnum {

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
