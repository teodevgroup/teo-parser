use std::fmt::{Display, Formatter};
use educe::Educe;
use serde::Serialize;

#[derive(Debug, Clone, Eq, Serialize)]
#[derive(Educe)]
#[educe(Hash, PartialEq)]
pub enum ModelShapeReference {
    Args(Vec<usize>, Vec<String>),
    FindManyArgs(Vec<usize>, Vec<String>),
}

impl Display for ModelShapeReference {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ModelShapeReference::Args(_, k) => f.write_str(&format!("Args<{}>", k.join("."))),
            ModelShapeReference::FindManyArgs(_, k) => f.write_str(&format!("FindManyArgs<{}>", k.join("."))),
        }
    }
}