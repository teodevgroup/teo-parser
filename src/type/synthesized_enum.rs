use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use educe::Educe;
use serde::Serialize;
use crate::r#type::keyword::Keyword;
use crate::r#type::Type;

#[derive(Debug, Clone, Eq, Serialize)]
#[derive(Educe)]
#[educe(Hash, PartialEq)]
pub enum SynthesizedEnum {
    ModelScalarFields(Box<Type>),
    ModelSerializableScalarFields(Box<Type>),
    ModelRelations(Box<Type>),
    ModelDirectRelations(Box<Type>),
    ModelIndirectRelations(Box<Type>),
}

impl SynthesizedEnum {

    pub fn contains_generics(&self) -> bool {
        match self {
            SynthesizedEnum::ModelScalarFields(t) => t.contains_generics(),
            SynthesizedEnum::ModelSerializableScalarFields(t) => t.contains_generics(),
            SynthesizedEnum::ModelRelations(t) => t.contains_generics(),
            SynthesizedEnum::ModelDirectRelations(t) => t.contains_generics(),
            SynthesizedEnum::ModelIndirectRelations(t) => t.contains_generics(),
        }
    }

    pub fn replace_keywords(&self, map: &BTreeMap<Keyword, &Type>) -> SynthesizedEnum {
        match self {
            Self::ModelScalarFields(t) => Self::ModelScalarFields(Box::new(t.replace_keywords(map))),
            Self::ModelSerializableScalarFields(t) => Self::ModelSerializableScalarFields(Box::new(t.replace_keywords(map))),
            Self::ModelRelations(t) => Self::ModelRelations(Box::new(t.replace_keywords(map))),
            Self::ModelDirectRelations(t) => Self::ModelDirectRelations(Box::new(t.replace_keywords(map))),
            Self::ModelIndirectRelations(t) => Self::ModelDirectRelations(Box::new(t.replace_keywords(map))),
        }
    }

    pub fn replace_generics(&self, map: &BTreeMap<String, Type>) -> SynthesizedEnum {
        match self {
            Self::ModelScalarFields(t) => Self::ModelScalarFields(Box::new(t.replace_generics(map))),
            Self::ModelSerializableScalarFields(t) => Self::ModelSerializableScalarFields(Box::new(t.replace_generics(map))),
            Self::ModelRelations(t) => Self::ModelRelations(Box::new(t.replace_generics(map))),
            Self::ModelDirectRelations(t) => Self::ModelDirectRelations(Box::new(t.replace_generics(map))),
            Self::ModelIndirectRelations(t) => Self::ModelDirectRelations(Box::new(t.replace_generics(map))),
        }
    }
}

impl Display for SynthesizedEnum {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SynthesizedEnum::ModelScalarFields(t) => f.write_str(&format!("ModelScalarFields<{}>", t)),
            SynthesizedEnum::ModelSerializableScalarFields(t) => f.write_str(&format!("ModelSerializableScalarFields<{}>", t)),
            SynthesizedEnum::ModelRelations(t) => f.write_str(&format!("ModelRelations<{}>", t)),
            SynthesizedEnum::ModelDirectRelations(t) => f.write_str(&format!("ModelDirectRelations<{}>", t)),
            SynthesizedEnum::ModelIndirectRelations(t) => f.write_str(&format!("ModelIndirectRelations<{}>", t)),
        }
    }
}