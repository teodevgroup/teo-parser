use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use educe::Educe;
use serde::Serialize;
use crate::r#type::keyword::Keyword;
use crate::r#type::Type;
use strum_macros::{Display, EnumString, AsRefStr};
use crate::ast::schema::Schema;
use crate::r#type::synthesized_enum::SynthesizedEnum;


#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Serialize, Display, EnumString, AsRefStr)]
pub enum SynthesizedEnumReferenceKind {
    ModelScalarFields,
    ModelSerializableScalarFields,
    ModelRelations,
    ModelDirectRelations,
    ModelIndirectRelations,
}

#[derive(Debug, Clone, Eq, Serialize)]
#[derive(Educe)]
#[educe(Hash, PartialEq)]
pub struct SynthesizedEnumReference {
    pub kind: SynthesizedEnumReferenceKind,
    pub owner: Box<Type>,
}

impl SynthesizedEnumReference {

    pub fn contains_generics(&self) -> bool {
        self.owner.contains_generics()
    }

    pub fn replace_keywords(&self, map: &BTreeMap<Keyword, Type>) -> SynthesizedEnumReference {
        Self {
            kind: self.kind,
            owner: Box::new(self.owner.replace_keywords(map)),
        }
    }

    pub fn replace_generics(&self, map: &BTreeMap<String, Type>) -> SynthesizedEnumReference {
        Self {
            kind: self.kind,
            owner: Box::new(self.owner.replace_generics(map)),
        }
    }

    pub fn fetch_synthesized_definition(&self, schema: &Schema) -> Option<&SynthesizedEnum> {
        let model = schema.find_top_by_path(self.owner.as_model_object().unwrap().path()).unwrap().as_model().unwrap();
        model.resolved().enums.get(&self.kind)
    }
}

impl Display for SynthesizedEnumReference {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{}<{}>", self.kind, self.owner))
    }
}