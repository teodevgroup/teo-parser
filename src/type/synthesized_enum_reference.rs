use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use educe::Educe;
use serde::Serialize;
use crate::r#type::keyword::Keyword;
use crate::r#type::Type;
use strum_macros::{Display, EnumString, AsRefStr, EnumIter};
use crate::ast::schema::Schema;
use crate::r#type::reference::Reference;
use crate::r#type::synthesized_enum::SynthesizedEnum;
use crate::traits::resolved::Resolve;


#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Serialize, Display, EnumString, AsRefStr, EnumIter)]
pub enum SynthesizedEnumReferenceKind {
    ScalarFields,
    SerializableScalarFields,
    Relations,
    DirectRelations,
    IndirectRelations,
}

#[derive(Debug, Clone, Eq, Serialize)]
#[derive(Educe)]
#[educe(Hash, PartialEq)]
pub struct SynthesizedEnumReference {
    pub kind: SynthesizedEnumReferenceKind,
    pub owner: Box<Type>,
}

impl SynthesizedEnumReference {

    pub fn model_scalar_fields(reference: Reference) -> Self {
        Self {
            kind: SynthesizedEnumReferenceKind::ScalarFields,
            owner: Box::new(Type::ModelObject(reference)),
        }
    }

    pub fn model_serializable_scalar_fields(reference: Reference) -> Self {
        Self {
            kind: SynthesizedEnumReferenceKind::SerializableScalarFields,
            owner: Box::new(Type::ModelObject(reference)),
        }
    }

    pub fn model_relations(reference: Reference) -> Self {
        Self {
            kind: SynthesizedEnumReferenceKind::Relations,
            owner: Box::new(Type::ModelObject(reference)),
        }
    }

    pub fn model_direct_relations(reference: Reference) -> Self {
        Self {
            kind: SynthesizedEnumReferenceKind::DirectRelations,
            owner: Box::new(Type::ModelObject(reference)),
        }
    }

    pub fn model_indirect_relations(reference: Reference) -> Self {
        Self {
            kind: SynthesizedEnumReferenceKind::IndirectRelations,
            owner: Box::new(Type::ModelObject(reference)),
        }
    }

    pub fn build_generics_map(&self, map: &mut BTreeMap<String, Type>, expect: &SynthesizedEnumReference) {
        self.owner.build_generics_map(map, expect.owner.as_ref());
    }

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

    pub fn fetch_synthesized_definition<'a>(&self, schema: &'a Schema) -> Option<&'a SynthesizedEnum> {
        if let Some(model_object) = self.owner.as_model_object() {
            if let Some(model) = schema.find_top_by_path(model_object.path()).unwrap().as_model() {
                model.resolved().enums.get(&self.kind)
            } else {
                None
            }
        } else {
            None
        }
    }
}

impl Display for SynthesizedEnumReference {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{}<{}>", self.kind, self.owner))
    }
}