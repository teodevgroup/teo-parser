use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use educe::Educe;
use serde::Serialize;
use crate::r#type::keyword::Keyword;
use crate::r#type::Type;
use strum_macros::{Display, EnumString, AsRefStr, EnumIter};
use crate::ast::schema::Schema;
use crate::r#type::reference::Reference;
use crate::r#type::synthesized_enum_reference::SynthesizedEnumReference;
use crate::r#type::synthesized_interface_enum::SynthesizedInterfaceEnum;
use crate::traits::resolved::Resolve;

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Serialize, Display, EnumString, AsRefStr, EnumIter)]
pub enum SynthesizedInterfaceEnumReferenceKind {
    FieldIndexes,
}

#[derive(Debug, Clone, Eq, Serialize)]
#[derive(Educe)]
#[educe(Hash, PartialEq)]
pub struct SynthesizedInterfaceEnumReference {
    pub kind: SynthesizedInterfaceEnumReferenceKind,
    pub owner: Box<Type>,
}

impl SynthesizedInterfaceEnumReference {

    pub fn model_field_indexes(reference: Reference) -> Self {
        Self {
            kind: SynthesizedInterfaceEnumReferenceKind::FieldIndexes,
            owner: Box::new(Type::ModelObject(reference)),
        }
    }

    pub fn build_generics_map(&self, map: &mut BTreeMap<String, Type>, expect: &SynthesizedInterfaceEnumReference) {
        self.owner.build_generics_map(map, expect.owner.as_ref());
    }

    pub fn contains_generics(&self) -> bool {
        self.owner.contains_generics()
    }

    pub fn replace_keywords(&self, map: &BTreeMap<Keyword, Type>) -> SynthesizedInterfaceEnumReference {
        Self {
            kind: self.kind,
            owner: Box::new(self.owner.replace_keywords(map)),
        }
    }

    pub fn replace_generics(&self, map: &BTreeMap<String, Type>) -> SynthesizedInterfaceEnumReference {
        Self {
            kind: self.kind,
            owner: Box::new(self.owner.replace_generics(map)),
        }
    }

    pub fn fetch_synthesized_definition<'a>(&self, schema: &'a Schema) -> Option<&'a SynthesizedInterfaceEnum> {
        let model = schema.find_top_by_path(self.owner.as_model_object().unwrap().path()).unwrap().as_model().unwrap();
        model.resolved().interface_enums.get(&self.kind)
    }
}

impl Display for SynthesizedInterfaceEnumReference {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{}<{}>", self.kind, self.owner))
    }
}