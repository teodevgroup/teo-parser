use crate::expr::ReferenceType;
use crate::r#type::reference::Reference;
use crate::r#type::Type;

#[derive(Debug, Clone)]
pub struct ReferenceInfo {
    pub r#type: ReferenceType,
    pub reference: Reference,
    pub generics: Option<Vec<Type>>,
}

impl ReferenceInfo {

    pub fn new(r#type: ReferenceType, reference: Reference, generics: Option<Vec<Type>>) -> Self {
        Self { r#type, reference, generics }
    }

    pub fn r#type(&self) -> ReferenceType {
        self.r#type
    }

    pub fn reference(&self) -> &Reference {
        &self.reference
    }

    pub fn reference_path(&self) -> &Reference {
        &self.reference
    }

    pub fn generics(&self) -> Option<&Vec<Type>> {
        self.generics.as_ref()
    }
}