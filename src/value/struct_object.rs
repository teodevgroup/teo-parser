use crate::r#type::reference::Reference;

#[derive(Debug, Clone)]
pub struct StructObject {
    reference: Reference
}

impl StructObject {
    pub fn new(reference: Reference) -> Self {
        Self { reference }
    }
}