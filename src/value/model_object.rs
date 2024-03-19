use crate::r#type::reference::Reference;

#[derive(Debug, Clone)]
pub struct ModelObject {
    reference: Reference
}

impl ModelObject {
    pub fn new(reference: Reference) -> Self {
        Self { reference }
    }
}