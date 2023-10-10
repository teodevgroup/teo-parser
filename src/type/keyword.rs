#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub(crate) enum TypeKeyword {
    SelfIdentifier,
    FieldType,
}

impl TypeKeyword {

    pub(crate) fn is_self(&self) -> bool {
        match self {
            TypeKeyword::SelfIdentifier => true,
            _ => false,
        }
    }

    pub(crate) fn is_field_type(&self) -> bool {
        match self {
            TypeKeyword::FieldType => true,
            _ => false,
        }
    }
}