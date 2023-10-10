#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub(crate) enum Keyword {
    SelfIdentifier,
    FieldType,
}

impl Keyword {

    pub(crate) fn is_self(&self) -> bool {
        match self {
            Keyword::SelfIdentifier => true,
            _ => false,
        }
    }

    pub(crate) fn is_field_type(&self) -> bool {
        match self {
            Keyword::FieldType => true,
            _ => false,
        }
    }
}