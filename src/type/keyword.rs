#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub(crate) enum Keyword {
    SelfIdentifier,
    ThisFieldType,
}

impl Keyword {

    pub(crate) fn is_self(&self) -> bool {
        match self {
            Keyword::SelfIdentifier => true,
            _ => false,
        }
    }

    pub(crate) fn is_this_field_type(&self) -> bool {
        match self {
            Keyword::ThisFieldType => true,
            _ => false,
        }
    }
}