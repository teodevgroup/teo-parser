use std::fmt::{Display, Formatter};
use serde::Serialize;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize)]
pub enum Keyword {
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

impl Display for Keyword {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Keyword::SelfIdentifier => f.write_str("Self"),
            Keyword::ThisFieldType => f.write_str("ThisFieldType"),
        }
    }
}