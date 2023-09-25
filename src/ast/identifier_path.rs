use std::fmt::{Display, Formatter};
use super::span::Span;
use super::identifier::Identifier;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct IdentifierPath {
    pub(crate) identifiers: Vec<Identifier>,
    pub(crate) span: Span,
}

impl IdentifierPath {

    pub(crate) fn path(&self) -> Vec<&str> {
        self.identifiers.iter().map(|i| i.name.as_str()).collect()
    }
}

impl Display for IdentifierPath {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for (i, id) in self.identifiers.iter().enumerate() {
            if i != 0 {
                f.write_str(".")?;
            }
            Display::fmt(&id, f)?;
        }
        Ok(())
    }
}