use std::fmt::{Display, Formatter};
use super::span::Span;
use super::identifier::Identifier;

#[derive(Debug)]
pub struct IdentifierPath {
    pub span: Span,
    pub identifiers: Vec<Identifier>,
}

impl IdentifierPath {

    pub fn names(&self) -> Vec<&str> {
        self.identifiers.iter().map(|i| i.name.as_str()).collect()
    }

    pub fn from_identifier(identifier: Identifier) -> Self {
        Self {
            span: identifier.span,
            identifiers: vec![identifier],
        }
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