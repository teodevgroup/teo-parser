use std::fmt::{Display, Formatter};
use crate::ast::argument_list::ArgumentList;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct Call {
    pub span: Span,
    pub identifier: Identifier,
    pub argument_list: ArgumentList,
}

impl Display for Call {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.identifier, f)?;
        Display::fmt(&self.argument_list, f)?;
        Ok(())
    }
}